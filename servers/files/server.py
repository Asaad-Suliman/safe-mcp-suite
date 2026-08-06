"""MCP server: the six file tools, wired to the safety core.

This module is wiring. It redesigns neither inspection, policy, nor movement — it
puts them in the one order that is safe and makes that order the only path:

    inspect -> evaluate -> (audit) -> move -> audit

Six tools, and the list is the design:

    list_files, plan_organize, apply_plan, move_file,
    undo_last_action, redo_last_action

**There is no delete tool.** The reference organizer had three ways to send files
to the trash and none of them could be undone. The capability is not guarded here,
it is absent: no argument, no config key, and no policy rule produces one.

Three properties are structural rather than conventional:

* **Nothing moves before a decision exists.** Every mutating tool evaluates
  ``safety.policy`` first, and every tool asks the *same question about the same
  file*. What differs is which of the two rule layers a tool may act on:
  ``plan_organize`` walks the workspace unprompted and so obeys both, while
  ``move_file`` carries a request naming one specific file and so obeys the
  PROTECTION layer only. No tool can reach past PROTECTION, and no phrasing of a
  request creates a tool that can.
* **Nothing applies without having been planned.** ``apply.apply_plan`` takes a
  ``Plan`` value, and only ``plan.build`` makes one. A client sends a plan *id*
  and this module looks it up; there is no argument that conjures a plan.
* **Nothing returns before it is audited.** Every tool funnels through
  :func:`_serve`, the single outcome-write point. Mutating tools additionally
  write an ``attempt`` record first, which is the fail-closed gate: if the log
  cannot be written, nothing moves.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from safety.audit import (
    ATTEMPT,
    OUTCOME,
    AuditLogger,
    AuditRecord,
    AuditUnavailable,
    new_event_id,
    utc_now,
)
from safety.paths import PathJail
from safety.policy import PROTECTION, Decision, evaluate_layered
from safety.redact import build_patterns, make_redactor
from safety.result import OperationResult, ResultCode, failed, succeeded
from servers.files import apply as apply_module
from servers.files import inspect, plan as plan_module
from servers.files.config import ConfigError, ENV_POLICY_FILE, FilesConfig
from servers.files.config import load as load_config
from servers.files.journal import Journal, JournalEntry, JournalError, JournalMove

__all__ = [
    "SERVER_NAME",
    "configure",
    "list_files",
    "plan_organize",
    "apply_plan",
    "move_file",
    "undo_last_action",
    "redo_last_action",
    "main",
]

SERVER_NAME = "files"

mcp = MCPServer("safe-mcp-files")

# Set once at startup by main(), or by tests through configure().
_CONFIG: FilesConfig | None = None
_JAIL: PathJail | None = None
_AUDIT: AuditLogger | None = None
_JOURNAL: Journal | None = None
_REDACTOR: Callable[[str], str] | None = None

# Plans awaiting apply. In process only: a plan that outlived a restart would
# almost certainly be stale, and persisting one would mean an approval could be
# cashed in days later against a directory that has moved on.
_PLANS: dict[str, plan_module.Plan] = {}

#: How many un-applied plans to remember. Small because a plan is meant to be
#: applied or discarded promptly; the oldest is dropped rather than growing
#: without bound.
_MAX_PENDING_PLANS = 8


def configure(
    config: FilesConfig,
    workspace_root: str | Path,
    *,
    audit_logger: AuditLogger | None = None,
    journal: Journal | None = None,
) -> None:
    """Install the active configuration, workspace jail, audit log, and journal.

    The redactor is built once and shared, so there is exactly one definition of
    what a secret looks like in this process — a filename can carry one just as a
    command line can.
    """
    global _CONFIG, _JAIL, _AUDIT, _JOURNAL, _REDACTOR

    if config.redaction_enabled:
        _REDACTOR = make_redactor(
            build_patterns(config.redaction_extra_patterns),
            entropy_fallback=config.redaction_entropy_fallback,
        )
    else:
        _REDACTOR = None

    _CONFIG = config
    _JAIL = PathJail.create(workspace_root)
    _AUDIT = (
        audit_logger
        if audit_logger is not None
        else AuditLogger(
            config.audit_log, fail_mode=config.audit_fail_mode, redactor=_REDACTOR
        )
    )
    _JOURNAL = journal if journal is not None else Journal(config.journal)
    _PLANS.clear()


def _require_config() -> tuple[FilesConfig, PathJail, AuditLogger, Journal]:
    if _CONFIG is None or _JAIL is None or _AUDIT is None or _JOURNAL is None:
        raise RuntimeError("server not configured: call configure() or main() first")
    return _CONFIG, _JAIL, _AUDIT, _JOURNAL


# --- auditing ---------------------------------------------------------------


@dataclass
class _Context:
    """Everything one tool invocation needs, plus its audit identity."""

    config: FilesConfig
    jail: PathJail
    audit: AuditLogger
    journal: Journal
    tool: str
    event_id: str
    subject: str | None = None
    targets: list[str] = field(default_factory=list)

    def attempt(self, reason: str = "") -> None:
        """Write the ``attempt`` record. The fail-closed gate before mutating.

        Under fail-closed auditing an unwritable log raises here, so the files are
        never touched: an unlogged move is worse than a refused one.
        """
        self.audit.record(
            _record(
                ctx=self,
                code=ResultCode.OK,
                record_type=ATTEMPT,
                reason=reason,
            )
        )


def _record(
    *,
    ctx: _Context,
    code: ResultCode,
    record_type: str,
    reason: str = "",
    decision: str | None = None,
    rule: str | None = None,
    duration_ms: int = 0,
    metrics: dict[str, int] | None = None,
) -> AuditRecord:
    """Assemble one audit record.

    Metrics are counts, never contents. Targets are workspace-relative, so the
    trail does not accumulate a second copy of the server's filesystem layout.
    """
    return AuditRecord(
        ts=utc_now(),
        event_id=ctx.event_id,
        record_type=record_type,
        server=SERVER_NAME,
        action=ctx.tool,
        code=code.value,
        subject=ctx.subject,
        attributes=[],
        targets=list(ctx.targets),
        decision=decision,
        rule=rule,
        reason=reason,
        duration_ms=duration_ms,
        metrics=metrics or {},
    )


def _serve(
    tool: str,
    handler: Callable[[_Context], OperationResult],
    *,
    subject: str | None = None,
) -> OperationResult:
    """The single path every tool takes, and the single outcome-write point.

    A tool added later inherits auditing by construction rather than by its
    author remembering to add it.
    """
    config, jail, audit, journal = _require_config()
    ctx = _Context(
        config=config,
        jail=jail,
        audit=audit,
        journal=journal,
        tool=tool,
        event_id=new_event_id(),
        subject=subject,
    )

    result = handler(ctx)

    audit.record(
        _record(
            ctx=ctx,
            code=result.code,
            record_type=OUTCOME,
            reason=result.reason,
            duration_ms=result.duration_ms,
            metrics={"moved": int(result.detail.get("moved", 0) or 0)},
        )
    )
    return result


def _finish(
    tool: str,
    handler: Callable[[_Context], OperationResult],
    *,
    subject: str | None = None,
) -> OperationResult:
    """Apply the error taxonomy so no exception ever crosses the MCP boundary."""
    try:
        return _serve(tool, handler, subject=subject)
    except AuditUnavailable as exc:
        return failed(
            ResultCode.AUDIT_UNAVAILABLE,
            tool,
            f"audit log unavailable, nothing was changed: {exc}",
        )
    except JournalError as exc:
        return failed(
            ResultCode.OPERATION_FAILED,
            tool,
            f"undo journal unavailable, nothing was changed: {exc}",
        )
    except Exception:
        # Deliberately generic. An exception message can carry a path or a
        # fragment of a secret, and this text goes straight to the client.
        return failed(ResultCode.INTERNAL_ERROR, tool, "internal error")


# --- shared helpers ---------------------------------------------------------


def _decide(ctx: _Context, facts: inspect.FileFacts) -> tuple[Decision, str | None]:
    """Ask the policy about one file, and get back *which layer* answered.

    Every tool asks the same question of the same file. What differs is which
    layers a tool is entitled to act on, and that is a property of the tool, not
    of the file — so the split lives at the two call sites below, and the layer
    never gets flattened away before it reaches them.
    """
    return evaluate_layered(inspect.ACTION, facts.attributes, policy=ctx.config.policy)


def _refusal_code(layer: str | None) -> ResultCode:
    """The code a refusal at ``layer`` reports."""
    return (
        ResultCode.POLICY_DENIED
        if layer == PROTECTION
        else ResultCode.NEEDS_EXPLICIT_REQUEST
    )


def _replay(
    ctx: _Context,
    moves: tuple[JournalMove, ...],
    commit: Callable[[], JournalEntry | None],
    *,
    verb: str,
) -> OperationResult:
    """Perform a recorded sequence of moves, then advance the journal.

    Shared by undo and redo, which differ only in direction and in which stack
    they advance. The batch is pre-flighted so a half-finished reversal — a state
    neither the user nor the journal describes — stays rare, and the journal is
    advanced only after every move actually landed.
    """
    blocked = apply_module.preflight(moves, jail=ctx.jail, action=ctx.tool)
    if blocked is not None:
        return blocked

    ctx.attempt(reason=f"{verb} {len(moves)} move(s)")

    done: list[dict[str, str]] = []
    for move in moves:
        result = apply_module.move_one(
            move.src, move.dest, jail=ctx.jail, action=ctx.tool
        )
        if not result.ok:
            return failed(
                result.code,
                ctx.tool,
                f"{result.reason} — {verb} stopped after {len(done)} of "
                f"{len(moves)} move(s); the journal was left unchanged",
                detail={"moved": len(done), "moves": done},
            )
        done.append({"src": str(result.detail["src"]), "dest": str(result.detail["dest"])})

    commit()
    return succeeded(
        ctx.tool,
        reason=f"{verb} {len(done)} move(s)",
        detail={"moved": len(done), "moves": done},
    )


def _remember_plan(plan: plan_module.Plan) -> None:
    """Hold a plan for apply, dropping the oldest if too many are pending."""
    _PLANS[plan.plan_id] = plan
    while len(_PLANS) > _MAX_PENDING_PLANS:
        _PLANS.pop(next(iter(_PLANS)))


# --- the six tools ----------------------------------------------------------


@mcp.tool()
def list_files(subdir: str | None = None) -> OperationResult:
    """List what is in the workspace, and what the policy thinks of each entry.

    Read-only. ``subdir`` is optional and must resolve inside the workspace root;
    a traversal, symlink, or absolute path that escapes returns PATH_ESCAPE
    without listing anything.

    Each entry reports its name, size, category, whether the organizer would move
    it, and — when it would not — the reason. That last part is the point: it
    answers "why was my file left alone" without anyone having to run an
    organize and compare.
    """

    def handler(ctx: _Context) -> OperationResult:
        target = ctx.jail.resolve(subdir)
        if target is None:
            return failed(
                ResultCode.PATH_ESCAPE,
                ctx.tool,
                f"path escapes the workspace: {subdir!r}",
            )
        ctx.targets = [_relative(target, ctx.jail.root)]

        if not target.is_dir():
            return failed(
                ResultCode.OPERATION_FAILED,
                ctx.tool,
                f"not a directory: {_relative(target, ctx.jail.root)}",
            )

        entries = []
        for path in sorted(target.iterdir(), key=lambda p: p.name):
            try:
                facts = inspect.facts(path, categories=ctx.config.categories)
            except OSError as exc:
                entries.append({"name": path.name, "error": f"could not inspect: {exc}"})
                continue
            decision, layer = _decide(ctx, facts)
            entries.append(
                {
                    "name": facts.name,
                    "size": facts.size,
                    "category": facts.category,
                    "organizable": decision.allowed,
                    # Which kind of "no" this is. Without it an installer and a
                    # symlink both read as organizable: false, and only one of
                    # them would move if move_file were asked for it by name.
                    "code": "" if decision.allowed else _refusal_code(layer).value,
                    "reason": "" if decision.allowed else decision.reason,
                }
            )

        return succeeded(
            ctx.tool,
            reason=f"listed {len(entries)} entr(ies)",
            detail={
                "path": _relative(target, ctx.jail.root),
                "count": len(entries),
                "entries": entries,
            },
        )

    return _finish("list_files", handler, subject=subdir)


@mcp.tool()
def plan_organize() -> OperationResult:
    """Propose how the workspace would be organized. Changes nothing.

    Returns a ``plan_id`` plus every move it would make and every entry it would
    skip with the reason. Nothing is created, moved, or renamed — not even the
    destination folders, which the reference organizer created merely by
    deciding.

    Pass the ``plan_id`` to ``apply_plan`` to carry it out. A plan is a snapshot:
    if any of its files change before it is applied, applying it is refused and
    the plan must be rebuilt.
    """

    def handler(ctx: _Context) -> OperationResult:
        plan = plan_module.build(
            ctx.jail,
            policy=ctx.config.policy,
            categories=ctx.config.categories,
            max_moves=ctx.config.max_plan_moves,
        )
        _remember_plan(plan)
        ctx.targets = [str(m.dest.relative_to(plan.root)) for m in plan.moves[:20]]
        return succeeded(
            ctx.tool,
            code=(
                ResultCode.OUTPUT_TRUNCATED if plan.truncated else ResultCode.OK
            ),
            reason=(
                f"proposed {len(plan.moves)} move(s), skipped {len(plan.skips)}"
                + (" (truncated)" if plan.truncated else "")
            ),
            detail=plan.describe(),
        )

    return _finish("plan_organize", handler)


@mcp.tool()
def apply_plan(plan_id: str) -> OperationResult:
    """Carry out a plan produced by ``plan_organize``.

    ``plan_id`` must name a plan this server built and has not yet applied; an
    unknown or already-used id is INVALID_REQUEST. Plans are single-use, so an
    approval cannot be replayed.

    Every file in the plan is re-checked first. If any of them changed, moved, or
    vanished since planning, the **whole** plan is refused and nothing is moved —
    you approved a specific set of moves, and a subset of it is not what you
    approved. No destination is ever overwritten.
    """

    def handler(ctx: _Context) -> OperationResult:
        plan = _PLANS.pop(plan_id, None)
        if plan is None:
            return failed(
                ResultCode.INVALID_REQUEST,
                ctx.tool,
                f"unknown or already-applied plan: {plan_id!r}. "
                "Run plan_organize to produce a fresh one.",
            )

        ctx.targets = [str(m.dest.relative_to(plan.root)) for m in plan.moves[:20]]
        ctx.attempt(reason=f"applying {len(plan.moves)} move(s)")

        result = apply_module.apply_plan(plan, jail=ctx.jail, journal=ctx.journal)
        return OperationResult(
            ok=result.ok,
            code=result.code,
            action=ctx.tool,
            reason=result.reason,
            detail=result.detail,
            duration_ms=result.duration_ms,
        )

    return _finish("apply_plan", handler, subject=plan_id)


@mcp.tool()
def move_file(src: str, dest: str) -> OperationResult:
    """Move one file inside the workspace.

    ``dest`` is the full destination path including the filename, not a folder —
    ``move_file("report.pdf", "Documents/report.pdf")``. Missing parent folders
    are created. A destination that already exists is refused rather than
    overwritten, and no numbered variant is invented for it. A directory may be
    moved, as one rename; its contents come with it and are not re-filed.

    This names one file, so it is not guessing, and the rules that exist only to
    stop the organizer guessing do not apply: an installer, a dotfile, an
    application folder or a plain directory all move if you ask for them by name.
    ``plan_organize`` still leaves every one of them alone, and reports them as
    NEEDS_EXPLICIT_REQUEST — which is a pointer to this tool.

    The safety rules are untouched and are not negotiable here: a path that
    escapes the workspace, a symlink, a name carrying control characters, and an
    occupied destination are all still refused, with POLICY_DENIED or
    PATH_ESCAPE. There is no phrasing of a request that gets past them.
    """

    def handler(ctx: _Context) -> OperationResult:
        resolved = ctx.jail.resolve_for_write(src)
        if resolved is None:
            return failed(
                ResultCode.PATH_ESCAPE,
                ctx.tool,
                f"source path escapes the workspace: {src!r}",
            )
        ctx.targets = [_relative(resolved, ctx.jail.root)]

        # Both ends are checked before any attempt record is written. An attempt
        # means something was genuinely about to move; claiming one for an
        # operation already doomed by its destination would make the trail lie
        # about how far the server got. move_one checks again regardless.
        if ctx.jail.resolve_for_write(dest) is None:
            return failed(
                ResultCode.PATH_ESCAPE,
                ctx.tool,
                f"destination path escapes the workspace: {dest!r}",
            )

        try:
            facts = inspect.facts(resolved, categories=ctx.config.categories)
        except OSError:
            return failed(
                ResultCode.OPERATION_FAILED, ctx.tool, f"source not found: {src!r}"
            )

        # Protection only. A restraint rule exists because filing this file
        # *automatically* would be a guess, and there is no guess here — the
        # caller named this file and this destination. Refusing it would not be
        # safety, it would be the organizer's caution applied to a decision
        # somebody already made.
        decision, layer = _decide(ctx, facts)
        if layer == PROTECTION:
            ctx.audit.record(
                _record(
                    ctx=ctx,
                    code=ResultCode.POLICY_DENIED,
                    record_type=OUTCOME,
                    reason=decision.reason,
                    decision="deny",
                    rule=decision.rule.action if decision.rule is not None else None,
                )
            )
            return failed(ResultCode.POLICY_DENIED, ctx.tool, decision.reason)

        # The trail says when a restraint was passed over, and which one. That a
        # file the organizer would have left alone was moved on request is
        # exactly the thing a reviewer wants to find written down.
        ctx.attempt(
            reason=(
                f"moved by explicit request over a restraint rule: {decision.reason}"
                if not decision.allowed
                else decision.reason
            )
        )

        result = apply_module.move_one(src, dest, jail=ctx.jail, action=ctx.tool)
        if not result.ok:
            return result

        ctx.journal.record(
            JournalEntry(
                action=ctx.tool,
                moves=(
                    JournalMove(
                        src=str(result.detail["src"]), dest=str(result.detail["dest"])
                    ),
                ),
            )
        )
        return succeeded(
            ctx.tool,
            reason=result.reason,
            detail={**result.detail, "moved": 1},
            duration_ms=result.duration_ms,
        )

    return _finish("move_file", handler, subject=f"{src} -> {dest}")


@mcp.tool()
def undo_last_action() -> OperationResult:
    """Reverse the most recent move, or the most recent plan, in one call.

    One journal entry is one action: undoing an ``apply_plan`` that moved forty
    files puts all forty back, rather than needing forty undos.

    The reversal is checked in full before anything moves, so a file that has
    since been moved or replaced by hand refuses the undo instead of half-doing
    it. Nothing is ever overwritten to make room for a restored file.
    """

    def handler(ctx: _Context) -> OperationResult:
        entry = ctx.journal.peek_undo()
        if entry is None:
            return failed(
                ResultCode.OPERATION_FAILED, ctx.tool, "there is nothing to undo"
            )
        return _replay(
            ctx, entry.reversed_moves(), ctx.journal.commit_undo, verb="undid"
        )

    return _finish("undo_last_action", handler)


@mcp.tool()
def redo_last_action() -> OperationResult:
    """Reapply the most recently undone action.

    The redo stack is cleared whenever new work is recorded, so a redo can never
    reapply a move into a workspace that has since been reorganized underneath
    it. Same checks as undo: verified in full first, and no destination is
    overwritten.
    """

    def handler(ctx: _Context) -> OperationResult:
        entry = ctx.journal.peek_redo()
        if entry is None:
            return failed(
                ResultCode.OPERATION_FAILED, ctx.tool, "there is nothing to redo"
            )
        return _replay(ctx, entry.moves, ctx.journal.commit_redo, verb="redid")

    return _finish("redo_last_action", handler)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:  # pragma: no cover - unreachable via the jail
        return path.name


# --- entry point ------------------------------------------------------------


def _fatal(message: str) -> None:
    """Print a startup failure and exit. stderr, because stdout carries JSON-RPC."""
    print(f"fatal: {message}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> None:
    """Console entry point: load config, refuse loudly if unsafe, then serve.

    ``argv`` is the argument list the CLI was called with (not ``sys.argv``),
    so both ``servers.cli`` and tests can drive it directly. ``--config``
    names the policy file explicitly; ``SAFE_MCP_POLICY_FILE`` remains
    supported for deployments that prefer an environment variable. Neither
    supplied is a startup refusal rather than a silent fall back to whatever
    ``policy.toml`` happens to be in the working directory — that ambient
    default is exactly what made the documented Quickstart path depend on
    state nothing guaranteed.
    """
    parser = argparse.ArgumentParser(prog=f"safe-mcp {SERVER_NAME}")
    parser.add_argument("--config", help="path to policy.toml")
    # ``argv or []`` rather than letting argparse default to ``None``: a bare
    # ``None`` makes argparse read the real process ``sys.argv``, which is
    # wrong for a direct call (tests, ``python -m servers.files.server``)
    # that means "no extra CLI args" rather than "inherit the caller's".
    config_path = parser.parse_args(argv or []).config or os.environ.get(ENV_POLICY_FILE)

    if not config_path:
        _fatal(
            f"no policy file configured. Pass --config PATH or set {ENV_POLICY_FILE}. "
            "There is no default: a policy file nobody chose is not a policy."
        )
        return

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fatal(f"could not load policy: {exc}")
        return

    # The workspace root is required. The reference defaulted it to a folder in
    # $HOME and let a tool re-point it at runtime; a sandbox nobody chose, that
    # anything can move, is not a sandbox.
    if not config.workspace_root:
        _fatal(
            "no workspace root configured. Set SAFE_MCP_WORKSPACE_ROOT or "
            "files.workspace_root in policy.toml to the directory this server may "
            "organize. It is required so files can never be moved outside an "
            "explicitly chosen folder."
        )
        return

    try:
        jail = PathJail.create(config.workspace_root)
    except ValueError as exc:
        _fatal(str(exc))
        return

    # Both state files must live outside the workspace. Inside, the organizer
    # would treat its own audit trail and undo journal as user files to be filed
    # away — and a file it can move is a file it can lose.
    for label, location in (
        ("audit log", config.audit_log),
        ("undo journal", config.journal),
    ):
        if jail.contains_external(location):
            _fatal(
                f"the {label} must live outside the workspace root, else the "
                "organizer could move or overwrite its own state:\n"
                f"  {label:<13}: {Path(location).resolve()}\n"
                f"  workspace root: {jail.root}"
            )
            return

    configure(config, jail.root)
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
