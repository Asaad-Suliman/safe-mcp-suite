"""MCP server: the terminal tools, wired to the safety core.

This module is wiring. It redesigns neither parsing, policy, nor execution — it
puts them in the one order that is safe and makes that order the only path:

    parse -> evaluate -> (audit) -> execute -> audit

Two properties are load-bearing, and both are structural rather than
conventional:

* **Nothing executes before a decision exists.** ``execute.run`` cannot be
  called without a ``Decision``, and the only place one is produced is after a
  successful parse. There is no branch that reaches a subprocess any other way.
* **Nothing returns before it is audited.** Both tools funnel through
  :func:`_serve`, which is the single audit write point. A third tool added
  later inherits auditing by construction instead of by the author remembering.

On the executing path two records share an event id: an ``attempt`` written
*before* the subprocess starts and an ``outcome`` written after. The attempt
write is the fail-closed gate — if the log cannot be written, it raises, and
execution is never reached. Every non-executing path writes a single ``outcome``.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
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
from safety.policy import Decision, evaluate
from safety.redact import build_patterns, make_redactor
from safety.result import OperationResult, ResultCode, failed, succeeded
from servers.terminal import execute
from servers.terminal.config import ConfigError, ENV_POLICY_FILE, TerminalConfig
from servers.terminal.config import load as load_config
from servers.terminal.parse import ParsedCommand, parse

__all__ = ["SERVER_NAME", "configure", "run_command", "explain_command", "main"]

SERVER_NAME = "terminal"

mcp = MCPServer("safe-mcp-terminal")

# Set once at startup by main(), or by tests through configure().
_CONFIG: TerminalConfig | None = None
_JAIL: PathJail | None = None
_AUDIT: AuditLogger | None = None
_REDACTOR: Callable[[str], str] | None = None


def configure(
    config: TerminalConfig,
    jail_root: str | Path,
    *,
    audit_logger: AuditLogger | None = None,
) -> None:
    """Install the active configuration, jail, and audit logger.

    The redactor is built once and shared by the executor (which scrubs command
    output) and the audit logger (which scrubs its own free-text fields), so
    there is exactly one definition of what a secret looks like in this process.
    """
    global _CONFIG, _JAIL, _AUDIT, _REDACTOR

    if config.redaction_enabled:
        _REDACTOR = make_redactor(
            build_patterns(config.redaction_extra_patterns),
            entropy_fallback=config.redaction_entropy_fallback,
        )
    else:
        _REDACTOR = None

    _CONFIG = config
    _JAIL = PathJail.create(jail_root)
    _AUDIT = (
        audit_logger
        if audit_logger is not None
        else AuditLogger(
            config.audit_log,
            fail_mode=config.audit_fail_mode,
            redactor=_REDACTOR,
        )
    )


def _require_config() -> tuple[TerminalConfig, PathJail, AuditLogger]:
    if _CONFIG is None or _JAIL is None or _AUDIT is None:
        raise RuntimeError("server not configured: call configure() or main() first")
    return _CONFIG, _JAIL, _AUDIT


# Flags whose *following* argv token is the secret. The audit logger redacts
# each attribute independently, and an isolated token like "hunter2" looks like
# an ordinary word — only its neighbour reveals what it is. The joined form
# ("--password hunter2" inside the raw command string) is already handled by
# safety.redact's cli_flag pattern; this covers the split form.
_SECRET_VALUE_FLAGS = frozenset(
    {"--password", "--token", "--secret", "--api-key", "--apikey"}
)


def _scrub_argv(argv: tuple[str, ...]) -> list[str]:
    """Blank the token after a secret-bearing flag."""
    out: list[str] = []
    redact_next = False
    for token in argv:
        if redact_next:
            out.append("[REDACTED:cli_flag]")
            redact_next = False
            continue
        out.append(token)
        redact_next = token in _SECRET_VALUE_FLAGS
    return out


def _record(
    *,
    tool: str,
    command: str,
    code: ResultCode,
    record_type: str,
    event_id: str,
    parsed: ParsedCommand | None = None,
    decision: Decision | None = None,
    reason: str = "",
    cwd: str | None = None,
    duration_ms: int = 0,
    metrics: dict[str, int] | None = None,
) -> AuditRecord:
    """Assemble one audit record.

    Metrics are byte counts, never bytes. A log that accumulated stdout would be
    a second copy of every secret that ever passed through the server, sitting in
    a file that outlives the request.
    """
    return AuditRecord(
        ts=utc_now(),
        event_id=event_id,
        record_type=record_type,
        server=SERVER_NAME,
        action=tool,
        code=code.value,
        subject=command,
        attributes=_scrub_argv(parsed.argv) if parsed is not None else [],
        targets=[cwd] if cwd is not None else [],
        decision=(
            None if decision is None else ("allow" if decision.allowed else "deny")
        ),
        rule=(
            decision.rule.action
            if decision is not None and decision.rule is not None
            else None
        ),
        reason=reason,
        duration_ms=duration_ms,
        metrics=metrics or {},
    )


def _serve(tool: str, command: str, cwd: str | None, *, run: bool) -> OperationResult:
    """The single path both tools take, and the single place auditing happens.

    ``run=False`` (explain_command) returns before the executor is reached, so
    the dry run does not merely decline to execute — it has no route to the
    executor at all.
    """
    config, jail, audit = _require_config()
    event_id = new_event_id()

    parsed = parse(command)
    if isinstance(parsed, OperationResult):
        # Unevaluable input: no policy was consulted, so the record carries no
        # decision. The reason names what was wrong with the string.
        audit.record(
            _record(
                tool=tool,
                command=command,
                code=parsed.code,
                record_type=OUTCOME,
                event_id=event_id,
                reason=parsed.reason,
                cwd=cwd,
            )
        )
        return failed(parsed.code, tool, parsed.reason)

    decision = evaluate(parsed.action, parsed.attributes, policy=config.policy)

    if not decision.allowed:
        audit.record(
            _record(
                tool=tool,
                command=command,
                code=ResultCode.POLICY_DENIED,
                record_type=OUTCOME,
                event_id=event_id,
                parsed=parsed,
                decision=decision,
                reason=decision.reason,
                cwd=cwd,
            )
        )
        return failed(ResultCode.POLICY_DENIED, tool, decision.reason)

    if not run:
        # Dry run. Allowed, audited, and deliberately not executed.
        audit.record(
            _record(
                tool=tool,
                command=command,
                code=ResultCode.OK,
                record_type=OUTCOME,
                event_id=event_id,
                parsed=parsed,
                decision=decision,
                reason=decision.reason,
            )
        )
        return succeeded(
            tool,
            reason=decision.reason,
            detail={
                "would_execute": True,
                "action": parsed.action,
                "argv": _scrub_argv(parsed.argv),
            },
        )

    # The fail-closed gate. Under fail-closed an unwritable log raises here and
    # the subprocess is never spawned: an unlogged execution is worse than a
    # refused one.
    audit.record(
        _record(
            tool=tool,
            command=command,
            code=ResultCode.OK,
            record_type=ATTEMPT,
            event_id=event_id,
            parsed=parsed,
            decision=decision,
            reason=decision.reason,
            cwd=cwd,
        )
    )

    result = execute.run(
        parsed,
        decision,
        jail=jail,
        cwd=cwd,
        timeout=config.timeout,
        max_output_bytes=config.max_output_bytes,
        redactor=_REDACTOR,
    )

    audit.record(
        _record(
            tool=tool,
            command=command,
            code=result.code,
            record_type=OUTCOME,
            event_id=event_id,
            parsed=parsed,
            decision=decision,
            reason=result.reason or decision.reason,
            cwd=cwd,
            duration_ms=result.duration_ms,
            metrics={
                "stdout_bytes": len(str(result.detail.get("stdout", "")).encode()),
                "stderr_bytes": len(str(result.detail.get("stderr", "")).encode()),
            },
        )
    )

    # Restamp the action so the envelope names the tool the client called rather
    # than the executor's internal action name.
    return OperationResult(
        ok=result.ok,
        code=result.code,
        action=tool,
        reason=result.reason,
        detail=result.detail,
        duration_ms=result.duration_ms,
    )


def _finish(tool: str, command: str, cwd: str | None, *, run: bool) -> OperationResult:
    """Apply the error taxonomy so no exception ever crosses the MCP boundary."""
    try:
        return _serve(tool, command, cwd, run=run)
    except AuditUnavailable as exc:
        return failed(
            ResultCode.AUDIT_UNAVAILABLE,
            tool,
            f"audit log unavailable, nothing was executed: {exc}",
        )
    except Exception:
        # Deliberately generic. An exception message can carry a path, an
        # environment value, or a fragment of a secret, and this text goes
        # straight to the client.
        return failed(ResultCode.INTERNAL_ERROR, tool, "internal error")


@mcp.tool()
def run_command(command: str, cwd: str | None = None) -> OperationResult:
    """Evaluate a command against the policy and run it sandboxed if allowed.

    A denied command is never executed. ``cwd`` is optional and must resolve
    inside the jail root; a traversal, symlink, or absolute path that escapes
    returns PATH_ESCAPE without running anything. Every invocation is audited,
    and under fail-closed auditing an unwritable log returns AUDIT_UNAVAILABLE
    rather than executing unlogged.

    stdout, stderr, and exit_code are in ``detail``. A non-zero exit code is
    still ``ok`` — the command ran; whether it succeeded is its own business.
    """
    return _finish("run_command", command, cwd, run=True)


@mcp.tool()
def explain_command(command: str) -> OperationResult:
    """Report what the policy would decide, without executing anything.

    The dry run. It reaches the same parse and the same evaluation as
    ``run_command`` and then returns, so what it reports is what would actually
    happen rather than a separate reimplementation that could drift. ``detail``
    carries ``would_execute`` and the parsed argv; it never carries stdout,
    stderr, or an exit code, because nothing ran.
    """
    return _finish("explain_command", command, None, run=False)


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
    # wrong for a direct call (tests, ``python -m servers.terminal.server``)
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

    # The jail root is required. Defaulting it to the launch directory once
    # turned an entire home directory into the sandbox, and a jail nobody chose
    # is not a jail.
    if not config.jail_root:
        _fatal(
            "no jail root configured. Set SAFE_MCP_JAIL_ROOT or jail_root in "
            "policy.toml to the directory commands may run in. It is required so "
            "commands can never run outside an explicitly chosen sandbox."
        )
        return

    try:
        jail = PathJail.create(config.jail_root)
    except ValueError as exc:
        _fatal(str(exc))
        return

    # The audit log must not be reachable from inside the jail, or a permitted
    # command could read the trail or append forged records to it. Resolved the
    # way AuditLogger actually opens it (relative to cwd), not the way a
    # command's cwd is resolved (relative to the jail root) — see
    # PathJail.contains_external.
    if jail.contains_external(config.audit_log):
        _fatal(
            "the audit log must live outside the jail root, else a permitted "
            "command could read or forge it:\n"
            f"  audit log : {Path(config.audit_log).resolve()}\n"
            f"  jail root : {jail.root}"
        )
        return

    configure(config, jail.root)
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
