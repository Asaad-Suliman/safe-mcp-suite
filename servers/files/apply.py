"""The only code in this server that moves a file.

Every mutation funnels through :func:`move_one` — the organizer's bulk apply, a
single directed move, an undo, a redo. That is the whole point of the module: the
rule "never overwrite" and the rule "never leave the workspace" are each written
once, so a tool added later inherits both by construction rather than by its
author remembering. The reference organizer had fourteen separate ``rename()``
call sites and the safety checks around them had already drifted apart.

There is no delete. Not a guarded one, not a trash-can one — the capability does
not exist in this server, so no argument, no config value, and no policy rule can
produce one.

What :func:`move_one` enforces, in order:

* **Containment**, via ``PathJail.resolve_for_write`` for *both* ends. Not
  ``resolve``: a symlink at either name must be moved or refused as itself, never
  followed to somewhere else.
* **A source that is there.** Renaming something absent is a failure, not a no-op.
* **A free destination.** Checked with ``lstat``, so a dangling symlink still
  counts as occupied.
"""

from __future__ import annotations

import time
from pathlib import Path

from safety.paths import PathJail
from safety.result import OperationResult, ResultCode, failed, succeeded
from servers.files.journal import Journal, JournalEntry, JournalError, JournalMove
from servers.files.plan import Plan, occupied
from servers.files.plan import verify as verify_plan

__all__ = ["ACTION", "move_one", "apply_plan"]

#: Action name used on results produced by this module.
ACTION = "apply_plan"


def move_one(
    src: str | Path, dest: str | Path, *, jail: PathJail, action: str = ACTION
) -> OperationResult:
    """Move ``src`` to ``dest`` inside ``jail``, or explain why it did not.

    Returns a result; raises nothing a caller has to catch. ``action`` names the
    tool on the envelope so a refusal reads as coming from the tool the client
    called rather than from this helper.

    On success ``detail`` carries the workspace-relative ``src`` and ``dest``,
    which is what the journal and the audit record both want.
    """
    resolved_src = jail.resolve_for_write(src)
    if resolved_src is None:
        return failed(
            ResultCode.PATH_ESCAPE,
            action,
            f"source path escapes the workspace: {str(src)!r}",
        )

    resolved_dest = jail.resolve_for_write(dest)
    if resolved_dest is None:
        return failed(
            ResultCode.PATH_ESCAPE,
            action,
            f"destination path escapes the workspace: {str(dest)!r}",
        )

    if not occupied(resolved_src):
        return failed(
            ResultCode.OPERATION_FAILED,
            action,
            f"source not found: {_relative(resolved_src, jail.root)}",
        )

    # The load-bearing check. Path.rename is os.rename, which on POSIX silently
    # replaces an existing destination — this is the only thing between "no silent
    # overwrites" and a clobber.
    #
    # ponytail: check-then-use, same TOCTOU ceiling as safety/paths.py. A file
    # created at the destination between this check and the rename below is still
    # overwritten. Upgrade path is os.link(src, dest) + os.unlink(src), where the
    # link fails atomically if the destination exists; it is not used here because
    # it does not work across filesystems and cannot move a directory.
    if occupied(resolved_dest):
        return failed(
            ResultCode.OPERATION_FAILED,
            action,
            "destination already exists, refusing to overwrite: "
            f"{_relative(resolved_dest, jail.root)}",
        )

    start = time.monotonic()
    try:
        resolved_dest.parent.mkdir(parents=True, exist_ok=True)
        resolved_src.rename(resolved_dest)
    except OSError as exc:
        return failed(
            ResultCode.OPERATION_FAILED,
            action,
            f"could not move {_relative(resolved_src, jail.root)}: {exc}",
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    return succeeded(
        action,
        reason=f"moved {_relative(resolved_src, jail.root)}",
        detail={
            "src": _relative(resolved_src, jail.root),
            "dest": _relative(resolved_dest, jail.root),
        },
        duration_ms=int((time.monotonic() - start) * 1000),
    )


def apply_plan(plan: Plan, *, jail: PathJail, journal: Journal) -> OperationResult:
    """Execute a plan, having first confirmed it still describes reality.

    Takes a :class:`Plan` **value**, not an identifier and not a dictionary. That
    is what makes an unplanned apply unrepresentable rather than merely rejected:
    ``plan.build`` is the only thing that produces a ``Plan``, so there is no
    argument a client could send that reaches this function without having been
    planned first.

    Verification happens before anything is touched, and a stale plan refuses
    entirely — zero moves, not the subset that still fits.

    If a move fails partway through despite that pre-flight (a genuine race), the
    moves already made are journalled before returning, so the partial state is
    undoable. There is no automatic rollback: unwinding is itself a sequence of
    moves that can fail, and a failed rollback leaves a state nobody planned.
    """
    stale = verify_plan(plan)
    if stale is not None:
        # Restamp the action so the envelope names this tool rather than the
        # planner's internal action name.
        return OperationResult(
            ok=False,
            code=stale.code,
            action=ACTION,
            reason=stale.reason,
            detail=stale.detail,
        )

    start = time.monotonic()
    done: list[JournalMove] = []

    for move in plan.moves:
        result = move_one(move.src, move.dest, jail=jail, action=ACTION)
        if not result.ok:
            journal_error = _remember(journal, done)
            return failed(
                result.code,
                ACTION,
                f"{result.reason} — stopped after {len(done)} of "
                f"{len(plan.moves)} moves"
                + (f". {journal_error}" if journal_error else ""),
                detail={
                    "plan_id": plan.plan_id,
                    "moved": len(done),
                    "planned": len(plan.moves),
                    "moves": [m.to_dict() for m in done],
                },
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        done.append(
            JournalMove(src=str(result.detail["src"]), dest=str(result.detail["dest"]))
        )

    journal_error = _remember(journal, done)
    if journal_error:
        # The moves happened and cannot be un-happened by refusing now. Say so
        # plainly rather than reporting a clean success that hides a lost undo.
        return failed(
            ResultCode.OPERATION_FAILED,
            ACTION,
            f"{len(done)} file(s) moved, but the undo journal could not be "
            f"written, so this cannot be undone. {journal_error}",
            detail={
                "plan_id": plan.plan_id,
                "moved": len(done),
                "planned": len(plan.moves),
                "moves": [m.to_dict() for m in done],
            },
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    return succeeded(
        ACTION,
        code=(
            ResultCode.OUTPUT_TRUNCATED if plan.truncated else ResultCode.OK
        ),
        reason=(
            f"moved {len(done)} file(s)"
            + (" (plan was truncated; re-plan for the rest)" if plan.truncated else "")
        ),
        detail={
            "plan_id": plan.plan_id,
            "moved": len(done),
            "planned": len(plan.moves),
            "moves": [m.to_dict() for m in done],
        },
        duration_ms=int((time.monotonic() - start) * 1000),
    )


def _remember(journal: Journal, moves: list[JournalMove]) -> str:
    """Journal what was done. Returns "" on success, or the problem as text.

    A journal failure must not be raised past here: the files have already moved,
    and an exception at this point would report a failure that undid nothing.
    """
    if not moves:
        return ""
    try:
        journal.record(JournalEntry(action=ACTION, moves=tuple(moves)))
    except JournalError as exc:
        return str(exc)
    return ""


def _relative(path: Path, root: Path) -> str:
    """Workspace-relative text, so no absolute path reaches the client.

    Falls back to the bare name if the path is somehow outside the root; that
    should be unreachable, and printing an absolute path is the one outcome not
    worth risking to prove it.
    """
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name
