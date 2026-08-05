"""Propose moves. Touch nothing.

``plan_organize`` and ``apply_plan`` are two tools on purpose, and this module is
the half that cannot write. It walks the workspace, asks ``safety.policy`` about
each entry, and returns a list of moves it *would* make. The reference organizer
had no such split: ``organize_workspace()`` decided and moved in the same pass, so
the only way to find out what it would do was to let it do it.

This is the tool that acts on its own initiative — nothing it does was asked for
file by file — so it is the one that enforces **both** rule layers. Every skip it
reports carries the layer that produced it, because "the organizer will not guess
about this" and "this is forbidden" lead to different next steps for the caller,
and the only other way to tell them apart would be to attempt the move.

The type is the enforcement. ``apply.apply_plan`` takes a :class:`Plan` value, and
:func:`build` is the only thing that constructs one. A client speaks JSON and
cannot fabricate a ``Plan``, so there is no route from raw client input to a move
that does not pass through this module first — the same shape as the terminal
server, where ``execute.run`` demands a ``ParsedCommand`` and a ``Decision``
rather than a string.

:func:`verify` is the other half of that guarantee. A plan is a description of the
workspace at a moment, and the workspace can change afterwards. Verification
re-reads every source and compares the fingerprint taken at plan time; anything
that moved, changed size, or vanished refuses the **whole** plan. Applying the
half of a proposal that still fits would mean the user approved one thing and got
another.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from safety.audit import utc_now
from safety.paths import PathJail
from safety.policy import PROTECTION, Policy, evaluate_layered
from safety.result import OperationResult, ResultCode, failed
from servers.files import inspect

__all__ = ["ACTION", "Move", "Skip", "Plan", "build", "verify", "occupied"]

#: Action name used on results produced by this module.
ACTION = "plan_organize"


@dataclass(frozen=True)
class Move:
    """One proposed rename, with the fingerprint that says it is still valid."""

    src: Path
    dest: Path
    category: str
    size: int
    mtime_ns: int

    def describe(self, root: Path) -> dict[str, object]:
        """Workspace-relative view, for handing back to a client.

        Relative because an absolute path leaks the server's filesystem layout to
        whoever is driving it, and the client has no use for it — every path it
        can name is inside the workspace by definition.
        """
        return {
            "src": str(self.src.relative_to(root)),
            "dest": str(self.dest.relative_to(root)),
            "category": self.category,
            "size": self.size,
        }


@dataclass(frozen=True)
class Skip:
    """One entry the plan deliberately left alone, why, and how firmly.

    ``code`` is what separates "this is forbidden" from "the organizer will not
    guess about this". A NEEDS_EXPLICIT_REQUEST skip is an invitation: name the
    file to ``move_file`` and it moves. A POLICY_DENIED skip is not, and trying
    it through the other tool will fail the same way. Without the distinction a
    caller could only tell the two apart by attempting the move.
    """

    name: str
    reason: str
    code: ResultCode
    rule: str | None = None

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "reason": self.reason,
            "code": self.code.value,
            "rule": self.rule,
        }


@dataclass(frozen=True)
class Plan:
    """A proposal: what would move, what would not, and when it was decided.

    Constructed only by :func:`build`. Passing one to ``apply`` is how a caller
    proves the proposal was produced by inspection rather than asserted.
    """

    plan_id: str
    root: Path
    moves: tuple[Move, ...] = ()
    skips: tuple[Skip, ...] = ()
    created: str = field(default_factory=utc_now)
    truncated: bool = False

    def describe(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "created": self.created,
            "truncated": self.truncated,
            "move_count": len(self.moves),
            "skip_count": len(self.skips),
            "moves": [m.describe(self.root) for m in self.moves],
            "skips": [s.describe() for s in self.skips],
        }


def build(
    jail: PathJail,
    *,
    policy: Policy,
    categories: Mapping[str, str],
    max_moves: int,
) -> Plan:
    """Inspect the workspace top level and propose moves. Writes nothing.

    Only the top level is walked. Recursing would mean re-filing files the user
    already filed — the reference's ``rglob`` walks reached into every category
    folder it had previously created and shuffled their contents again.

    Entries are processed in name order so the same workspace produces the same
    plan twice; a proposal a human is asked to approve should not reshuffle
    itself between readings.
    """
    root = jail.root
    moves: list[Move] = []
    skips: list[Skip] = []
    truncated = False

    for path in sorted(root.iterdir(), key=lambda p: p.name):
        if len(moves) >= max_moves:
            truncated = True
            break

        try:
            facts = inspect.facts(path, categories=categories)
        except OSError as exc:
            # The tree changed under the walk. One unreadable entry is not a
            # reason to refuse the other ninety-nine.
            skips.append(
                Skip(
                    name=path.name,
                    reason=f"could not inspect: {exc}",
                    code=ResultCode.OPERATION_FAILED,
                )
            )
            continue

        # Both layers, because this tool is the one acting on its own initiative:
        # nothing here names a file, so every restraint rule applies. The layer is
        # reported rather than flattened away, so a caller can see which skips
        # would move if it asked for them by name.
        decision, layer = evaluate_layered(
            inspect.ACTION, facts.attributes, policy=policy
        )
        if not decision.allowed:
            skips.append(
                Skip(
                    name=facts.name,
                    reason=decision.reason,
                    code=(
                        ResultCode.POLICY_DENIED
                        if layer == PROTECTION
                        else ResultCode.NEEDS_EXPLICIT_REQUEST
                    ),
                    rule=decision.rule.action if decision.rule is not None else None,
                )
            )
            continue

        # resolve_for_write, not resolve: a symlink sitting at the destination name
        # must not redirect the move to whatever it points at. The category name
        # comes from config, and one called "../x" would aim the whole category
        # outside the workspace — config rejects that at startup, and this is the
        # second lock on the same door.
        dest = jail.resolve_for_write(Path(facts.category) / facts.name)
        if dest is None:
            skips.append(
                Skip(
                    name=facts.name,
                    reason=(
                        f"destination for category {facts.category!r} "
                        "escapes the workspace"
                    ),
                    code=ResultCode.PATH_ESCAPE,
                )
            )
            continue

        if occupied(dest):
            # Reported now rather than discovered at apply time, so the proposal
            # a human reads is the truth. apply checks again anyway.
            skips.append(
                Skip(
                    name=facts.name,
                    reason=(
                        f"destination already exists: {dest.relative_to(root)}"
                    ),
                    code=ResultCode.OPERATION_FAILED,
                )
            )
            continue

        moves.append(
            Move(
                src=facts.path,
                dest=dest,
                category=facts.category,
                size=facts.size,
                mtime_ns=facts.mtime_ns,
            )
        )

    return Plan(
        plan_id=str(uuid.uuid4()),
        root=root,
        moves=tuple(moves),
        skips=tuple(skips),
        truncated=truncated,
    )


def occupied(path: Path) -> bool:
    """True if anything occupies ``path``, including a broken symlink.

    ``Path.exists()`` follows links and answers False for a dangling one, which
    would call an occupied name free and let a rename clobber the link.
    """
    try:
        path.lstat()
    except OSError:
        return False
    return True


def verify(plan: Plan) -> OperationResult | None:
    """Return ``None`` if the plan still describes reality, else why it does not.

    Every source is re-read and compared against the fingerprint captured when the
    plan was built, and every destination is re-checked for having become
    occupied. A single mismatch refuses the entire plan: partial application of an
    approved proposal is the outcome this split exists to prevent.

    Failure codes are distinct because the conditions are. A changed source is
    INVALID_REQUEST — the plan itself is no longer a valid request, and the fix is
    to re-plan. An occupied destination is OPERATION_FAILED — the plan was fine,
    the filesystem simply will not accept it without an overwrite this server does
    not perform.
    """
    for move in plan.moves:
        try:
            st = move.src.lstat()
        except OSError:
            return failed(
                ResultCode.INVALID_REQUEST,
                ACTION,
                f"plan is stale: {move.src.name} is no longer there. "
                "Re-run plan_organize.",
                detail={"plan_id": plan.plan_id, "stale": move.src.name},
            )

        if st.st_size != move.size or st.st_mtime_ns != move.mtime_ns:
            return failed(
                ResultCode.INVALID_REQUEST,
                ACTION,
                f"plan is stale: {move.src.name} changed since it was planned. "
                "Re-run plan_organize.",
                detail={"plan_id": plan.plan_id, "stale": move.src.name},
            )

        if occupied(move.dest):
            return failed(
                ResultCode.OPERATION_FAILED,
                ACTION,
                "destination already exists, refusing to overwrite: "
                f"{move.dest.relative_to(plan.root)}",
                detail={
                    "plan_id": plan.plan_id,
                    "collision": str(move.dest.relative_to(plan.root)),
                },
            )

    return None
