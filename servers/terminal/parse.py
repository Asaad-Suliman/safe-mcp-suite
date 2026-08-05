"""Turn a raw command string into something the policy engine can judge.

This is the first of the two halves that ``safety/`` deliberately does not have.
``safety.policy.evaluate`` speaks *action name + attributes*; a terminal client
speaks a command line. Bridging the two is terminal work, because only a terminal
server knows that a command line is argv and that argv[0] is the action.

Nothing here decides anything. Parsing either produces a request that *can* be
evaluated, or it refuses the input as unevaluable — the allow/deny judgement
belongs entirely to ``safety.policy``.

That distinction is why every rejection here is ``INVALID_REQUEST`` and never
``POLICY_DENIED``, including the shell metacharacter scan. At this point no
policy has been consulted and no rule has fired, so calling it a denial would
claim a decision that was never made. The audit ``reason`` still records exactly
which metacharacter was seen.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from safety.patterns import SHELL_METACHARACTERS, first_match
from safety.result import OperationResult, ResultCode, failed

__all__ = ["ACTION", "METACHARACTERS", "ParsedCommand", "parse"]

#: Action name used on results produced by this module.
ACTION = "parse_command"

#: The operators this module rejects. Defined in :mod:`safety.patterns` because
#: the file server scans names with the same function; re-exported under the
#: terminal's own name so callers here need not know where it lives. Rejecting a
#: command that contains one means such input never reaches allow/deny evaluation.
METACHARACTERS: tuple[str, ...] = SHELL_METACHARACTERS


@dataclass(frozen=True)
class ParsedCommand:
    """One command line, split into the vocabulary each consumer needs.

    ``action`` and ``attributes`` are what ``safety.policy.evaluate`` consumes;
    ``argv`` is what a subprocess consumes. Both views are computed once here so
    no later stage has to re-split the string — a second split is a second
    chance to disagree about what the command actually was.
    """

    action: str  # argv[0], lowercased — the policy action name
    args: tuple[str, ...]  # argv[1:], in the order the caller wrote them
    argv: tuple[str, ...]  # the full token list, for execution
    attributes: frozenset[str]  # args as a set — order-independent matching


def _find_metacharacter(raw: str) -> str | None:
    """Return the first shell metacharacter in ``raw``, else None."""
    # ponytail: raw substring scan, known ceiling — it flags metacharacters
    # inside quotes too, so `echo "a;b"` is rejected even though it is harmless.
    # That is the safe direction to be wrong in: there is no quoting trick that
    # smuggles an operator past a scan that ignores quoting. Upgrade path is a
    # quote-aware scanner (walk shlex tokens instead of the raw string), and it
    # is only worth it if legitimate quoted metacharacters actually show up.
    return first_match(raw, METACHARACTERS)


def parse(raw: str) -> ParsedCommand | OperationResult:
    """Parse ``raw`` into a :class:`ParsedCommand`, or return why it could not be.

    Returns a *failed result*, never an exception — the caller hands whatever
    comes back to an MCP client, and a ``shlex`` ``ValueError`` escaping across
    that boundary would be a traceback on the wire.

    Callers distinguish the two outcomes with ``isinstance(x, OperationResult)``.
    """
    meta = _find_metacharacter(raw)
    if meta is not None:
        return failed(
            ResultCode.INVALID_REQUEST,
            ACTION,
            f"shell metacharacter {meta!r} is not allowed in a command",
        )

    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        # Unbalanced quotes, a trailing backslash — the string has no single
        # unambiguous reading, so there is nothing to evaluate.
        return failed(
            ResultCode.INVALID_REQUEST, ACTION, f"could not parse command: {exc}"
        )

    if not tokens:
        return failed(ResultCode.INVALID_REQUEST, ACTION, "no command given")

    args = tuple(tokens[1:])
    return ParsedCommand(
        # Lowercased so `RM` cannot slip past a rule written for `rm`. This
        # matches how safety.policy.evaluate lowercases the action it is given.
        action=tokens[0].lower(),
        args=args,
        argv=tuple(tokens),
        attributes=frozenset(args),
    )
