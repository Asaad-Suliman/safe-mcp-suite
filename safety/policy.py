"""Deny-by-default rule evaluation. Decides nothing about *how* to act.

A request is modelled as an **action name** plus a set of **attributes**. That is
the whole vocabulary, and it is deliberately thin enough for both servers to
speak it:

    evaluate("git",  {"push", "--force"})       # terminal: argv tokens
    evaluate("move", {"ext:.exe", "dest:outside-inbox"})   # organizer: facts

Turning a request *into* an action and attributes is server work — the terminal
server parses argv, the organizer inspects the file. What happens next is shared:

1. Nothing is permitted unless a rule allows it.
2. Any matching deny beats any matching allow.

This module is pure. It reads no files, runs nothing, and has no config format;
a loader belongs with the servers that know what their config looks like.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

__all__ = ["ALLOW", "DENY", "ANY_ACTION", "Rule", "Policy", "Decision", "evaluate"]

ALLOW = "allow"
DENY = "deny"

#: Action name that matches every action, for blanket rules.
ANY_ACTION = "*"


@dataclass(frozen=True)
class Rule:
    """One allow or deny rule.

    ``attributes`` are *requirements*: the rule fires only when the request
    carries **all** of them. An empty set therefore matches any request for that
    action, which is how a plain "this action is allowed" rule is written.

    Matching is set-based, so it is order-independent by construction. A rule
    requiring ``{"push", "--force"}`` fires on ``git push --force`` and equally
    on ``git --force push`` — a caller cannot reorder its way past a rule.
    """

    action: str
    effect: str = DENY
    attributes: frozenset[str] = field(default_factory=frozenset)
    reason: str = ""

    def __post_init__(self) -> None:
        if self.effect not in (ALLOW, DENY):
            raise ValueError(f"effect must be {ALLOW!r} or {DENY!r}, got {self.effect!r}")
        if not self.action:
            raise ValueError("rule action must not be empty")
        # Normalize so callers can pass any iterable and any casing of the action
        # name. Frozen dataclass, hence object.__setattr__.
        object.__setattr__(self, "action", self.action.lower())
        object.__setattr__(self, "attributes", frozenset(self.attributes))

    def matches(self, action: str, attributes: frozenset[str]) -> bool:
        """True if this rule applies to the given request."""
        if self.action != ANY_ACTION and self.action != action:
            return False
        return self.attributes <= attributes


@dataclass(frozen=True)
class Policy:
    """An ordered-for-readability, unordered-in-effect collection of rules.

    Rule order is presentation only. Evaluation examines every matching rule and
    lets deny win, so reordering a policy file can never change a decision — a
    property worth keeping, because "the rules got sorted differently" is a
    terrible way to lose a guardrail.
    """

    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))


@dataclass(frozen=True)
class Decision:
    """Why a request was allowed or denied. Carries no side effects."""

    allowed: bool
    rule: Rule | None  # the rule that decided; None when nothing matched
    reason: str


def evaluate(
    action: str,
    attributes: Iterable[str] = (),
    *,
    policy: Policy,
) -> Decision:
    """Evaluate one request against ``policy``.

    Action matching is case-insensitive so ``RM`` cannot slip past a rule written
    for ``rm``. The fallthrough is denial: a request that matches no rule at all
    is refused, which is what makes an empty or half-written policy safe rather
    than wide open.
    """
    name = action.lower()
    attrs = frozenset(attributes)

    matched = [rule for rule in policy.rules if rule.matches(name, attrs)]

    # Deny wins. Scanning all matches (rather than returning the first hit) is
    # what makes the outcome independent of rule order.
    for rule in matched:
        if rule.effect == DENY:
            return Decision(
                allowed=False,
                rule=rule,
                reason=rule.reason or f"{action!r} is denied by rule {rule.action!r}",
            )

    for rule in matched:
        return Decision(
            allowed=True,
            rule=rule,
            reason=rule.reason or f"{action!r} is allowed",
        )

    return Decision(
        allowed=False,
        rule=None,
        reason=f"{action!r} is not permitted by any rule (deny by default)",
    )
