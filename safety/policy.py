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

**Rules come in two layers, and they are not equally binding.** A PROTECTION rule
is a safety invariant: the path escapes its jail, it is a symlink, its name
carries control characters. A RESTRAINT rule is a rule that exists only because
*automatic* classification would be a guess — installers, hidden files,
directories. A caller acting on its own initiative must respect both. A caller
carrying an explicit human request that names one specific target is not
guessing, and for it a restraint rule is not a safety refusal. Which callers get
which treatment is the server's decision; this module only makes the distinction
available and makes it impossible to get backwards (see :func:`evaluate_layered`).

This module is pure. It reads no files, runs nothing, and has no config format;
a loader belongs with the servers that know what their config looks like.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

__all__ = [
    "ALLOW",
    "DENY",
    "ANY_ACTION",
    "PROTECTION",
    "RESTRAINT",
    "Rule",
    "Policy",
    "Decision",
    "evaluate",
    "protection_only",
    "evaluate_layered",
]

ALLOW = "allow"
DENY = "deny"

#: Action name that matches every action, for blanket rules.
ANY_ACTION = "*"

#: A safety invariant. Binding on every caller, however explicit the request.
PROTECTION = "protection"

#: A rule that declines to *guess*. Binding on a caller acting unprompted; not a
#: safety refusal for one carrying an explicit request that names its target.
RESTRAINT = "restraint"

_LAYERS = (PROTECTION, RESTRAINT)


@dataclass(frozen=True)
class Rule:
    """One allow or deny rule.

    ``attributes`` are *requirements*: the rule fires only when the request
    carries **all** of them. An empty set therefore matches any request for that
    action, which is how a plain "this action is allowed" rule is written.

    Matching is set-based, so it is order-independent by construction. A rule
    requiring ``{"push", "--force"}`` fires on ``git push --force`` and equally
    on ``git --force push`` — a caller cannot reorder its way past a rule.

    ``layer`` is PROTECTION or RESTRAINT and defaults to PROTECTION, so a rule
    written without one is treated as an absolute — the strictest reading, and
    the one that keeps a forgotten label from quietly weakening a guardrail.
    """

    action: str
    effect: str = DENY
    attributes: frozenset[str] = field(default_factory=frozenset)
    reason: str = ""
    layer: str = PROTECTION

    def __post_init__(self) -> None:
        if self.effect not in (ALLOW, DENY):
            raise ValueError(f"effect must be {ALLOW!r} or {DENY!r}, got {self.effect!r}")
        if self.layer not in _LAYERS:
            raise ValueError(
                f"layer must be {PROTECTION!r} or {RESTRAINT!r}, got {self.layer!r}"
            )
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


def protection_only(policy: Policy) -> Policy:
    """The safety-invariant subset of ``policy``: its PROTECTION rules alone.

    Derived from the full policy rather than built alongside it. That is the
    point — a protection rule cannot go missing from this subset by omission,
    the way it could if two policies were assembled side by side and one
    assembly forgot a line.

    Dropping the restraint rules drops allow rules too if any carry that layer,
    which is deliberate: deny-by-default still applies, so a subset that lost an
    allow refuses more, never less.
    """
    return Policy(rules=tuple(r for r in policy.rules if r.layer == PROTECTION))


def evaluate_layered(
    action: str,
    attributes: Iterable[str] = (),
    *,
    policy: Policy,
) -> tuple[Decision, str | None]:
    """Evaluate ``policy`` and say *which layer* refused: the pair every caller wants.

    Returns ``(decision, layer)`` where ``layer`` is None when the request is
    allowed outright, PROTECTION when a safety invariant refused it, and
    RESTRAINT when it cleared every invariant and was refused only because the
    policy declines to guess about it.

    The protection subset is evaluated **first**, and that ordering is the whole
    reason this function exists. :func:`evaluate` returns the first matching deny
    in rule order, so a request matching a rule in each layer would otherwise be
    classified by whichever rule the operator happened to write higher up the
    file. A caller that honours only protection refusals would then be one
    reordering away from letting an invariant through.

    A refusal with no rule behind it — deny-by-default — is PROTECTION. It is the
    fallthrough for requests the policy has no vocabulary for at all, and the
    strictest reading is the only safe one to take of something unrecognised.
    """
    guarded = evaluate(action, attributes, policy=protection_only(policy))
    if not guarded.allowed:
        return guarded, PROTECTION

    decision = evaluate(action, attributes, policy=policy)
    return decision, (None if decision.allowed else RESTRAINT)
