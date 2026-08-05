"""Policy evaluation tests, bypass attempts included.

Policies are built inline as objects — this module has no config format, so
there is nothing to load. Several tests deliberately assert the *same* outcome
from differently ordered policies; that redundancy is the point.
"""

import pytest

from safety.policy import (
    ALLOW,
    ANY_ACTION,
    DENY,
    PROTECTION,
    RESTRAINT,
    Decision,
    Policy,
    Rule,
    evaluate,
    evaluate_layered,
    protection_only,
)

# A small policy exercising the interesting overlaps: git is allowed in general
# but force-push is denied, and "clean" sits on both sides to prove deny wins.
_ALLOW_GIT = Rule(action="git", effect=ALLOW, reason="git is allowed")
_DENY_FORCE_PUSH = Rule(
    action="git",
    effect=DENY,
    attributes={"push", "--force"},
    reason="force-push rewrites shared history",
)
_ALLOW_CLEAN = Rule(action="clean", effect=ALLOW)
_DENY_CLEAN = Rule(action="clean", effect=DENY, reason="clean is destructive")


@pytest.fixture
def policy():
    return Policy((_ALLOW_GIT, _DENY_FORCE_PUSH, _ALLOW_CLEAN, _DENY_CLEAN))


# --- deny by default ------------------------------------------------------

def test_empty_policy_denies_everything():
    d = evaluate("anything", policy=Policy())
    assert d.allowed is False
    assert d.rule is None


def test_unmatched_action_denied_by_default(policy):
    d = evaluate("wget", ["http://x"], policy=policy)
    assert d.allowed is False
    assert d.rule is None
    assert "deny by default" in d.reason


def test_allow_rule_permits(policy):
    d = evaluate("git", ["status"], policy=policy)
    assert d.allowed is True
    assert d.rule is _ALLOW_GIT


# --- deny wins, regardless of order ---------------------------------------

def test_deny_wins_when_both_match(policy):
    d = evaluate("clean", policy=policy)
    assert d.allowed is False
    assert d.reason == "clean is destructive"


@pytest.mark.parametrize(
    "rules",
    [
        (_ALLOW_CLEAN, _DENY_CLEAN),  # allow listed first
        (_DENY_CLEAN, _ALLOW_CLEAN),  # deny listed first
    ],
    ids=["allow-first", "deny-first"],
)
def test_rule_order_cannot_flip_the_decision(rules):
    assert evaluate("clean", policy=Policy(rules)).allowed is False


def test_many_allows_cannot_outvote_one_deny():
    rules = (
        Rule(action="rm", effect=ALLOW),
        Rule(action="rm", effect=ALLOW, attributes={"-f"}),
        Rule(action="rm", effect=DENY, reason="no"),
        Rule(action="rm", effect=ALLOW, attributes={"-r"}),
    )
    assert evaluate("rm", ["-r", "-f"], policy=Policy(rules)).allowed is False


# --- attribute matching is order-independent ------------------------------

@pytest.mark.parametrize(
    "attrs",
    [
        ["push", "--force"],
        ["--force", "push"],          # reordered
        ["push", "--force", "origin"],  # extra attributes present
        ["--force", "origin", "push"],
    ],
)
def test_attribute_reordering_does_not_bypass(policy, attrs):
    d = evaluate("git", attrs, policy=policy)
    assert d.allowed is False
    assert d.rule is _DENY_FORCE_PUSH


def test_rule_needing_two_attributes_does_not_fire_on_one(policy):
    # `git push` alone is fine; only the pair is denied.
    assert evaluate("git", ["push"], policy=policy).allowed is True
    assert evaluate("git", ["--force"], policy=policy).allowed is True


def test_empty_attribute_set_matches_any_request(policy):
    # _ALLOW_GIT carries no attributes, so it matches git with or without args.
    assert evaluate("git", policy=policy).allowed is True
    assert evaluate("git", ["log", "--oneline"], policy=policy).allowed is True


def test_attributes_accept_any_iterable(policy):
    for attrs in (["push", "--force"], ("push", "--force"), {"push", "--force"}):
        assert evaluate("git", attrs, policy=policy).allowed is False


# --- name matching --------------------------------------------------------

@pytest.mark.parametrize("action", ["clean", "CLEAN", "Clean"])
def test_action_matching_is_case_insensitive(action, policy):
    assert evaluate(action, policy=policy).allowed is False


def test_rule_action_is_normalized_at_construction():
    p = Policy((Rule(action="GIT", effect=ALLOW),))
    assert evaluate("git", policy=p).allowed is True


def test_wildcard_rule_matches_any_action():
    p = Policy((Rule(action=ANY_ACTION, effect=DENY, attributes={"sudo"}, reason="no sudo"),
                Rule(action="ls", effect=ALLOW)))
    assert evaluate("ls", policy=p).allowed is True
    assert evaluate("ls", ["sudo"], policy=p).allowed is False
    assert evaluate("anything", ["sudo"], policy=p).allowed is False


# --- layers ---------------------------------------------------------------

# One action refused by a rule in each layer. The pair exists to prove the
# classification does not depend on which of the two an operator wrote first.
_GUARD = Rule(action="organize", effect=DENY, attributes={"symlink"},
              reason="a symlink is not what it appears to be", layer=PROTECTION)
_CAUTION = Rule(action="organize", effect=DENY, attributes={"ext:.exe"},
                reason="installers are left alone", layer=RESTRAINT)
_ALLOW_ORGANIZE = Rule(action="organize", effect=ALLOW, attributes={"file"},
                       reason="files are organizable", layer=PROTECTION)


def test_a_rule_is_a_protection_rule_unless_it_says_otherwise():
    # The strictest reading. A forgotten label must not weaken a guardrail.
    assert Rule(action="git", effect=DENY).layer == PROTECTION


def test_an_unknown_layer_is_rejected():
    with pytest.raises(ValueError, match="layer must be"):
        Rule(action="git", effect=DENY, layer="advisory")


def test_protection_only_drops_restraint_rules_and_keeps_the_rest():
    subset = protection_only(Policy((_ALLOW_ORGANIZE, _GUARD, _CAUTION)))
    assert subset.rules == (_ALLOW_ORGANIZE, _GUARD)


def test_a_protection_refusal_is_reported_as_protection():
    p = Policy((_ALLOW_ORGANIZE, _GUARD))
    decision, layer = evaluate_layered("organize", {"symlink"}, policy=p)
    assert (decision.allowed, layer) == (False, PROTECTION)


def test_a_restraint_refusal_is_reported_as_restraint():
    p = Policy((_ALLOW_ORGANIZE, _CAUTION))
    decision, layer = evaluate_layered("organize", {"file", "ext:.exe"}, policy=p)
    assert (decision.allowed, layer) == (False, RESTRAINT)
    assert decision.reason == "installers are left alone"


def test_an_allowed_request_has_no_layer():
    p = Policy((_ALLOW_ORGANIZE, _GUARD, _CAUTION))
    decision, layer = evaluate_layered("organize", {"file", "ext:.pdf"}, policy=p)
    assert (decision.allowed, layer) == (True, None)


@pytest.mark.parametrize(
    "order",
    [(_GUARD, _CAUTION), (_CAUTION, _GUARD)],
    ids=["protection first", "restraint first"],
)
def test_matching_both_layers_reports_protection_whatever_the_rule_order(order):
    """The reason this helper exists.

    ``evaluate`` returns the first matching deny in rule order. A caller that
    honours only protection refusals would otherwise be one reordering of
    policy.toml away from letting a safety invariant through.
    """
    p = Policy((_ALLOW_ORGANIZE, *order))
    decision, layer = evaluate_layered(
        "organize", {"symlink", "ext:.exe"}, policy=p
    )
    assert layer == PROTECTION
    assert decision.rule is _GUARD


def test_deny_by_default_is_protection():
    # Nothing matched at all. An unrecognised request is not something to be
    # relaxed about, so the fallthrough takes the strictest layer.
    decision, layer = evaluate_layered("organize", {"dir"}, policy=Policy())
    assert (decision.allowed, decision.rule, layer) == (False, None, PROTECTION)


def test_an_allow_that_only_the_full_policy_carries_does_not_leak_into_protection():
    """A restraint-layered allow is dropped, and deny-by-default catches it.

    The subset may refuse more than the full policy; it must never refuse less.
    """
    p = Policy((Rule(action="organize", effect=ALLOW, attributes={"dir"},
                     layer=RESTRAINT),))
    assert evaluate("organize", {"dir"}, policy=p).allowed is True
    assert evaluate_layered("organize", {"dir"}, policy=p)[1] == PROTECTION


# --- rule validation ------------------------------------------------------

def test_invalid_effect_rejected():
    with pytest.raises(ValueError):
        Rule(action="git", effect="maybe")


def test_empty_action_rejected():
    with pytest.raises(ValueError):
        Rule(action="", effect=ALLOW)


def test_decision_is_data_not_an_exception(policy):
    # A denial is returned, never raised — the whole premise of the envelope.
    assert isinstance(evaluate("rm", ["-rf", "/"], policy=policy), Decision)
