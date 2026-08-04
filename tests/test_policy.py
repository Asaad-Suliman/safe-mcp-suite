"""Policy evaluation tests, bypass attempts included.

Policies are built inline as objects — this module has no config format, so
there is nothing to load. Several tests deliberately assert the *same* outcome
from differently ordered policies; that redundancy is the point.
"""

import pytest

from safety.policy import ALLOW, ANY_ACTION, DENY, Decision, Policy, Rule, evaluate

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
