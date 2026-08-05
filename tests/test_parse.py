"""Tests for servers/terminal/parse.py."""

from __future__ import annotations

import pytest

from safety.result import OperationResult, ResultCode
from servers.terminal.parse import ACTION, METACHARACTERS, ParsedCommand, parse


def _ok(raw: str) -> ParsedCommand:
    """Parse and assert it succeeded, returning the parsed command."""
    result = parse(raw)
    assert isinstance(result, ParsedCommand), f"expected success, got {result}"
    return result


def _rejected(raw: str) -> OperationResult:
    """Parse and assert it was refused, returning the failed result."""
    result = parse(raw)
    assert isinstance(result, OperationResult), f"expected refusal, got {result}"
    return result


# --- metacharacter rejection ---------------------------------------------


@pytest.mark.parametrize("meta", METACHARACTERS)
def test_every_metacharacter_is_rejected(meta: str) -> None:
    result = _rejected(f"echo hello {meta} world")
    assert result.code is ResultCode.INVALID_REQUEST
    assert repr(meta) in result.reason


@pytest.mark.parametrize(
    "raw",
    [
        "ls; rm -rf /",
        "cat file | grep secret",
        "sleep 5 & echo done",
        "echo hi > /etc/passwd",
        "cat < /etc/shadow",
        "echo `whoami`",
        "echo $(whoami)",
        "ls && rm file",
        "ls || rm file",
    ],
)
def test_injection_shapes_are_rejected(raw: str) -> None:
    assert _rejected(raw).code is ResultCode.INVALID_REQUEST


def test_metacharacter_inside_quotes_is_still_rejected() -> None:
    """The documented ceiling: the scan is quote-blind, deliberately.

    `echo "a;b"` is harmless under shell=False, but rejecting it is the price of
    a scan that no quoting trick can slip past.
    """
    assert _rejected('echo "a;b"').code is ResultCode.INVALID_REQUEST
    assert _rejected("echo 'a|b'").code is ResultCode.INVALID_REQUEST


def test_metacharacter_is_checked_before_parsing() -> None:
    """A string that is both unquotable and injecting reports the metacharacter.

    Order matters: the metacharacter scan must not be reachable only via a
    successful shlex split, or an unbalanced quote would mask an injection.
    """
    result = _rejected("echo 'unbalanced ; rm -rf /")
    assert "';'" in result.reason


# --- empty and unparseable input ------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\t", "\n", "  \t \n "])
def test_empty_input_is_rejected(raw: str) -> None:
    result = _rejected(raw)
    assert result.code is ResultCode.INVALID_REQUEST
    assert result.reason == "no command given"


def test_unbalanced_quote_is_rejected_not_raised() -> None:
    result = _rejected("echo 'unterminated")
    assert result.code is ResultCode.INVALID_REQUEST
    assert "could not parse" in result.reason


def test_rejections_never_raise() -> None:
    """Whatever goes in, a result comes out. Nothing escapes as an exception."""
    for raw in ["", "'", '"', "\\", "echo \\", "ls ;", "$(", "`"]:
        assert isinstance(parse(raw), OperationResult)


def test_failed_results_are_not_ok_and_name_the_action() -> None:
    result = _rejected("")
    assert result.ok is False
    assert result.action == ACTION


def test_parse_never_returns_policy_denied() -> None:
    """Denial is the policy engine's word. Parsing only reports unevaluable input."""
    for raw in ["", "ls; rm -rf /", "echo 'unterminated"]:
        result = _rejected(raw)
        assert result.code is ResultCode.INVALID_REQUEST


# --- successful parsing ----------------------------------------------------


def test_simple_command_splits_into_action_and_args() -> None:
    parsed = _ok("git status --short")
    assert parsed.action == "git"
    assert parsed.args == ("status", "--short")
    assert parsed.argv == ("git", "status", "--short")


def test_bare_command_has_no_args() -> None:
    parsed = _ok("ls")
    assert parsed.action == "ls"
    assert parsed.args == ()
    assert parsed.argv == ("ls",)
    assert parsed.attributes == frozenset()


def test_action_is_lowercased() -> None:
    """`RM` must not slip past a rule written for `rm`."""
    assert _ok("RM file").action == "rm"
    assert _ok("Git STATUS").action == "git"


def test_arguments_keep_their_case() -> None:
    """Only the action is normalized; an argument's case can be meaningful."""
    assert _ok("git checkout MyBranch").args == ("checkout", "MyBranch")


def test_leading_and_trailing_whitespace_is_ignored() -> None:
    assert _ok("   ls -la   ").argv == ("ls", "-la")


def test_quoted_argument_with_space_stays_one_token() -> None:
    parsed = _ok('cat "my file.txt"')
    assert parsed.argv == ("cat", "my file.txt")


def test_argv_preserves_order_but_attributes_do_not() -> None:
    """Order is kept for execution and dropped for matching — on purpose.

    Set-based attributes are what make `git --force push` match the same rule as
    `git push --force`, so a caller cannot reorder past a guardrail.
    """
    forward = _ok("git push --force")
    reversed_ = _ok("git --force push")

    assert forward.argv != reversed_.argv
    assert forward.attributes == reversed_.attributes == frozenset({"push", "--force"})


def test_duplicate_arguments_collapse_in_attributes_only() -> None:
    parsed = _ok("git push push")
    assert parsed.args == ("push", "push")
    assert parsed.attributes == frozenset({"push"})


def test_parsed_command_is_immutable() -> None:
    parsed = _ok("ls -la")
    with pytest.raises(Exception):
        parsed.action = "rm"  # type: ignore[misc]


def test_attributes_feed_policy_evaluate_directly() -> None:
    """The whole point of the module: what comes out is what evaluate() takes."""
    from safety.policy import ALLOW, DENY, Policy, Rule, evaluate

    policy = Policy(
        rules=(
            Rule(action="git", effect=ALLOW),
            Rule(
                action="git",
                effect=DENY,
                attributes=frozenset({"push", "--force"}),
                reason="force-push rewrites shared history",
            ),
        )
    )

    allowed = _ok("git status")
    denied = _ok("git --force push")

    assert evaluate(allowed.action, allowed.attributes, policy=policy).allowed is True
    assert evaluate(denied.action, denied.attributes, policy=policy).allowed is False
