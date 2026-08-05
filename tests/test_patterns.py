"""Tests for safety/patterns.py.

The scanner is small enough that its behaviour is mostly its edge cases: what it
returns when several patterns match, what it does with an empty needle, and
whether the two shipped vocabularies actually cover what they claim to.
"""

from __future__ import annotations

import pytest

from safety.patterns import SHELL_METACHARACTERS, UNSAFE_NAME_CHARACTERS, first_match


# --- first_match ------------------------------------------------------------


def test_returns_none_when_nothing_matches() -> None:
    assert first_match("ls -la", SHELL_METACHARACTERS) is None


def test_returns_the_matching_pattern() -> None:
    assert first_match("echo hi; rm -rf /", SHELL_METACHARACTERS) == ";"


def test_returns_by_pattern_order_not_text_position() -> None:
    """The answer names which rule tripped, not what came first in the string.

    ``|`` appears later in the text than ``>`` but earlier in the pattern tuple,
    so it is the one reported. This is the documented contract; a refusal message
    is more useful naming a rule than naming an offset.
    """
    assert SHELL_METACHARACTERS.index("|") < SHELL_METACHARACTERS.index(">")
    assert first_match("a > b | c", SHELL_METACHARACTERS) == "|"


def test_empty_text_matches_nothing() -> None:
    assert first_match("", SHELL_METACHARACTERS) is None


def test_empty_pattern_list_matches_nothing() -> None:
    assert first_match("rm -rf / ; echo", ()) is None


def test_an_empty_pattern_matches_everything() -> None:
    """`"" in anything` is True. Documented so nobody is surprised by it later."""
    assert first_match("harmless", ("",)) == ""


def test_accepts_any_iterable_not_just_a_tuple() -> None:
    assert first_match("a|b", ["|"]) == "|"
    assert first_match("a|b", iter(["|"])) == "|"


def test_matching_is_case_sensitive_and_literal() -> None:
    """No regex: a pattern's metacharacters are matched as themselves."""
    assert first_match("a.b", (".",)) == "."
    assert first_match("ab", (".",)) is None
    assert first_match("aXb", ("x",)) is None


# --- SHELL_METACHARACTERS ---------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("echo a; echo b", ";"),
        ("ls | wc", "|"),
        ("sleep 1 &", "&"),
        ("echo a && echo b", "&"),  # && is covered by &
        ("echo a || echo b", "|"),  # || is covered by |
        ("cat < in", "<"),
        ("cat > out", ">"),
        ("echo `id`", "`"),
        ("echo $(id)", "$("),
    ],
)
def test_every_chaining_form_is_caught(command: str, expected: str) -> None:
    assert first_match(command, SHELL_METACHARACTERS) == expected


def test_a_bare_dollar_is_not_an_operator() -> None:
    """Only `$(` substitutes. `$HOME` is inert under shell=False."""
    assert first_match("echo $HOME", SHELL_METACHARACTERS) is None


def test_ordinary_commands_are_left_alone() -> None:
    for command in ["ls -la", "git status", "echo hello world", "pwd", "cat file.txt"]:
        assert first_match(command, SHELL_METACHARACTERS) is None


# --- UNSAFE_NAME_CHARACTERS -------------------------------------------------


def test_covers_every_c0_control_character_and_del() -> None:
    """A gap here is a character that could slip through a name check."""
    assert set(UNSAFE_NAME_CHARACTERS) == {chr(c) for c in range(32)} | {"\x7f"}
    assert len(UNSAFE_NAME_CHARACTERS) == 33


@pytest.mark.parametrize(
    "name",
    [
        "report\nfake-audit-line.pdf",  # would split a JSONL audit record
        "invoice\r.pdf",  # carriage return, overwrites displayed text
        "sneaky\x1b[2Kname.txt",  # escape sequence, redraws a terminal
        "nul\x00byte.txt",
        "tab\tseparated.txt",
        "del\x7fchar.txt",
    ],
)
def test_catches_names_that_misrepresent_themselves(name: str) -> None:
    assert first_match(name, UNSAFE_NAME_CHARACTERS) is not None


@pytest.mark.parametrize(
    "name",
    [
        "report.pdf",
        "My Photo (2024).jpeg",
        "notes-v2_final.md",
        ".hidden",
        "ünïcödé-résumé.docx",  # non-ASCII is not a control character
        "emoji-🎉.png",
    ],
)
def test_leaves_ordinary_names_alone(name: str) -> None:
    assert first_match(name, UNSAFE_NAME_CHARACTERS) is None


def test_a_slash_is_not_flagged_here() -> None:
    """Path separators are a containment question, not a character question.

    ``safety.paths.PathJail`` answers that one. Flagging `/` here as well would
    put the same rule in two places and let them disagree.
    """
    assert first_match("../etc/passwd", UNSAFE_NAME_CHARACTERS) is None
