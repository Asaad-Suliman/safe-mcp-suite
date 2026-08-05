"""Literal pattern scanning, and the character sets worth scanning for.

One function and two vocabularies. The function answers "does this text contain
any of these literals, and which one first" — which is the whole of what both
servers need, and is deliberately smaller than a regex engine because a scanner
nobody can misconfigure is worth more here than an expressive one.

The point of it living in ``safety/`` is that there is exactly one copy. The
terminal server scans a command line for shell operators; the file server scans a
filename for characters that have no business in one. Those are different
questions asked of the same code, and a fix to the scan is a fix to both.

Note what this module does **not** do: it does not refuse anything. It reports
what it found and returns. Whether a match is fatal, or merely an attribute for
``safety.policy`` to weigh, is the caller's decision — the terminal treats a shell
operator as unevaluable input, while the file server turns an odd filename into a
policy attribute. Neither behaviour is baked in here.
"""

from __future__ import annotations

from collections.abc import Iterable

__all__ = ["SHELL_METACHARACTERS", "UNSAFE_NAME_CHARACTERS", "first_match"]

# Shell control operators. Their presence means the caller is trying to chain,
# redirect, or substitute — none of which survives ``shell=False`` anyway, so a
# command containing one is either a mistake or an injection attempt.
#
# `||` and `&&` are covered by `|` and `&`; `$(` covers command substitution.
SHELL_METACHARACTERS: tuple[str, ...] = (";", "|", "&", "<", ">", "`", "$(")

# Every C0 control character, plus DEL. A filename may legally contain these on
# POSIX — the kernel only forbids `/` and NUL — which is precisely the problem:
# a name carrying a newline splits an audit line in two, and one carrying a
# carriage return or an escape sequence can redraw whatever terminal displays it.
# A file whose name misrepresents itself is not one to move around silently.
UNSAFE_NAME_CHARACTERS: tuple[str, ...] = tuple(chr(code) for code in range(32)) + (
    "\x7f",
)


def first_match(text: str, patterns: Iterable[str]) -> str | None:
    """Return the first pattern from ``patterns`` occurring in ``text``, else None.

    "First" is by pattern order, not by position in the text: the answer names
    *which rule tripped*, which is what a refusal message and an audit reason both
    want to say. Callers that need the position have a substring to search for.

    Matching is plain containment, with no awareness of quoting or escaping. That
    is the safe direction to be imprecise in — it over-matches (a shell operator
    inside quotes still counts) but there is no quoting trick that hides an
    operator from a scan that does not respect quoting in the first place.
    """
    for pattern in patterns:
        if pattern in text:
            return pattern
    return None
