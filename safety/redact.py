"""Secret redaction over text. Pure functions, no I/O, no config parsing.

Any text on its way out of a server — command output, a directory listing, a
path, an audit field — may carry a secret that the agent should not see and the
log should not keep. This module strips them.

Two design choices carried over because they earn their keep:

* **Named placeholders.** A hit becomes ``[REDACTED:<name>]``, not a row of
  asterisks, so an operator reading a log can still tell that a secret appeared
  and what kind it was.
* **Keys stay, values go.** For ``token=…``, ``--password …``, and
  ``Authorization: …`` only the value is replaced. Losing the key would hide the
  fact that a credential was passed at all.

One rule is new here, lifted out of the terminal server's executor where only
one server benefited from it: **redact before truncating, never after** — see
:func:`redact_and_truncate`.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass

__all__ = [
    "Pattern",
    "BUILTIN_PATTERNS",
    "redact",
    "compile_extra",
    "build_patterns",
    "make_redactor",
    "shannon_entropy",
    "entropy_redact",
    "redact_and_truncate",
    "TRUNCATION_MARKER",
]

TRUNCATION_MARKER = "...[truncated]"


@dataclass(frozen=True)
class Pattern:
    """A named, pre-compiled redaction rule."""

    name: str
    regex: re.Pattern[str]
    repl: Callable[[re.Match[str]], str]


def _whole(name: str) -> Callable[[re.Match[str]], str]:
    """Replace the entire match — used when the match *is* the secret."""
    placeholder = f"[REDACTED:{name}]"
    return lambda _m: placeholder


def _keep_key(name: str) -> Callable[[re.Match[str]], str]:
    """Keep group 1 (the key or header) and replace only the value after it."""
    placeholder = f"[REDACTED:{name}]"
    return lambda m: m.group(1) + placeholder


def _pattern(name: str, regex: str, *, keep_key: bool = False, flags: int = 0) -> Pattern:
    return Pattern(
        name=name,
        regex=re.compile(regex, flags),
        repl=_keep_key(name) if keep_key else _whole(name),
    )


# Compiled once at import, never per call — redaction runs on every byte of
# output a server returns, so the cost of recompiling would be paid constantly.
#
# Keyed rules are listed first so a keyed secret keeps its key rather than being
# swallowed whole by a later vendor-token rule. Order affects only which
# placeholder a value ends up with; every rule still redacts.
BUILTIN_PATTERNS: tuple[Pattern, ...] = (
    _pattern(
        "private_key_block",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        flags=re.DOTALL,
    ),
    _pattern(
        "auth_header",
        r"(Authorization:\s*\S+\s+)\S+",
        keep_key=True,
        flags=re.IGNORECASE,
    ),
    _pattern(
        # Long forms only. A bare `-p` means something else entirely in cp, ssh,
        # and mkdir; redacting the token after it would corrupt ordinary text
        # while protecting nothing. Operators can add short flags themselves.
        "cli_flag",
        r"(?<!\S)((?:--password|--token|--secret|--api-key|--apikey)(?:=|\s+))\S+",
        keep_key=True,
    ),
    _pattern(
        "assignment",
        r"((?i:api[_-]?key|secret|token|password|passwd|pwd)\s*=\s*)\S+",
        keep_key=True,
    ),
    _pattern("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    _pattern("github_token", r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    _pattern("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    _pattern("langsmith_key", r"\blsv2_[A-Za-z0-9_-]{20,}\b"),
    _pattern("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    _pattern(
        "aws_secret_key",
        r"((?i:aws)[^\n]{0,40}?(?i:secret)[^\n]{0,20}?['\"\s:=]+)[A-Za-z0-9/+]{40}\b",
        keep_key=True,
    ),
    _pattern("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
)


def redact(text: str, patterns: Iterable[Pattern]) -> str:
    """Apply every pattern to ``text`` and return the result."""
    for pattern in patterns:
        text = pattern.regex.sub(pattern.repl, text)
    return text


def compile_extra(name: str, regex: str) -> Pattern:
    """Compile one operator-supplied pattern.

    Lets ``re.error`` propagate: a typo'd regex in an operator's config must fail
    loudly at load time, not be quietly skipped and leave a secret unredacted.
    """
    return Pattern(name=name, regex=re.compile(regex), repl=_whole(name))


def build_patterns(extra: Iterable[tuple[str, str]] = ()) -> tuple[Pattern, ...]:
    """Built-ins plus operator-defined ``(name, regex)`` pairs."""
    return BUILTIN_PATTERNS + tuple(compile_extra(n, r) for n, r in extra)


def make_redactor(
    patterns: Iterable[Pattern] | None = None,
    *,
    entropy_fallback: bool = False,
) -> Callable[[str], str]:
    """Build a reusable text -> text redactor.

    Defaults to the built-in patterns with the entropy fallback **off**; see
    :func:`entropy_redact` for why that default is not timidity.
    """
    compiled = tuple(patterns) if patterns is not None else BUILTIN_PATTERNS

    def _redactor(text: str) -> str:
        text = redact(text, compiled)
        if entropy_fallback:
            text = entropy_redact(text)
        return text

    return _redactor


# --- entropy fallback (opt-in) -------------------------------------------

# Candidates for "might be a secret": base64/base64url-ish and long enough that
# ordinary words don't qualify.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s``, in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_redact(text: str, *, min_len: int = 20, threshold: float = 4.0) -> str:
    """Redact unrecognised high-entropy tokens as ``[REDACTED:high_entropy]``.

    Off by default because it is noisy, not because it is weak: git SHAs, UUIDs,
    checksums, and base64 payloads all trip it, and a file organizer listing
    content-addressed filenames would see most of its output disappear. Callers
    that value catching an unknown token over readable output opt in.
    """

    def _sub(m: re.Match[str]) -> str:
        token = m.group(0)
        if len(token) >= min_len and shannon_entropy(token) >= threshold:
            return "[REDACTED:high_entropy]"
        return token

    return _TOKEN.sub(_sub, text)


# --- ordering guarantee ---------------------------------------------------

def redact_and_truncate(
    text: str,
    redactor: Callable[[str], str] | None,
    *,
    max_bytes: int,
    marker: str = TRUNCATION_MARKER,
) -> tuple[str, bool]:
    """Redact the whole text, *then* cap it. Returns ``(text, was_truncated)``.

    The order is the entire point. Truncating first and redacting the remainder
    leaves the head of a secret sitting at the cut — the pattern no longer
    matches, so nothing removes it, and half a credential is still a leak. By
    redacting the full text first, the secret is already a short placeholder
    before any byte cap is applied.

    Capping is done on encoded bytes (an output limit is a transport limit, and
    one character is not one byte), then decoded with ``errors="replace"`` so a
    cut landing mid-codepoint yields a replacement character rather than raising.
    """
    if redactor is not None:
        text = redactor(text)
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", errors="replace") + marker, True
