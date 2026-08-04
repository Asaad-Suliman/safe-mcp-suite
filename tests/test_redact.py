"""Redaction tests.

Every secret-shaped string below is synthetic: AWS's published example key, the
standard example JWT, and invented tokens. None of them is a live credential —
see .gitleaks.toml, which allowlists this file for exactly that reason.
"""

import re

import pytest

from safety.redact import (
    BUILTIN_PATTERNS,
    build_patterns,
    entropy_redact,
    make_redactor,
    redact,
    redact_and_truncate,
    shannon_entropy,
)


@pytest.fixture
def redactor():
    return make_redactor()


# --- built-in patterns ----------------------------------------------------

@pytest.mark.parametrize(
    ("name", "text", "secret"),
    [
        ("openai_key", "key is sk-abcdefghij0123456789 ok", "sk-abcdefghij0123456789"),
        ("github_token", "ghp_" + "a" * 30, "ghp_" + "a" * 30),
        ("slack_token", "xoxb-1234567890-abcdef", "xoxb-1234567890-abcdef"),
        ("langsmith_key", "lsv2_" + "b" * 24, "lsv2_" + "b" * 24),
        ("aws_access_key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
            "eyJhbGciOiJIUzI1NiJ9",
        ),
    ],
)
def test_builtin_pattern_removes_the_secret(redactor, name, text, secret):
    out = redactor(text)
    assert secret not in out
    assert f"[REDACTED:{name}]" in out


def test_private_key_block_redacted_across_lines(redactor):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redactor(text)
    assert "MIIEowIBAAKCAQEA" not in out
    assert out == "[REDACTED:private_key_block]"


# --- keyed secrets keep their key ----------------------------------------

@pytest.mark.parametrize(
    ("text", "kept", "secret"),
    [
        ("Authorization: Bearer abc123xyz", "Authorization: Bearer ", "abc123xyz"),
        ("curl --token hunter2 https://x", "--token ", "hunter2"),
        ("--password=hunter2", "--password=", "hunter2"),
        ("API_KEY=hunter2", "API_KEY=", "hunter2"),
        ("password = hunter2", "password = ", "hunter2"),
    ],
)
def test_key_survives_value_does_not(redactor, text, kept, secret):
    out = redactor(text)
    assert kept in out
    assert secret not in out


def test_aws_secret_key_keeps_its_context(redactor):
    text = "aws_secret_access_key = " + "A" * 20 + "b" * 20
    out = redactor(text)
    assert "aws_secret_access_key" in out
    assert "A" * 20 + "b" * 20 not in out


# --- ordinary text is left alone -----------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "cp -p source.txt dest.txt",       # -p is not a password flag
        "ssh -p 2222 host",                # nor here
        "ls -la /home/user/documents",
        "moved report.pdf to archive/2026/",
        "git commit -m 'fix the token parser'",  # the word alone is not a secret
    ],
)
def test_ordinary_text_untouched(redactor, text):
    assert redactor(text) == text


# --- operator-supplied patterns ------------------------------------------

def test_extra_pattern_is_applied():
    r = make_redactor(build_patterns([("internal_id", r"INT-[0-9]{8}")]))
    out = r("ticket INT-12345678 filed")
    assert "INT-12345678" not in out
    assert "[REDACTED:internal_id]" in out


def test_builtins_still_apply_alongside_extras():
    r = make_redactor(build_patterns([("internal_id", r"INT-[0-9]{8}")]))
    assert "AKIAIOSFODNN7EXAMPLE" not in r("AKIAIOSFODNN7EXAMPLE and INT-12345678")


def test_invalid_extra_regex_fails_loudly():
    # A typo'd operator regex must not be silently skipped.
    with pytest.raises(re.error):
        build_patterns([("broken", "([unclosed")])


# --- entropy fallback -----------------------------------------------------

def test_entropy_fallback_is_off_by_default(redactor):
    # A git SHA is high-entropy but not a secret; the default must keep it.
    sha = "9f8c1a2b3d4e5f60718293a4b5c6d7e8f9a0b1c2"
    assert sha in redactor(f"commit {sha}")


def test_entropy_fallback_catches_unknown_token_when_enabled():
    r = make_redactor(entropy_fallback=True)
    token = "Zk8Qp2Lx7Vn4Rm1Ty6Wb3Hc9Jd5Fg0As"
    out = r(f"opaque {token}")
    assert token not in out
    assert "[REDACTED:high_entropy]" in out


def test_entropy_of_empty_and_uniform_strings():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0


def test_short_tokens_are_below_the_entropy_floor():
    assert entropy_redact("abc123") == "abc123"


# --- the ordering guarantee ----------------------------------------------

def test_redaction_happens_before_truncation(redactor):
    # The secret is positioned so the byte cap would cut through the middle of
    # it. Redacting first turns it into a short placeholder, so nothing of it
    # can survive at the boundary.
    secret = "ghp_" + "z" * 36
    text = "x" * 50 + " " + secret + " tail"
    out, truncated = redact_and_truncate(text, redactor, max_bytes=60)
    assert truncated is True
    assert "ghp_" not in out
    assert "z" * 10 not in out


def test_truncating_first_would_have_leaked():
    # The inverse, to show the rule is load-bearing rather than decorative:
    # cutting first leaves a headless fragment that no pattern matches.
    redactor = make_redactor()
    secret = "ghp_" + "z" * 36
    text = "x" * 50 + " " + secret + " tail"
    wrong_order = redactor(text.encode("utf-8")[:60].decode("utf-8"))
    assert "ghp_" in wrong_order  # the leak the correct order prevents


def test_short_text_is_not_truncated(redactor):
    out, truncated = redact_and_truncate("hello", redactor, max_bytes=1024)
    assert (out, truncated) == ("hello", False)


def test_cap_counts_bytes_not_characters(redactor):
    # Four 3-byte characters exceed a 6-byte cap even though they are 4 chars.
    out, truncated = redact_and_truncate("日本語文", redactor, max_bytes=6)
    assert truncated is True
    assert out.startswith("日本")


def test_cut_mid_codepoint_does_not_raise(redactor):
    out, truncated = redact_and_truncate("日本語", redactor, max_bytes=4)
    assert truncated is True
    assert "日" in out  # the partial second character became a replacement char


def test_redact_and_truncate_without_a_redactor():
    # Redaction disabled by config: the cap must still apply.
    out, truncated = redact_and_truncate("x" * 100, None, max_bytes=10)
    assert truncated is True
    assert out.startswith("x" * 10)


def test_patterns_are_compiled_once():
    # Compiled at import, not per call — redaction runs over every byte of
    # output a server returns.
    assert all(isinstance(p.regex, re.Pattern) for p in BUILTIN_PATTERNS)
    assert redact("nothing here", BUILTIN_PATTERNS) == "nothing here"
