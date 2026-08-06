"""Tests for servers/terminal/config.py.

The loader's job is a translation, so most of these assert on the *behaviour* of
the resulting policy through ``evaluate()`` rather than on the shape of the rule
tuple. A rule list that looks right but decides wrong is the failure that matters.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safety.audit import FAIL_CLOSED, FAIL_OPEN
from safety.policy import evaluate
from servers.terminal import config
from servers.terminal.config import ConfigError, TerminalConfig, load
from servers.terminal.parse import ParsedCommand, parse

BASIC = """
[terminal.allowlist]
commands = ["ls", "echo", "git"]

[terminal.denylist]
commands = ["rm", "curl"]

[[terminal.rules]]
command = "git"
deny_args = ["push --force"]
reason = "force-push rewrites shared history"
"""


def _write(tmp_path: Path, body: str, name: str = "policy.toml") -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def _decide(cfg: TerminalConfig, raw: str):
    """Parse a command and evaluate it against the loaded policy."""
    parsed = parse(raw)
    assert isinstance(parsed, ParsedCommand), f"unparseable test input: {raw}"
    return evaluate(parsed.action, parsed.attributes, policy=cfg.policy)


# --- the translation, judged by how it decides -----------------------------


def test_allowlisted_command_is_allowed(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, BASIC))
    assert _decide(cfg, "ls -la").allowed is True


def test_unlisted_command_is_denied_by_default(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, BASIC))
    decision = _decide(cfg, "python script.py")
    assert decision.allowed is False
    assert decision.rule is None  # nothing matched; the fallthrough decided


def test_denylisted_command_is_denied(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, BASIC))
    assert _decide(cfg, "rm -rf /").allowed is False


def test_a_command_on_both_lists_is_denied(tmp_path: Path) -> None:
    """Deny-wins, and the loader contains no code that says so."""
    cfg = load(
        _write(
            tmp_path,
            """
[terminal.allowlist]
commands = ["git"]
[terminal.denylist]
commands = ["git"]
""",
        )
    )
    assert _decide(cfg, "git status").allowed is False


def test_case_is_normalized(tmp_path: Path) -> None:
    cfg = load(
        _write(
            tmp_path,
            """
[terminal.allowlist]
commands = ["ls"]
[terminal.denylist]
commands = ["RM"]
""",
        )
    )
    assert _decide(cfg, "RM file").allowed is False
    assert _decide(cfg, "LS").allowed is True


def test_argument_rule_denies_the_specific_pattern(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, BASIC))
    assert _decide(cfg, "git status").allowed is True
    assert _decide(cfg, "git push origin main").allowed is True

    denied = _decide(cfg, "git push --force")
    assert denied.allowed is False
    assert denied.reason == "force-push rewrites shared history"


def test_argument_rule_is_order_independent(tmp_path: Path) -> None:
    """Reordering the arguments is not a bypass."""
    cfg = load(_write(tmp_path, BASIC))
    assert _decide(cfg, "git --force push").allowed is False


def test_argument_rule_needs_every_token(tmp_path: Path) -> None:
    """A partial match must not fire the rule."""
    cfg = load(_write(tmp_path, BASIC))
    assert _decide(cfg, "git --force").allowed is True


def test_argument_rule_matching_is_token_level(tmp_path: Path) -> None:
    """`--force` must not match an argument that merely contains it."""
    cfg = load(_write(tmp_path, BASIC))
    assert _decide(cfg, "git push --force-with-lease").allowed is True


def test_multiple_deny_args_patterns_each_become_a_rule(tmp_path: Path) -> None:
    cfg = load(
        _write(
            tmp_path,
            """
[terminal.allowlist]
commands = ["git"]
[[terminal.rules]]
command = "git"
deny_args = ["push --force", "push -f"]
reason = "no force pushing"
""",
        )
    )
    assert _decide(cfg, "git push --force").allowed is False
    assert _decide(cfg, "git push -f").allowed is False
    assert _decide(cfg, "git push").allowed is True


def test_an_empty_policy_denies_everything(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, ""))
    assert cfg.policy.rules == ()
    assert _decide(cfg, "ls").allowed is False


# --- defaults and settings -------------------------------------------------


def test_defaults_are_applied(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, BASIC))
    assert cfg.audit_log == config.DEFAULT_AUDIT_LOG
    assert cfg.audit_fail_mode == FAIL_CLOSED
    assert cfg.redaction_enabled is True
    assert cfg.redaction_entropy_fallback is False
    assert cfg.timeout == config.DEFAULT_TIMEOUT
    assert cfg.max_output_bytes == config.DEFAULT_MAX_OUTPUT_BYTES
    assert cfg.jail_root == ""


def test_settings_are_read_from_the_file(tmp_path: Path) -> None:
    cfg = load(
        _write(
            tmp_path,
            """
audit_log = "/var/log/trail.jsonl"
audit_fail_mode = "open"

[redaction]
enabled = false
entropy_fallback = true
extra_patterns = [{ name = "internal_id", regex = "INT-[0-9]{8}" }]

[terminal]
jail_root = "/srv/sandbox"

[terminal.limits]
timeout_seconds = 5
max_output_bytes = 1024
""",
        )
    )
    assert cfg.jail_root == "/srv/sandbox"
    assert cfg.audit_log == "/var/log/trail.jsonl"
    assert cfg.audit_fail_mode == FAIL_OPEN
    assert cfg.timeout == 5.0
    assert cfg.max_output_bytes == 1024
    assert cfg.redaction_enabled is False
    assert cfg.redaction_entropy_fallback is True
    assert cfg.redaction_extra_patterns == (("internal_id", "INT-[0-9]{8}"),)


def test_config_is_immutable(tmp_path: Path) -> None:
    cfg = load(_write(tmp_path, BASIC))
    with pytest.raises(Exception):
        cfg.jail_root = "/elsewhere"  # type: ignore[misc]


# --- environment overrides -------------------------------------------------


def test_env_overrides_beat_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(
        tmp_path,
        """
audit_log = "/from/file.jsonl"
audit_fail_mode = "closed"

[terminal]
jail_root = "/from/file"
""",
    )
    monkeypatch.setenv(config.ENV_JAIL_ROOT, "/from/env")
    monkeypatch.setenv(config.ENV_AUDIT_LOG, "/from/env.jsonl")
    monkeypatch.setenv(config.ENV_AUDIT_FAIL_MODE, "open")

    cfg = load(path)
    assert cfg.jail_root == "/from/env"
    assert cfg.audit_log == "/from/env.jsonl"
    assert cfg.audit_fail_mode == FAIL_OPEN


def test_policy_file_path_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path, BASIC, name="elsewhere.toml")
    monkeypatch.setenv(config.ENV_POLICY_FILE, str(path))
    assert _decide(load(), "ls").allowed is True


def test_an_invalid_env_fail_mode_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(config.ENV_AUDIT_FAIL_MODE, "maybe")
    with pytest.raises(ConfigError, match="audit_fail_mode"):
        load(_write(tmp_path, BASIC))


# --- failing loudly --------------------------------------------------------


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load(tmp_path / "absent.toml")


def test_invalid_toml_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid TOML"):
        load(_write(tmp_path, "this is not = = toml"))


def test_a_directory_instead_of_a_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load(tmp_path)


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ('[terminal.allowlist]\ncommands = "ls"', "allowlist.commands"),
        ("[terminal.allowlist]\ncommands = [1, 2]", "allowlist.commands"),
        ('[terminal.denylist]\ncommands = "rm"', "denylist.commands"),
        ('[terminal]\nallowlist = "not a table"', r"\[allowlist\]"),
        ('audit_fail_mode = "sometimes"', "audit_fail_mode"),
        ("audit_log = 42", "audit_log"),
        ("[terminal]\njail_root = 42", "terminal.jail_root"),
        ("terminal = \"not a table\"", r"\[terminal\]"),
        ('[terminal]\nrules = "not an array"', r"\[\[terminal\.rules\]\]"),
        ("[terminal]\nbogus = \"x\"", "unknown key"),
        ("[[terminal.rules]]\ndeny_args = []", "command"),
        ('[[terminal.rules]]\ncommand = ""', "command"),
        ('[[terminal.rules]]\ncommand = "git"\nreason = 5', "reason"),
        ('[[terminal.rules]]\ncommand = "git"\ndeny_args = "push"', "deny_args"),
        ('[[terminal.rules]]\ncommand = "git"\ndeny_args = ["  "]', "empty pattern"),
        ('redaction = "not a table"', r"\[redaction\]"),
        ("[redaction]\nenabled = 1", "redaction.enabled"),
        ("[redaction]\nentropy_fallback = 1", "entropy_fallback"),
        ('[redaction]\nextra_patterns = "no"', "extra_patterns"),
        ("[redaction]\nextra_patterns = [{ regex = \"x\" }]", "name"),
        ('[redaction]\nextra_patterns = [{ name = "n" }]', "regex"),
        ('[terminal.limits]\ntimeout_seconds = "fast"', "timeout_seconds"),
        ("[terminal.limits]\ntimeout_seconds = 0", "greater than zero"),
        ("[terminal.limits]\ntimeout_seconds = -5", "greater than zero"),
        ('[terminal.limits]\nmax_output_bytes = "big"', "max_output_bytes"),
        ("[terminal.limits]\nmax_output_bytes = 0", "greater than zero"),
    ],
)
def test_malformed_config_raises(tmp_path: Path, body: str, match: str) -> None:
    with pytest.raises(ConfigError, match=match):
        load(_write(tmp_path, body))


def test_an_uncompilable_extra_pattern_raises(tmp_path: Path) -> None:
    """A typo'd regex must fail at startup, not the first time a secret appears."""
    body = '[redaction]\nextra_patterns = [{ name = "bad", regex = "([unclosed" }]'
    with pytest.raises(ConfigError, match="not a valid regex"):
        load(_write(tmp_path, body))


# --- the shipped file ------------------------------------------------------


def test_the_shipped_policy_file_loads_and_behaves(tmp_path: Path) -> None:
    cfg = load(Path(__file__).resolve().parent.parent / "policy.toml")

    assert _decide(cfg, "ls -la").allowed is True
    assert _decide(cfg, "git status").allowed is True
    assert _decide(cfg, "rm -rf /").allowed is False
    assert _decide(cfg, "sudo reboot").allowed is False
    assert _decide(cfg, "git push --force").allowed is False
    assert _decide(cfg, "git clean -fdx").allowed is False
    assert _decide(cfg, "python evil.py").allowed is False
    assert cfg.jail_root == ""  # deliberately unset; the operator must choose one
