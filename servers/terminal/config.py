"""Load ``policy.toml`` and translate it into the shared rule model.

``safety/policy.py`` evaluates rules but reads no files and defines no config
format, on the grounds that a loader belongs with the server that knows what its
config looks like. This is that loader for the terminal server: it owns the
*file format* and nothing else.

The translation is the interesting part. The config file speaks in allowlists,
denylists, and per-command argument rules, because that is how an operator
thinks about a terminal. The rule model speaks in actions, effects, and required
attributes. Mapping one onto the other is a handful of lines, and crucially it
does **not** re-implement precedence: deny-wins and deny-by-default are already
properties of ``evaluate()``, so an entry appearing on both lists is denied
without this module containing a single ``if`` to that effect.

Malformed config raises rather than degrading. A policy file with a typo'd key
that silently becomes an empty allowlist would deny everything, which is safe but
baffling; one that silently becomes an empty *denylist* would not be safe at all.
"""

from __future__ import annotations

import os
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from safety.audit import FAIL_CLOSED, FAIL_OPEN
from safety.policy import ALLOW, DENY, Policy, Rule
from safety.redact import compile_extra

__all__ = [
    "ConfigError",
    "TerminalConfig",
    "ENV_POLICY_FILE",
    "ENV_JAIL_ROOT",
    "ENV_AUDIT_LOG",
    "ENV_AUDIT_FAIL_MODE",
    "load",
]

# Environment overrides. Suite-wide prefix rather than a per-server one: both
# servers will want a jail root and an audit log, and an operator should not have
# to learn two spellings of the same idea.
ENV_POLICY_FILE = "SAFE_MCP_POLICY_FILE"
ENV_JAIL_ROOT = "SAFE_MCP_JAIL_ROOT"
ENV_AUDIT_LOG = "SAFE_MCP_AUDIT_LOG"
ENV_AUDIT_FAIL_MODE = "SAFE_MCP_AUDIT_FAIL_MODE"

DEFAULT_POLICY_FILE = "policy.toml"
DEFAULT_AUDIT_LOG = "audit.jsonl"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 65536


class ConfigError(Exception):
    """Raised when the policy file is missing, unparseable, or malformed."""


@dataclass(frozen=True)
class TerminalConfig:
    """Everything the terminal server needs, validated and typed.

    ``policy`` is the translated rule set; the remaining fields are the knobs
    that are genuinely terminal-shaped (a deadline, an output cap) or
    deployment-shaped (where the jail is, where the log goes).
    """

    policy: Policy
    jail_root: str = ""  # "" means not configured; the entry point enforces it
    audit_log: str = DEFAULT_AUDIT_LOG
    audit_fail_mode: str = FAIL_CLOSED
    redaction_enabled: bool = True
    redaction_entropy_fallback: bool = False
    redaction_extra_patterns: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    timeout: float = DEFAULT_TIMEOUT
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES


def _table(data: dict, key: str) -> dict:
    """Fetch an optional table, rejecting anything that is not one."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a table")
    return value


def _str_list(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return value


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be a boolean")
    return value


def _positive_number(value: object, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where} must be a number")
    if value <= 0:
        raise ConfigError(f"{where} must be greater than zero")
    return float(value)


def _positive_int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where} must be an integer")
    if value <= 0:
        raise ConfigError(f"{where} must be greater than zero")
    return value


def _argument_rules(raw: object) -> tuple[Rule, ...]:
    """Translate ``[[rules]]`` entries into attribute-bearing deny rules.

    Each ``deny_args`` pattern becomes one rule requiring all of its tokens. The
    tokens are a *set*, so ``git push --force`` and ``git --force push`` both fire
    it — reordering is not a bypass. Splitting with ``shlex`` keeps matching at
    token level, so a pattern of ``--force`` does not accidentally match an
    argument that merely contains that substring.
    """
    if not isinstance(raw, list):
        raise ConfigError("[[terminal.rules]] must be an array of tables")

    rules: list[Rule] = []
    for index, entry in enumerate(raw):
        where = f"terminal.rules[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")

        command = entry.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ConfigError(f"{where}.command must be a non-empty string")

        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            raise ConfigError(f"{where}.reason must be a string")

        for pattern in _str_list(entry.get("deny_args", []), f"{where}.deny_args"):
            tokens = shlex.split(pattern)
            if not tokens:
                # An empty pattern would produce a rule with no required
                # attributes — a blanket deny of the whole command, which is
                # certainly not what "deny these arguments" was meant to say.
                raise ConfigError(f"{where}.deny_args contains an empty pattern")
            rules.append(
                Rule(
                    action=command,
                    effect=DENY,
                    attributes=frozenset(tokens),
                    reason=reason or f"{command} {pattern} is denied",
                )
            )
    return tuple(rules)


def _redaction(section: dict) -> tuple[bool, bool, tuple[tuple[str, str], ...]]:
    """Validate ``[redaction]``, compiling extra patterns to fail loudly here."""
    enabled = _bool(section.get("enabled", True), "redaction.enabled")
    entropy = _bool(
        section.get("entropy_fallback", False), "redaction.entropy_fallback"
    )

    raw = section.get("extra_patterns", [])
    if not isinstance(raw, list):
        raise ConfigError("redaction.extra_patterns must be a list of tables")

    extra: list[tuple[str, str]] = []
    for index, item in enumerate(raw):
        where = f"redaction.extra_patterns[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a table")
        name, regex = item.get("name"), item.get("regex")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{where}.name must be a non-empty string")
        if not isinstance(regex, str) or not regex:
            raise ConfigError(f"{where}.regex must be a non-empty string")
        try:
            # Compiled and thrown away purely to reject a bad regex at startup.
            # A typo'd pattern that failed at first use would mean the secret it
            # was written to catch goes out unredacted.
            compile_extra(name, regex)
        except Exception as exc:
            raise ConfigError(f"{where}.regex is not a valid regex: {exc}") from exc
        extra.append((name, regex))

    return enabled, entropy, tuple(extra)


def load(path: str | Path | None = None) -> TerminalConfig:
    """Read and validate the policy file into a :class:`TerminalConfig`.

    ``path`` defaults to ``$SAFE_MCP_POLICY_FILE`` and then to ``policy.toml``.
    Environment overrides win over file values for the jail root, audit log, and
    audit fail mode, so an operator can redirect a deployment without editing a
    file that is under version control.
    """
    resolved_path = Path(
        path or os.environ.get(ENV_POLICY_FILE) or DEFAULT_POLICY_FILE
    )
    try:
        with resolved_path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"policy file not found: {resolved_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"policy file is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read policy file: {exc}") from exc

    terminal = _table(data, "terminal")
    unknown = set(terminal) - {"jail_root", "limits", "allowlist", "denylist", "rules"}
    if unknown:
        # A misspelled key (e.g. "alowlist") would otherwise be silently ignored,
        # leaving a command allowed or denied by an empty list instead of by
        # what the operator actually wrote.
        raise ConfigError(f"[terminal] has unknown key(s): {', '.join(sorted(unknown))}")

    allow_names = _str_list(
        _table(terminal, "allowlist").get("commands", []), "terminal.allowlist.commands"
    )
    deny_names = _str_list(
        _table(terminal, "denylist").get("commands", []), "terminal.denylist.commands"
    )

    # The whole translation. Note what is absent: no precedence handling. An entry
    # on both lists produces one ALLOW rule and one DENY rule, and evaluate()
    # applies deny-wins on its own. A command on neither list produces no rule at
    # all, and deny-by-default handles it.
    rules = (
        tuple(Rule(action=name, effect=ALLOW) for name in allow_names)
        + tuple(
            Rule(
                action=name,
                effect=DENY,
                reason=f"{name!r} is on the denylist",
            )
            for name in deny_names
        )
        + _argument_rules(terminal.get("rules", []))
    )

    jail_root = os.environ.get(ENV_JAIL_ROOT) or terminal.get("jail_root", "")
    if not isinstance(jail_root, str):
        raise ConfigError("terminal.jail_root must be a string")

    audit_log = os.environ.get(ENV_AUDIT_LOG) or data.get(
        "audit_log", DEFAULT_AUDIT_LOG
    )
    if not isinstance(audit_log, str) or not audit_log:
        raise ConfigError("audit_log must be a non-empty string")

    audit_fail_mode = os.environ.get(ENV_AUDIT_FAIL_MODE) or data.get(
        "audit_fail_mode", FAIL_CLOSED
    )
    if audit_fail_mode not in (FAIL_CLOSED, FAIL_OPEN):
        raise ConfigError(
            f"audit_fail_mode must be {FAIL_CLOSED!r} or {FAIL_OPEN!r}, "
            f"got {audit_fail_mode!r}"
        )

    enabled, entropy, extra = _redaction(_table(data, "redaction"))
    limits = _table(terminal, "limits")

    return TerminalConfig(
        policy=Policy(rules=rules),
        jail_root=jail_root,
        audit_log=audit_log,
        audit_fail_mode=audit_fail_mode,
        redaction_enabled=enabled,
        redaction_entropy_fallback=entropy,
        redaction_extra_patterns=extra,
        timeout=_positive_number(
            limits.get("timeout_seconds", DEFAULT_TIMEOUT),
            "terminal.limits.timeout_seconds",
        ),
        max_output_bytes=_positive_int(
            limits.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES),
            "terminal.limits.max_output_bytes",
        ),
    )
