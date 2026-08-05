"""Load the ``[files]`` section of ``policy.toml`` into the shared rule model.

The counterpart to ``servers/terminal/config.py``, and it owns the same one thing:
a *file format*. ``safety/policy.py`` evaluates rules and reads no files;
``servers/files/inspect.py`` produces attributes and defines no rules. This module
is where an operator's TOML becomes ``Rule`` objects, and it adds no precedence
logic of its own — deny-wins and deny-by-default already belong to ``evaluate()``.

Two translation decisions are worth reading before the code.

**What is organizable at all.** Exactly one ALLOW rule is generated, and it
requires the ``file`` attribute. So a regular file is organizable unless a skip
rule denies it, while a directory or a symlink matches no allow rule and is
refused by deny-by-default — without any rule being written for it. That keeps
the core property pointed at the dangerous cases: enabling symlink traversal is
not something an operator can do by deleting a line.

**Skip rules are validated against the producer's vocabulary.** Every attribute
named in a rule must be one ``inspect.py`` can actually emit. A rule written for
``symlnk`` is a startup failure, not a rule that quietly never matches — a
guardrail that never fires is worse than none, because it looks like protection.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from safety.audit import FAIL_CLOSED, FAIL_OPEN
from safety.policy import ALLOW, DENY, Policy, Rule
from safety.redact import compile_extra
from servers.files.inspect import (
    ACTION,
    ATTRIBUTE_PREFIXES,
    BARE_ATTRIBUTES,
    EXT_PREFIX,
    FILE,
    NAME_PREFIX,
)

__all__ = [
    "ConfigError",
    "FilesConfig",
    "ENV_POLICY_FILE",
    "ENV_WORKSPACE_ROOT",
    "ENV_JOURNAL",
    "ENV_AUDIT_LOG",
    "ENV_AUDIT_FAIL_MODE",
    "DEFAULT_JOURNAL",
    "DEFAULT_MAX_PLAN_MOVES",
    "load",
]

# Same suite-wide prefix the terminal server uses. An operator should not have to
# learn two spellings of "where is the audit log".
ENV_POLICY_FILE = "SAFE_MCP_POLICY_FILE"
ENV_WORKSPACE_ROOT = "SAFE_MCP_WORKSPACE_ROOT"
ENV_JOURNAL = "SAFE_MCP_FILES_JOURNAL"
ENV_AUDIT_LOG = "SAFE_MCP_AUDIT_LOG"
ENV_AUDIT_FAIL_MODE = "SAFE_MCP_AUDIT_FAIL_MODE"

DEFAULT_POLICY_FILE = "policy.toml"
DEFAULT_AUDIT_LOG = "audit.jsonl"
DEFAULT_JOURNAL = "organizer-journal.json"
DEFAULT_MAX_PLAN_MOVES = 500


class ConfigError(Exception):
    """Raised when the policy file is missing, unparseable, or malformed."""


@dataclass(frozen=True)
class FilesConfig:
    """Everything the file server needs, validated and typed.

    ``categories`` is flattened at load time from the operator's
    category-to-extensions table into the extension-to-category lookup
    ``inspect.facts`` actually wants, so no consumer has to invert it later.
    """

    policy: Policy
    categories: dict[str, str] = field(default_factory=dict)
    workspace_root: str = ""  # "" means not configured; the entry point enforces it
    journal: str = DEFAULT_JOURNAL
    audit_log: str = DEFAULT_AUDIT_LOG
    audit_fail_mode: str = FAIL_CLOSED
    redaction_enabled: bool = True
    redaction_entropy_fallback: bool = False
    redaction_extra_patterns: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    max_plan_moves: int = DEFAULT_MAX_PLAN_MOVES


# ponytail: these four validators and _redaction below are near-copies of the ones
# in servers/terminal/config.py. Duplicated rather than shared because the only
# honest home for them is a new top-level config package, and two servers is not
# yet enough callers to justify one. Upgrade path: if a third server appears, or
# if the two [redaction] readings ever disagree, extract them then.
def _table(data: dict, key: str) -> dict:
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


def _positive_int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where} must be an integer")
    if value <= 0:
        raise ConfigError(f"{where} must be greater than zero")
    return value


def _check_attribute(attribute: str, where: str) -> str:
    """Reject any attribute ``inspect.py`` could never produce.

    This is the typo guard. ``ext:.exe`` and ``name:thumbs.db`` are checked for a
    non-empty value after the prefix; bare attributes are checked against the
    exact vocabulary. Values are lowercased to match how ``inspect`` emits them,
    so a rule written for ``ext:.EXE`` still fires.
    """
    if not attribute.strip():
        raise ConfigError(f"{where} contains an empty attribute")

    for prefix in ATTRIBUTE_PREFIXES:
        if attribute.startswith(prefix):
            value = attribute[len(prefix) :]
            if not value:
                raise ConfigError(f"{where}: {attribute!r} has no value after {prefix!r}")
            if prefix == EXT_PREFIX and not value.startswith("."):
                raise ConfigError(
                    f"{where}: {attribute!r} must include the dot, e.g. 'ext:.exe'"
                )
            return f"{prefix}{value.lower()}"

    if attribute not in BARE_ATTRIBUTES:
        known = ", ".join(sorted(BARE_ATTRIBUTES))
        raise ConfigError(
            f"{where}: {attribute!r} is not an attribute this server can produce. "
            f"Known attributes: {known}. Or use a prefix: "
            f"{EXT_PREFIX}<.ext>, {NAME_PREFIX}<filename>."
        )
    return attribute


def _skip_rules(raw: object) -> tuple[Rule, ...]:
    """Translate ``[[files.skip]]`` entries into DENY rules.

    ``when`` lists attributes every generated rule requires. ``any_ext`` and
    ``any_name`` each fan out into one rule per value, exactly as the terminal
    loader turns each ``deny_args`` pattern into its own rule — because a single
    rule's attributes are an AND, and "any of these extensions" is an OR.

    An entry that would generate a rule with no required attributes is refused: a
    blanket deny of every file is certainly not what "skip these" was meant to say.
    """
    if not isinstance(raw, list):
        raise ConfigError("[[files.skip]] must be an array of tables")

    rules: list[Rule] = []
    for index, entry in enumerate(raw):
        where = f"files.skip[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")

        unknown = set(entry) - {"when", "any_ext", "any_name", "reason"}
        if unknown:
            # A misspelled key would otherwise be silently ignored, leaving a rule
            # that denies nothing.
            raise ConfigError(f"{where} has unknown key(s): {', '.join(sorted(unknown))}")

        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            raise ConfigError(f"{where}.reason must be a string")

        base = frozenset(
            _check_attribute(a, f"{where}.when")
            for a in _str_list(entry.get("when", []), f"{where}.when")
        )
        extras = [
            _check_attribute(f"{EXT_PREFIX}{v}", f"{where}.any_ext")
            for v in _str_list(entry.get("any_ext", []), f"{where}.any_ext")
        ] + [
            _check_attribute(f"{NAME_PREFIX}{v}", f"{where}.any_name")
            for v in _str_list(entry.get("any_name", []), f"{where}.any_name")
        ]

        if not extras:
            if not base:
                raise ConfigError(
                    f"{where} must name at least one of when, any_ext, any_name"
                )
            rules.append(
                Rule(
                    action=ACTION,
                    effect=DENY,
                    attributes=base,
                    reason=reason or f"skipped by rule {where}",
                )
            )
            continue

        for extra in extras:
            rules.append(
                Rule(
                    action=ACTION,
                    effect=DENY,
                    attributes=base | {extra},
                    reason=reason or f"skipped by rule {where} ({extra})",
                )
            )

    return tuple(rules)


def _categories(section: dict) -> dict[str, str]:
    """Flatten ``[files.categories]`` into an extension-to-category lookup.

    A duplicate extension is a hard error rather than last-one-wins. Two
    categories claiming ``.pdf`` has no correct answer, and picking one silently
    would send files somewhere the operator did not intend.
    """
    mapping: dict[str, str] = {}
    for name, value in section.items():
        where = f"files.categories.{name}"
        if not name.strip():
            raise ConfigError("files.categories has an empty category name")
        # A category becomes a directory name under the workspace root. One
        # containing a separator or a `..` segment would aim every file in that
        # category outside the workspace, so it is refused at startup rather than
        # left for the jail to catch on every single move.
        if "/" in name or "\\" in name or name == ".." or name.startswith(".."):
            raise ConfigError(
                f"{where}: a category name must be a plain folder name, "
                f"with no path separators or '..' segments"
            )
        for ext in _str_list(value, where):
            if not ext.startswith(".") or len(ext) < 2:
                raise ConfigError(
                    f"{where}: {ext!r} must be an extension including the dot, e.g. '.pdf'"
                )
            lowered = ext.lower()
            if lowered in mapping and mapping[lowered] != name:
                raise ConfigError(
                    f"{where}: extension {lowered!r} is already claimed by "
                    f"category {mapping[lowered]!r}"
                )
            mapping[lowered] = name
    return mapping


def _redaction(section: dict) -> tuple[bool, bool, tuple[tuple[str, str], ...]]:
    """Validate the suite-wide ``[redaction]`` table, compiling extras eagerly."""
    enabled = _bool(section.get("enabled", True), "redaction.enabled")
    entropy = _bool(section.get("entropy_fallback", False), "redaction.entropy_fallback")

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
            compile_extra(name, regex)
        except Exception as exc:
            raise ConfigError(f"{where}.regex is not a valid regex: {exc}") from exc
        extra.append((name, regex))

    return enabled, entropy, tuple(extra)


def load(path: str | Path | None = None) -> FilesConfig:
    """Read and validate the policy file into a :class:`FilesConfig`.

    ``path`` defaults to ``$SAFE_MCP_POLICY_FILE`` and then to ``policy.toml`` —
    the same file the terminal server reads, a different section of it.
    """
    resolved_path = Path(path or os.environ.get(ENV_POLICY_FILE) or DEFAULT_POLICY_FILE)
    try:
        with resolved_path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"policy file not found: {resolved_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"policy file is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read policy file: {exc}") from exc

    files = _table(data, "files")
    unknown = set(files) - {
        "workspace_root",
        "journal",
        "max_plan_moves",
        "categories",
        "skip",
    }
    if unknown:
        raise ConfigError(f"[files] has unknown key(s): {', '.join(sorted(unknown))}")

    # The whole translation. One ALLOW requiring `file`, plus the skip denials.
    # Nothing else: a directory or symlink matches no allow rule and falls to
    # deny-by-default without a rule being written for it.
    rules = (
        Rule(
            action=ACTION,
            effect=ALLOW,
            attributes=frozenset({FILE}),
            reason="regular files are organizable unless a skip rule says otherwise",
        ),
    ) + _skip_rules(files.get("skip", []))

    workspace_root = os.environ.get(ENV_WORKSPACE_ROOT) or files.get(
        "workspace_root", ""
    )
    if not isinstance(workspace_root, str):
        raise ConfigError("files.workspace_root must be a string")

    journal = os.environ.get(ENV_JOURNAL) or files.get("journal", DEFAULT_JOURNAL)
    if not isinstance(journal, str) or not journal:
        raise ConfigError("files.journal must be a non-empty string")

    audit_log = os.environ.get(ENV_AUDIT_LOG) or data.get("audit_log", DEFAULT_AUDIT_LOG)
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

    return FilesConfig(
        policy=Policy(rules=rules),
        categories=_categories(_table(files, "categories")),
        workspace_root=workspace_root,
        journal=journal,
        audit_log=audit_log,
        audit_fail_mode=audit_fail_mode,
        redaction_enabled=enabled,
        redaction_entropy_fallback=entropy,
        redaction_extra_patterns=extra,
        max_plan_moves=_positive_int(
            files.get("max_plan_moves", DEFAULT_MAX_PLAN_MOVES),
            "files.max_plan_moves",
        ),
    )
