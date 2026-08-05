"""Tests for servers/files/config.py.

Two things are being checked. First, that malformed config fails loudly — a
policy file that degrades into "no rules" is the failure mode that matters, since
it looks like a working server. Second, that the translation adds no precedence
logic: the deny-wins and deny-by-default behaviour tested here is inherited from
safety.policy.evaluate, and these tests exist to prove the loader did not
accidentally reimplement it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safety.policy import ALLOW, DENY, evaluate
from servers.files.config import (
    DEFAULT_JOURNAL,
    DEFAULT_MAX_PLAN_MOVES,
    ENV_AUDIT_FAIL_MODE,
    ENV_AUDIT_LOG,
    ENV_JOURNAL,
    ENV_WORKSPACE_ROOT,
    ConfigError,
    load,
)
from servers.files.inspect import ACTION, DIRECTORY, FILE, HIDDEN, SYMLINK

MINIMAL = """
[files]
workspace_root = "/srv/inbox"
"""

SHIPPED = Path(__file__).resolve().parent.parent / "policy.toml"


def write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(body)
    return path


def decide(config, attributes):
    return evaluate(ACTION, attributes, policy=config.policy)


# --- the basics -------------------------------------------------------------


def test_minimal_config_loads(tmp_path: Path) -> None:
    cfg = load(write(tmp_path, MINIMAL))
    assert cfg.workspace_root == "/srv/inbox"
    assert cfg.journal == DEFAULT_JOURNAL
    assert cfg.max_plan_moves == DEFAULT_MAX_PLAN_MOVES
    assert cfg.categories == {}


def test_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load(tmp_path / "absent.toml")


def test_invalid_toml_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid TOML"):
        load(write(tmp_path, "[files\nbroken"))


def test_a_file_with_no_files_section_still_loads(tmp_path: Path) -> None:
    """The terminal's own policy.toml must not become unloadable for this server."""
    cfg = load(write(tmp_path, "[allowlist]\ncommands = ['ls']\n"))
    assert cfg.workspace_root == ""


def test_unknown_key_in_files_is_rejected(tmp_path: Path) -> None:
    """A misspelled key would otherwise be silently ignored."""
    with pytest.raises(ConfigError, match="unknown key"):
        load(write(tmp_path, "[files]\nworkspce_root = '/srv/inbox'\n"))


# --- what is organizable by default -----------------------------------------


def test_a_plain_file_is_allowed(tmp_path: Path) -> None:
    cfg = load(write(tmp_path, MINIMAL))
    assert decide(cfg, {FILE, "ext:.pdf"}).allowed is True


def test_a_directory_is_denied_with_no_rule_written_for_it(tmp_path: Path) -> None:
    """Deny-by-default, not a skip rule. There is no line to delete to enable it."""
    cfg = load(write(tmp_path, MINIMAL))
    decision = decide(cfg, {DIRECTORY})
    assert decision.allowed is False
    assert decision.rule is None


def test_a_symlink_is_denied_with_no_rule_written_for_it(tmp_path: Path) -> None:
    cfg = load(write(tmp_path, MINIMAL))
    decision = decide(cfg, {SYMLINK})
    assert decision.allowed is False
    assert decision.rule is None


def test_exactly_one_allow_rule_is_generated(tmp_path: Path) -> None:
    cfg = load(write(tmp_path, MINIMAL))
    allows = [r for r in cfg.policy.rules if r.effect == ALLOW]
    assert len(allows) == 1
    assert allows[0].attributes == frozenset({FILE})


# --- skip rules -------------------------------------------------------------


def test_a_when_rule_denies_a_matching_file(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[[files.skip]]\nwhen = ['hidden']\nreason = 'dotfiles'\n",
        )
    )
    assert decide(cfg, {FILE, HIDDEN}).allowed is False
    assert decide(cfg, {FILE, HIDDEN}).reason == "dotfiles"
    assert decide(cfg, {FILE}).allowed is True


def test_any_ext_fans_out_into_one_rule_per_extension(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[[files.skip]]\nany_ext = ['.exe', '.msi']\n",
        )
    )
    denies = [r for r in cfg.policy.rules if r.effect == DENY]
    assert len(denies) == 2
    assert decide(cfg, {FILE, "ext:.exe"}).allowed is False
    assert decide(cfg, {FILE, "ext:.msi"}).allowed is False
    assert decide(cfg, {FILE, "ext:.pdf"}).allowed is True


def test_any_name_fans_out_into_one_rule_per_name(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[[files.skip]]\nany_name = ['desktop.ini', 'thumbs.db']\n",
        )
    )
    assert decide(cfg, {FILE, "name:desktop.ini"}).allowed is False
    assert decide(cfg, {FILE, "name:thumbs.db"}).allowed is False
    assert decide(cfg, {FILE, "name:report.pdf"}).allowed is True


def test_when_combines_with_any_ext_as_an_and(tmp_path: Path) -> None:
    """when narrows every generated rule; the fan-out values are the alternatives."""
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[[files.skip]]\nwhen = ['empty']\nany_ext = ['.log']\n",
        )
    )
    assert decide(cfg, {FILE, "empty", "ext:.log"}).allowed is False
    assert decide(cfg, {FILE, "ext:.log"}).allowed is True, "not empty, so not skipped"
    assert decide(cfg, {FILE, "empty"}).allowed is True, "not a .log, so not skipped"


def test_deny_wins_over_the_allow_without_the_loader_saying_so(tmp_path: Path) -> None:
    """Precedence comes from evaluate(), not from this module."""
    cfg = load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = ['file']\n"))
    assert decide(cfg, {FILE}).allowed is False


def test_extension_rules_are_case_insensitive(tmp_path: Path) -> None:
    cfg = load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nany_ext = ['.EXE']\n"))
    assert decide(cfg, {FILE, "ext:.exe"}).allowed is False


def test_rule_order_does_not_change_the_outcome(tmp_path: Path) -> None:
    first = load(
        write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = ['hidden']\n" +
              "\n[[files.skip]]\nany_ext = ['.exe']\n")
    )
    other = tmp_path / "other.toml"
    other.write_text(
        MINIMAL + "\n[[files.skip]]\nany_ext = ['.exe']\n"
        "\n[[files.skip]]\nwhen = ['hidden']\n"
    )
    second = load(other)
    for attrs in ({FILE, HIDDEN}, {FILE, "ext:.exe"}, {FILE, "ext:.pdf"}):
        assert decide(first, attrs).allowed == decide(second, attrs).allowed


# --- skip rule validation: the typo guard -----------------------------------


def test_an_unknown_attribute_is_rejected(tmp_path: Path) -> None:
    """A rule that never fires looks like protection. It must not load."""
    with pytest.raises(ConfigError, match="symlnk"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = ['symlnk']\n"))


def test_the_error_lists_the_known_attributes(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unsafe-name"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = ['nonsense']\n"))


def test_an_empty_skip_entry_is_rejected(tmp_path: Path) -> None:
    """It would generate a rule with no requirements: a blanket deny of everything."""
    with pytest.raises(ConfigError, match="at least one"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nreason = 'oops'\n"))


def test_an_unknown_key_in_a_skip_entry_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown key"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhn = ['hidden']\n"))


def test_an_extension_without_a_dot_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="include the dot"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nany_ext = ['exe']\n"))


def test_a_prefix_with_no_value_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="no value"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = ['name:']\n"))


def test_skip_must_be_an_array_of_tables(tmp_path: Path) -> None:
    # `skip` here lands inside [files]: a TOML table runs until the next header.
    with pytest.raises(ConfigError, match="array of tables"):
        load(write(tmp_path, MINIMAL + "skip = 'nope'\n"))


def test_when_must_be_a_list_of_strings(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="list of strings"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = [1, 2]\n"))


def test_a_bare_prefixed_attribute_in_when_is_accepted(tmp_path: Path) -> None:
    """`when = ['ext:.exe']` is the long form of a one-value any_ext."""
    cfg = load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nwhen = ['ext:.exe']\n"))
    assert decide(cfg, {FILE, "ext:.exe"}).allowed is False


# --- categories -------------------------------------------------------------


def test_categories_are_flattened_to_an_extension_lookup(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[files.categories]\nImages = ['.png', '.JPG']\n",
        )
    )
    assert cfg.categories == {".png": "Images", ".jpg": "Images"}


def test_a_duplicate_extension_across_categories_is_rejected(tmp_path: Path) -> None:
    """Two categories claiming .pdf has no right answer; do not pick one silently."""
    with pytest.raises(ConfigError, match="already claimed"):
        load(
            write(
                tmp_path,
                MINIMAL
                + "\n[files.categories]\nDocuments = ['.pdf']\nArchive = ['.pdf']\n",
            )
        )


def test_repeating_an_extension_within_one_category_is_fine(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[files.categories]\nImages = ['.png', '.PNG']\n",
        )
    )
    assert cfg.categories == {".png": "Images"}


def test_a_category_extension_needs_a_dot(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="including the dot"):
        load(write(tmp_path, MINIMAL + "\n[files.categories]\nImages = ['png']\n"))


def test_categories_must_be_lists_of_strings(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="list of strings"):
        load(write(tmp_path, MINIMAL + "\n[files.categories]\nImages = 'png'\n"))


# --- limits and paths -------------------------------------------------------


def test_max_plan_moves_must_be_a_positive_integer(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="greater than zero"):
        load(write(tmp_path, MINIMAL + "max_plan_moves = 0\n"))


def test_max_plan_moves_rejects_a_non_integer(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must be an integer"):
        load(write(tmp_path, "[files]\nworkspace_root='/x'\nmax_plan_moves = 1.5\n"))


def test_journal_must_not_be_empty(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="journal"):
        load(write(tmp_path, "[files]\nworkspace_root='/x'\njournal = ''\n"))


def test_audit_fail_mode_is_validated(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="audit_fail_mode"):
        load(write(tmp_path, MINIMAL + "\naudit_fail_mode = 'maybe'\n"))


# --- environment overrides --------------------------------------------------


def test_env_overrides_win_over_file_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_WORKSPACE_ROOT, "/from/env")
    monkeypatch.setenv(ENV_JOURNAL, "/env/journal.json")
    monkeypatch.setenv(ENV_AUDIT_LOG, "/env/audit.jsonl")
    monkeypatch.setenv(ENV_AUDIT_FAIL_MODE, "open")

    cfg = load(write(tmp_path, MINIMAL + "\njournal = 'from-file.json'\n"))

    assert cfg.workspace_root == "/from/env"
    assert cfg.journal == "/env/journal.json"
    assert cfg.audit_log == "/env/audit.jsonl"
    assert cfg.audit_fail_mode == "open"


def test_workspace_root_is_not_defaulted(tmp_path: Path) -> None:
    """Empty means unconfigured. The entry point refuses; the loader does not guess."""
    cfg = load(write(tmp_path, "[files]\njournal = 'j.json'\n"))
    assert cfg.workspace_root == ""


# --- the file that actually ships -------------------------------------------


def test_the_shipped_policy_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_WORKSPACE_ROOT, raising=False)
    monkeypatch.delenv(ENV_JOURNAL, raising=False)
    cfg = load(SHIPPED)
    assert cfg.categories[".pdf"] == "Documents"
    assert cfg.max_plan_moves > 0


def test_the_shipped_policy_ships_no_workspace_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It must be a deliberate choice by the operator, never a shipped default."""
    monkeypatch.delenv(ENV_WORKSPACE_ROOT, raising=False)
    assert load(SHIPPED).workspace_root == ""


@pytest.mark.parametrize(
    "attributes",
    [
        {DIRECTORY},
        {SYMLINK},
        {FILE, HIDDEN},
        {FILE, "unsafe-name"},
        {FILE, "ext:.exe"},
        {FILE, "ext:.msi"},
        {FILE, "ext:.lnk"},
        {FILE, "name:desktop.ini"},
        {FILE, "name:thumbs.db"},
    ],
)
def test_the_shipped_policy_refuses_what_it_claims_to(attributes) -> None:
    assert evaluate(ACTION, attributes, policy=load(SHIPPED).policy).allowed is False


@pytest.mark.parametrize(
    "attributes",
    [
        {FILE, "ext:.pdf", "name:report.pdf"},
        {FILE, "ext:.png", "name:photo.png"},
        {FILE, "ext:.mp3", "name:song.mp3"},
    ],
)
def test_the_shipped_policy_still_organizes_ordinary_files(attributes) -> None:
    """The other half: this is a guard, not a wall."""
    assert evaluate(ACTION, attributes, policy=load(SHIPPED).policy).allowed is True
