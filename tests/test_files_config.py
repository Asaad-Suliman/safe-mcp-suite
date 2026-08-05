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

from safety.policy import (
    ALLOW,
    DENY,
    PROTECTION,
    RESTRAINT,
    evaluate,
    evaluate_layered,
    protection_only,
)
from servers.files.config import (
    BASE_RULES,
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

#: The header of a skip entry. `layer` is required, so every fixture below must
#: declare one; these tests are about the translation rather than about the layer,
#: so they take the weaker of the two and the layer tests are grouped on their own.
SKIP = "\n[[files.skip]]\nlayer = 'restraint'\n"

SHIPPED = Path(__file__).resolve().parent.parent / "policy.toml"


def write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(body)
    return path


def decide(config, attributes):
    return evaluate(ACTION, attributes, policy=config.policy)


def decide_protection(config, attributes):
    """What move_file sees: the invariant subset, restraint rules removed."""
    return evaluate(ACTION, attributes, policy=protection_only(config.policy))


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


def test_a_directory_is_denied_to_the_organizer_by_a_restraint_rule(
    tmp_path: Path,
) -> None:
    """The organizer will not guess a category for a folder.

    A refusal to guess, not an invariant — so it is a restraint, and it is the
    layer rather than the refusal that carries the meaning.
    """
    cfg = load(write(tmp_path, MINIMAL))
    decision, layer = evaluate_layered(ACTION, {DIRECTORY}, policy=cfg.policy)
    assert decision.allowed is False
    assert layer == RESTRAINT


def test_a_directory_is_movable_once_the_restraint_rules_are_dropped(
    tmp_path: Path,
) -> None:
    """What move_file sees. A request that names a folder is not guessing."""
    cfg = load(write(tmp_path, MINIMAL))
    assert decide_protection(cfg, {DIRECTORY}).allowed is True


def test_a_symlink_is_denied_in_both_layers_with_no_rule_written_for_it(
    tmp_path: Path,
) -> None:
    """Deny-by-default in the protection layer too. No line to delete enables it."""
    cfg = load(write(tmp_path, MINIMAL))
    for decision in (decide(cfg, {SYMLINK}), decide_protection(cfg, {SYMLINK})):
        assert decision.allowed is False
        assert decision.rule is None

    assert evaluate_layered(ACTION, {SYMLINK}, policy=cfg.policy)[1] == PROTECTION


def test_only_files_and_directories_are_ever_allowed(tmp_path: Path) -> None:
    """The whole allow surface, in both layers. Everything else falls through.

    The organizer's own view is narrower still: a directory is allowed here and
    taken back by the restraint rule, which is why the check above matters.
    """
    cfg = load(write(tmp_path, MINIMAL))
    allows = [r for r in cfg.policy.rules if r.effect == ALLOW]
    assert [r.attributes for r in allows] == [
        frozenset({FILE}),
        frozenset({DIRECTORY}),
    ]
    assert all(r.layer == PROTECTION for r in allows)


# --- skip rules -------------------------------------------------------------


def test_a_when_rule_denies_a_matching_file(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + SKIP + "when = ['hidden']\nreason = 'dotfiles'\n",
        )
    )
    assert decide(cfg, {FILE, HIDDEN}).allowed is False
    assert decide(cfg, {FILE, HIDDEN}).reason == "dotfiles"
    assert decide(cfg, {FILE}).allowed is True


def test_any_ext_fans_out_into_one_rule_per_extension(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + SKIP + "any_ext = ['.exe', '.msi']\n",
        )
    )
    denies = [r for r in cfg.policy.rules if r.effect == DENY and r not in BASE_RULES]
    assert len(denies) == 2
    assert decide(cfg, {FILE, "ext:.exe"}).allowed is False
    assert decide(cfg, {FILE, "ext:.msi"}).allowed is False
    assert decide(cfg, {FILE, "ext:.pdf"}).allowed is True


def test_any_name_fans_out_into_one_rule_per_name(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + SKIP + "any_name = ['desktop.ini', 'thumbs.db']\n",
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
            MINIMAL + SKIP + "when = ['empty']\nany_ext = ['.log']\n",
        )
    )
    assert decide(cfg, {FILE, "empty", "ext:.log"}).allowed is False
    assert decide(cfg, {FILE, "ext:.log"}).allowed is True, "not empty, so not skipped"
    assert decide(cfg, {FILE, "empty"}).allowed is True, "not a .log, so not skipped"


def test_deny_wins_over_the_allow_without_the_loader_saying_so(tmp_path: Path) -> None:
    """Precedence comes from evaluate(), not from this module."""
    cfg = load(write(tmp_path, MINIMAL + SKIP + "when = ['file']\n"))
    assert decide(cfg, {FILE}).allowed is False


def test_extension_rules_are_case_insensitive(tmp_path: Path) -> None:
    cfg = load(write(tmp_path, MINIMAL + SKIP + "any_ext = ['.EXE']\n"))
    assert decide(cfg, {FILE, "ext:.exe"}).allowed is False


def test_rule_order_does_not_change_the_outcome(tmp_path: Path) -> None:
    first = load(
        write(tmp_path, MINIMAL + SKIP + "when = ['hidden']\n" +
              SKIP + "any_ext = ['.exe']\n")
    )
    other = tmp_path / "other.toml"
    other.write_text(
        MINIMAL + SKIP + "any_ext = ['.exe']\n" + SKIP + "when = ['hidden']\n"
    )
    second = load(other)
    for attrs in ({FILE, HIDDEN}, {FILE, "ext:.exe"}, {FILE, "ext:.pdf"}):
        assert decide(first, attrs).allowed == decide(second, attrs).allowed


# --- layers -----------------------------------------------------------------


def test_a_skip_entry_without_a_layer_is_rejected(tmp_path: Path) -> None:
    """No default. The loader is in no position to guess which kind of rule this is."""
    with pytest.raises(ConfigError, match="must declare a layer"):
        load(write(tmp_path, MINIMAL + "\n[[files.skip]]\nany_ext = ['.exe']\n"))


def test_an_unknown_layer_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="layer must be"):
        load(
            write(
                tmp_path,
                MINIMAL + "\n[[files.skip]]\nlayer = 'advisory'\nany_ext = ['.exe']\n",
            )
        )


def test_a_protection_rule_stops_move_file_too(tmp_path: Path) -> None:
    cfg = load(
        write(
            tmp_path,
            MINIMAL + "\n[[files.skip]]\nlayer = 'protection'\nwhen = ['unsafe-name']\n",
        )
    )
    assert decide(cfg, {FILE, "unsafe-name"}).allowed is False
    assert decide_protection(cfg, {FILE, "unsafe-name"}).allowed is False


def test_a_restraint_rule_stops_only_the_organizer(tmp_path: Path) -> None:
    """The distinction this phase exists to draw, at the loader level."""
    cfg = load(write(tmp_path, MINIMAL + SKIP + "any_ext = ['.exe']\n"))
    assert decide(cfg, {FILE, "ext:.exe"}).allowed is False
    assert decide_protection(cfg, {FILE, "ext:.exe"}).allowed is True


def test_every_rule_fanned_out_from_one_entry_carries_its_layer(tmp_path: Path) -> None:
    """A layer that applied to only the first extension would be a silent hole."""
    cfg = load(
        write(
            tmp_path,
            MINIMAL
            + "\n[[files.skip]]\nlayer = 'protection'\n"
            + "any_ext = ['.exe', '.msi']\nany_name = ['desktop.ini']\n",
        )
    )
    denies = [r for r in cfg.policy.rules if r.effect == DENY and r.attributes]
    generated = [r for r in denies if r.layer == PROTECTION]
    assert len(generated) == 3, "three values, three rules, all protection"


def test_the_shipped_policy_labels_every_skip_rule(tmp_path: Path) -> None:
    """The file that actually ships must not lean on a default that does not exist."""
    cfg = load(SHIPPED)
    assert all(r.layer in (PROTECTION, RESTRAINT) for r in cfg.policy.rules)
    # And it must draw the distinction, not label everything one way.
    assert {r.layer for r in cfg.policy.rules} == {PROTECTION, RESTRAINT}


# --- skip rule validation: the typo guard -----------------------------------


def test_an_unknown_attribute_is_rejected(tmp_path: Path) -> None:
    """A rule that never fires looks like protection. It must not load."""
    with pytest.raises(ConfigError, match="symlnk"):
        load(write(tmp_path, MINIMAL + SKIP + "when = ['symlnk']\n"))


def test_the_error_lists_the_known_attributes(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unsafe-name"):
        load(write(tmp_path, MINIMAL + SKIP + "when = ['nonsense']\n"))


def test_an_empty_skip_entry_is_rejected(tmp_path: Path) -> None:
    """It would generate a rule with no requirements: a blanket deny of everything."""
    with pytest.raises(ConfigError, match="at least one"):
        load(write(tmp_path, MINIMAL + SKIP + "reason = 'oops'\n"))


def test_an_unknown_key_in_a_skip_entry_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown key"):
        load(write(tmp_path, MINIMAL + SKIP + "whn = ['hidden']\n"))


def test_an_extension_without_a_dot_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="include the dot"):
        load(write(tmp_path, MINIMAL + SKIP + "any_ext = ['exe']\n"))


def test_a_prefix_with_no_value_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="no value"):
        load(write(tmp_path, MINIMAL + SKIP + "when = ['name:']\n"))


def test_skip_must_be_an_array_of_tables(tmp_path: Path) -> None:
    # `skip` here lands inside [files]: a TOML table runs until the next header.
    with pytest.raises(ConfigError, match="array of tables"):
        load(write(tmp_path, MINIMAL + "skip = 'nope'\n"))


def test_when_must_be_a_list_of_strings(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="list of strings"):
        load(write(tmp_path, MINIMAL + SKIP + "when = [1, 2]\n"))


def test_a_bare_prefixed_attribute_in_when_is_accepted(tmp_path: Path) -> None:
    """`when = ['ext:.exe']` is the long form of a one-value any_ext."""
    cfg = load(write(tmp_path, MINIMAL + SKIP + "when = ['ext:.exe']\n"))
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
