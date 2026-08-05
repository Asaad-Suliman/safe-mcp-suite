"""Tests for servers/files/plan.py.

Two claims are under test. First, that planning writes nothing — checked by
comparing the whole tree before and after, not by trusting the code's intent.
Second, that verification refuses a plan that no longer matches reality, and
refuses *all* of it rather than the part that still fits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safety.paths import PathJail
from safety.policy import DENY, PROTECTION, RESTRAINT, Policy, Rule
from safety.result import ResultCode
from servers.files import inspect
from servers.files.config import BASE_RULES
from servers.files.plan import Plan, build, verify

CATEGORIES = {".pdf": "Documents", ".png": "Images", ".mp3": "Audio"}

# The rules config actually generates, imported rather than restated. A local
# copy would let this file keep testing a policy shape the loader had stopped
# producing, which is the failure mode these tests exist to catch.
BASE_POLICY = Policy(rules=BASE_RULES)


def workspace(tmp_path: Path, *names: str) -> PathJail:
    root = tmp_path / "workspace"
    root.mkdir()
    for name in names:
        (root / name).write_text(f"contents of {name}")
    return PathJail.create(root)


def tree(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def plan_for(jail: PathJail, policy: Policy = BASE_POLICY, max_moves: int = 100) -> Plan:
    return build(jail, policy=policy, categories=CATEGORIES, max_moves=max_moves)


# --- planning proposes ------------------------------------------------------


def test_a_file_becomes_a_move(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "report.pdf")
    plan = plan_for(jail)

    assert len(plan.moves) == 1
    move = plan.moves[0]
    assert move.src == jail.root / "report.pdf"
    assert move.dest == jail.root / "Documents" / "report.pdf"
    assert move.category == "Documents"


def test_a_plan_has_an_id_and_a_timestamp(tmp_path: Path) -> None:
    plan = plan_for(workspace(tmp_path, "a.pdf"))
    assert plan.plan_id
    assert plan.created


def test_two_plans_get_different_ids(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    assert plan_for(jail).plan_id != plan_for(jail).plan_id


def test_files_are_planned_in_name_order(tmp_path: Path) -> None:
    """A proposal a human approves should not reshuffle between readings."""
    jail = workspace(tmp_path, "c.pdf", "a.pdf", "b.pdf")
    assert [m.src.name for m in plan_for(jail).moves] == ["a.pdf", "b.pdf", "c.pdf"]


def test_unknown_extensions_go_to_other(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "mystery.zzz")
    assert plan_for(jail).moves[0].dest == jail.root / "Other" / "mystery.zzz"


def test_the_fingerprint_is_captured(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    move = plan_for(jail).moves[0]
    st = (jail.root / "a.pdf").stat()
    assert move.size == st.st_size
    assert move.mtime_ns == st.st_mtime_ns


# --- planning writes nothing ------------------------------------------------


def test_planning_creates_no_directories(tmp_path: Path) -> None:
    """The reference created every category folder as a side effect of deciding."""
    jail = workspace(tmp_path, "a.pdf", "b.png", "c.mp3")
    before = tree(jail.root)

    plan_for(jail)

    assert tree(jail.root) == before
    assert not (jail.root / "Documents").exists()


def test_planning_twice_changes_nothing(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    before = tree(jail.root)
    plan_for(jail)
    plan_for(jail)
    assert tree(jail.root) == before


def test_planning_does_not_touch_file_contents_or_mtimes(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    before = (jail.root / "a.pdf").stat().st_mtime_ns
    plan_for(jail)
    assert (jail.root / "a.pdf").stat().st_mtime_ns == before


# --- skips ------------------------------------------------------------------


def test_a_directory_is_never_proposed_and_is_skipped_as_a_restraint(
    tmp_path: Path,
) -> None:
    """The organizer has no extension to file a folder by, so it does not guess.

    Restraint rather than protection: move_file will move the same directory
    when a request names it, and the code is what says so.
    """
    jail = workspace(tmp_path, "a.pdf")
    (jail.root / "Documents").mkdir()

    plan = plan_for(jail)

    assert [s.name for s in plan.skips] == ["Documents"]
    assert plan.skips[0].code is ResultCode.NEEDS_EXPLICIT_REQUEST
    assert len(plan.moves) == 1


def test_a_directory_with_a_categorised_extension_is_still_not_proposed(
    tmp_path: Path,
) -> None:
    """An application folder is a directory. The extension does not make it a file."""
    jail = workspace(tmp_path)
    (jail.root / "album.pdf").mkdir()

    plan = plan_for(jail)

    assert plan.moves == ()
    assert plan.skips[0].code is ResultCode.NEEDS_EXPLICIT_REQUEST


def test_a_symlink_is_skipped_and_never_followed(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "real.pdf")
    outside = tmp_path / "outside.pdf"
    outside.write_text("secret")
    (jail.root / "link.pdf").symlink_to(outside)

    plan = plan_for(jail)

    skip = next(s for s in plan.skips if s.name == "link.pdf")
    assert [m.src.name for m in plan.moves] == ["real.pdf"]
    # Protection, not restraint: there is no way of asking that moves this one.
    assert skip.code is ResultCode.POLICY_DENIED


def test_a_policy_denial_is_reported_with_its_reason(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "setup.exe", "report.pdf")
    policy = Policy(
        rules=BASE_POLICY.rules
        + (
            Rule(
                action=inspect.ACTION,
                effect=DENY,
                attributes=frozenset({"ext:.exe"}),
                reason="installers are left alone",
                layer=RESTRAINT,
            ),
        )
    )

    plan = plan_for(jail, policy)

    assert [m.src.name for m in plan.moves] == ["report.pdf"]
    skip = next(s for s in plan.skips if s.name == "setup.exe")
    assert skip.reason == "installers are left alone"
    assert skip.rule == inspect.ACTION
    assert skip.code is ResultCode.NEEDS_EXPLICIT_REQUEST


def test_a_skip_carries_the_layer_of_the_rule_that_caused_it(tmp_path: Path) -> None:
    """Two rules, same shape, different layers. Only the layer differs downstream."""
    jail = workspace(tmp_path, "setup.exe", "secret.pdf")
    policy = Policy(
        rules=BASE_POLICY.rules
        + (
            Rule(action=inspect.ACTION, effect=DENY, layer=RESTRAINT,
                 attributes=frozenset({"ext:.exe"}), reason="not guessing"),
            Rule(action=inspect.ACTION, effect=DENY, layer=PROTECTION,
                 attributes=frozenset({"name:secret.pdf"}), reason="never"),
        )
    )

    codes = {s.name: s.code for s in plan_for(jail, policy).skips}

    assert codes["setup.exe"] is ResultCode.NEEDS_EXPLICIT_REQUEST
    assert codes["secret.pdf"] is ResultCode.POLICY_DENIED


def test_a_protection_rule_wins_over_a_restraint_rule_on_the_same_file(
    tmp_path: Path,
) -> None:
    """A file both rules match is forbidden, not merely un-guessed at.

    The reverse would be a bypass: report it as a restraint and a caller acting
    on that report would try move_file, which honours protection only.
    """
    jail = workspace(tmp_path, "setup.exe")
    policy = Policy(
        rules=BASE_POLICY.rules
        + (
            Rule(action=inspect.ACTION, effect=DENY, layer=RESTRAINT,
                 attributes=frozenset({"ext:.exe"}), reason="not guessing"),
            Rule(action=inspect.ACTION, effect=DENY, layer=PROTECTION,
                 attributes=frozenset({"name:setup.exe"}), reason="never"),
        )
    )

    assert plan_for(jail, policy).skips[0].code is ResultCode.POLICY_DENIED


def test_an_existing_destination_is_skipped_at_plan_time(tmp_path: Path) -> None:
    """So the proposal a human reads is the truth, not a surprise at apply time."""
    jail = workspace(tmp_path, "report.pdf")
    (jail.root / "Documents").mkdir()
    (jail.root / "Documents" / "report.pdf").write_text("older copy")

    plan = plan_for(jail)

    assert plan.moves == ()
    skip = next(s for s in plan.skips if s.name == "report.pdf")
    assert "already exists" in skip.reason


def test_a_dangling_destination_symlink_still_counts_as_occupied(
    tmp_path: Path,
) -> None:
    jail = workspace(tmp_path, "report.pdf")
    (jail.root / "Documents").mkdir()
    (jail.root / "Documents" / "report.pdf").symlink_to(jail.root / "gone")

    plan = plan_for(jail)

    assert plan.moves == ()
    skip = next(s for s in plan.skips if s.name == "report.pdf")
    assert "already exists" in skip.reason


def test_a_symlink_at_the_destination_never_redirects_the_move(
    tmp_path: Path,
) -> None:
    """Regression: resolving the full destination followed the link.

    With a symlink sitting at Documents/report.pdf, resolving the whole
    destination path returned the link's *target*, so the plan proposed moving
    the file somewhere it never named. Only the category directory may be
    resolved; the filename is appended afterwards.
    """
    jail = workspace(tmp_path, "report.pdf")
    (jail.root / "Documents").mkdir()
    decoy = jail.root / "decoy.pdf"
    decoy.write_text("not the target")
    (jail.root / "Documents" / "report.pdf").symlink_to(decoy)

    plan = plan_for(jail)

    assert all(m.dest != decoy for m in plan.moves), "a symlink retargeted the move"
    assert not any(m.src.name == "report.pdf" for m in plan.moves)


def test_a_category_that_escapes_the_workspace_is_skipped(tmp_path: Path) -> None:
    """config refuses such a name at startup; this is the second lock."""
    jail = workspace(tmp_path, "a.pdf")
    plan = build(
        jail,
        policy=BASE_POLICY,
        categories={".pdf": "../escape"},
        max_moves=100,
    )
    assert plan.moves == ()
    assert "escapes the workspace" in plan.skips[0].reason


# --- limits -----------------------------------------------------------------


def test_a_plan_stops_at_max_moves_and_says_so(tmp_path: Path) -> None:
    jail = workspace(tmp_path, *[f"file{i}.pdf" for i in range(10)])

    plan = plan_for(jail, max_moves=3)

    assert len(plan.moves) == 3
    assert plan.truncated is True


def test_an_untruncated_plan_says_so(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    assert plan_for(jail).truncated is False


# --- describe ---------------------------------------------------------------


def test_describe_uses_workspace_relative_paths(tmp_path: Path) -> None:
    """An absolute path would leak the server's filesystem layout to the client."""
    jail = workspace(tmp_path, "report.pdf")
    described = plan_for(jail).describe()

    assert described["moves"][0]["src"] == "report.pdf"
    assert described["moves"][0]["dest"] == "Documents/report.pdf"
    assert str(tmp_path) not in str(described)


def test_describe_reports_counts(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    (jail.root / "sub").mkdir()
    described = plan_for(jail).describe()
    assert described["move_count"] == 1
    assert described["skip_count"] == 1


# --- verify -----------------------------------------------------------------


def test_a_fresh_plan_verifies(tmp_path: Path) -> None:
    assert verify(plan_for(workspace(tmp_path, "a.pdf"))) is None


def test_an_empty_plan_verifies(tmp_path: Path) -> None:
    assert verify(plan_for(workspace(tmp_path))) is None


def test_a_modified_source_makes_the_plan_stale(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    plan = plan_for(jail)

    (jail.root / "a.pdf").write_text("different contents entirely")

    result = verify(plan)
    assert result is not None
    assert result.code is ResultCode.INVALID_REQUEST
    assert "stale" in result.reason


def test_a_deleted_source_makes_the_plan_stale(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    plan = plan_for(jail)

    (jail.root / "a.pdf").unlink()

    result = verify(plan)
    assert result is not None
    assert result.code is ResultCode.INVALID_REQUEST
    assert "no longer there" in result.reason


def test_a_touched_source_makes_the_plan_stale(tmp_path: Path) -> None:
    """Same size, different mtime. Content-length alone is not a fingerprint."""
    jail = workspace(tmp_path, "a.pdf")
    plan = plan_for(jail)

    src = jail.root / "a.pdf"
    original = src.read_text()
    src.write_text(original)  # identical bytes, new mtime

    assert verify(plan) is not None


def test_one_stale_file_refuses_the_whole_plan(tmp_path: Path) -> None:
    """The point of the split: no partial application of an approved proposal."""
    jail = workspace(tmp_path, "a.pdf", "b.pdf", "c.pdf")
    plan = plan_for(jail)
    assert len(plan.moves) == 3

    (jail.root / "b.pdf").write_text("changed")

    result = verify(plan)
    assert result is not None
    assert result.detail["stale"] == "b.pdf"


def test_a_destination_that_appeared_since_planning_is_refused(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    plan = plan_for(jail)

    (jail.root / "Documents").mkdir()
    (jail.root / "Documents" / "a.pdf").write_text("got there first")

    result = verify(plan)
    assert result is not None
    assert result.code is ResultCode.OPERATION_FAILED
    assert "refusing to overwrite" in result.reason


def test_verify_writes_nothing(tmp_path: Path) -> None:
    jail = workspace(tmp_path, "a.pdf")
    plan = plan_for(jail)
    before = tree(jail.root)
    verify(plan)
    assert tree(jail.root) == before


def test_an_unrelated_new_file_does_not_make_a_plan_stale(tmp_path: Path) -> None:
    """Staleness is about the planned files, not about the directory in general."""
    jail = workspace(tmp_path, "a.pdf")
    plan = plan_for(jail)

    (jail.root / "newcomer.pdf").write_text("arrived later")

    assert verify(plan) is None


# --- the type is the enforcement --------------------------------------------


def test_a_plan_is_frozen(tmp_path: Path) -> None:
    plan = plan_for(workspace(tmp_path, "a.pdf"))
    with pytest.raises(AttributeError):
        plan.moves = ()  # type: ignore[misc]


def test_moves_are_frozen(tmp_path: Path) -> None:
    move = plan_for(workspace(tmp_path, "a.pdf")).moves[0]
    with pytest.raises(AttributeError):
        move.dest = Path("/elsewhere")  # type: ignore[misc]
