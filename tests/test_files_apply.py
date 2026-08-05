"""Tests for servers/files/apply.py.

This is the only module that mutates the filesystem, so these tests are the last
line before real files move. The cases that matter are the refusals: a
destination that exists must survive untouched, an escaping path must move
nothing, and a stale plan must move nothing *at all* rather than the part of it
that still fits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safety.paths import PathJail
from safety.policy import ALLOW, Policy, Rule
from safety.result import ResultCode
from servers.files import inspect
from servers.files.apply import apply_plan, move_one
from servers.files.journal import Journal, JournalError
from servers.files.plan import build

CATEGORIES = {".pdf": "Documents", ".png": "Images"}
POLICY = Policy(
    rules=(Rule(action=inspect.ACTION, effect=ALLOW, attributes=frozenset({"file"})),)
)


@pytest.fixture
def jail(tmp_path: Path) -> PathJail:
    root = tmp_path / "workspace"
    root.mkdir()
    return PathJail.create(root)


@pytest.fixture
def journal(tmp_path: Path) -> Journal:
    return Journal(tmp_path / "state" / "journal.json")


def make(jail: PathJail, name: str, content: str = "contents") -> Path:
    path = jail.root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def tree(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def plan_for(jail: PathJail, max_moves: int = 100):
    return build(jail, policy=POLICY, categories=CATEGORIES, max_moves=max_moves)


# --- move_one: the happy path -----------------------------------------------


def test_a_file_moves(jail: PathJail) -> None:
    make(jail, "report.pdf")
    result = move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert result.ok is True
    assert result.code is ResultCode.OK
    assert (jail.root / "Documents" / "report.pdf").read_text() == "contents"
    assert not (jail.root / "report.pdf").exists()


def test_the_destination_directory_is_created(jail: PathJail) -> None:
    make(jail, "report.pdf")
    move_one("report.pdf", "Deeply/Nested/report.pdf", jail=jail)
    assert (jail.root / "Deeply" / "Nested" / "report.pdf").exists()


def test_detail_paths_are_workspace_relative(jail: PathJail) -> None:
    """An absolute path would leak the server's filesystem layout to the client."""
    make(jail, "report.pdf")
    result = move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert result.detail["src"] == "report.pdf"
    assert result.detail["dest"] == "Documents/report.pdf"
    assert str(jail.root) not in str(result.detail)


def test_the_action_can_be_restamped(jail: PathJail) -> None:
    make(jail, "a.pdf")
    result = move_one("a.pdf", "b.pdf", jail=jail, action="move_file")
    assert result.action == "move_file"


# --- move_one: no silent overwrite ------------------------------------------


def test_an_existing_destination_is_refused(jail: PathJail) -> None:
    make(jail, "report.pdf", "new")
    make(jail, "Documents/report.pdf", "original")

    result = move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert result.ok is False
    assert result.code is ResultCode.OPERATION_FAILED
    assert "refusing to overwrite" in result.reason


def test_a_refused_overwrite_leaves_both_files_untouched(jail: PathJail) -> None:
    make(jail, "report.pdf", "new")
    make(jail, "Documents/report.pdf", "original")

    move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert (jail.root / "Documents" / "report.pdf").read_text() == "original"
    assert (jail.root / "report.pdf").read_text() == "new"


def test_no_numbered_variant_is_invented(jail: PathJail) -> None:
    """The reference silently renamed to report(1).pdf. That behaviour is gone."""
    make(jail, "report.pdf", "new")
    make(jail, "Documents/report.pdf", "original")

    move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert not (jail.root / "Documents" / "report(1).pdf").exists()
    assert tree(jail.root) == {"report.pdf", "Documents", "Documents/report.pdf"}


def test_a_dangling_symlink_at_the_destination_counts_as_occupied(
    jail: PathJail,
) -> None:
    make(jail, "report.pdf")
    (jail.root / "Documents").mkdir()
    (jail.root / "Documents" / "report.pdf").symlink_to(jail.root / "nowhere")

    result = move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert result.ok is False
    assert "refusing to overwrite" in result.reason
    assert (jail.root / "report.pdf").exists()


def test_an_existing_directory_at_the_destination_is_refused(jail: PathJail) -> None:
    make(jail, "report.pdf")
    (jail.root / "Documents" / "report.pdf").mkdir(parents=True)

    result = move_one("report.pdf", "Documents/report.pdf", jail=jail)

    assert result.ok is False
    assert (jail.root / "report.pdf").exists()


# --- move_one: containment --------------------------------------------------


@pytest.mark.parametrize(
    "escape",
    ["../outside.pdf", "../../etc/passwd", "sub/../../outside.pdf"],
)
def test_a_traversal_source_is_refused(jail: PathJail, escape: str) -> None:
    result = move_one(escape, "Documents/x.pdf", jail=jail)
    assert result.ok is False
    assert result.code is ResultCode.PATH_ESCAPE


@pytest.mark.parametrize(
    "escape",
    ["../outside.pdf", "../../tmp/stolen.pdf", "sub/../../outside.pdf"],
)
def test_a_traversal_destination_is_refused(jail: PathJail, escape: str) -> None:
    make(jail, "report.pdf")
    result = move_one("report.pdf", escape, jail=jail)

    assert result.ok is False
    assert result.code is ResultCode.PATH_ESCAPE
    assert (jail.root / "report.pdf").exists(), "the source must not have moved"


def test_an_absolute_path_outside_the_workspace_is_refused(
    jail: PathJail, tmp_path: Path
) -> None:
    make(jail, "report.pdf")
    outside = tmp_path / "outside"
    outside.mkdir()

    result = move_one("report.pdf", str(outside / "stolen.pdf"), jail=jail)

    assert result.code is ResultCode.PATH_ESCAPE
    assert not (outside / "stolen.pdf").exists()


def test_a_symlinked_directory_escaping_the_workspace_is_refused(
    jail: PathJail, tmp_path: Path
) -> None:
    """The classic: a link inside the jail whose target is outside it."""
    outside = tmp_path / "outside"
    outside.mkdir()
    make(jail, "report.pdf")
    (jail.root / "escape").symlink_to(outside, target_is_directory=True)

    result = move_one("report.pdf", "escape/stolen.pdf", jail=jail)

    assert result.code is ResultCode.PATH_ESCAPE
    assert not (outside / "stolen.pdf").exists()
    assert (jail.root / "report.pdf").exists()


def test_a_symlink_source_is_moved_as_itself_not_followed(
    jail: PathJail, tmp_path: Path
) -> None:
    """Moving a link must not move whatever it points at."""
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (jail.root / "link.txt").symlink_to(outside)

    result = move_one("link.txt", "Documents/link.txt", jail=jail)

    assert result.ok is True
    assert outside.exists(), "the link's target must not have been moved"
    assert (jail.root / "Documents" / "link.txt").is_symlink()


@pytest.mark.parametrize("bad", ["", ".", "..", "sub/.."])
def test_a_destination_with_no_real_name_is_refused(jail: PathJail, bad: str) -> None:
    make(jail, "report.pdf")
    result = move_one("report.pdf", bad, jail=jail)
    assert result.code is ResultCode.PATH_ESCAPE


# --- move_one: missing source -----------------------------------------------


def test_a_missing_source_is_reported(jail: PathJail) -> None:
    result = move_one("absent.pdf", "Documents/absent.pdf", jail=jail)
    assert result.ok is False
    assert result.code is ResultCode.OPERATION_FAILED
    assert "source not found" in result.reason


def test_a_missing_source_creates_no_destination_directory(jail: PathJail) -> None:
    move_one("absent.pdf", "Documents/absent.pdf", jail=jail)
    assert not (jail.root / "Documents").exists()


# --- apply_plan -------------------------------------------------------------


def test_a_plan_applies(jail: PathJail, journal: Journal) -> None:
    make(jail, "a.pdf")
    make(jail, "b.png")
    plan = plan_for(jail)

    result = apply_plan(plan, jail=jail, journal=journal)

    assert result.ok is True
    assert result.detail["moved"] == 2
    assert (jail.root / "Documents" / "a.pdf").exists()
    assert (jail.root / "Images" / "b.png").exists()


def test_an_empty_plan_succeeds_quietly(jail: PathJail, journal: Journal) -> None:
    result = apply_plan(plan_for(jail), jail=jail, journal=journal)
    assert result.ok is True
    assert result.detail["moved"] == 0


def test_applying_records_one_journal_entry_for_the_whole_plan(
    jail: PathJail, journal: Journal
) -> None:
    make(jail, "a.pdf")
    make(jail, "b.png")

    apply_plan(plan_for(jail), jail=jail, journal=journal)

    assert journal.depths() == (1, 0)
    entry = journal.peek_undo()
    assert entry.action == "apply_plan"
    assert len(entry.moves) == 2


def test_an_empty_plan_records_nothing(jail: PathJail, journal: Journal) -> None:
    apply_plan(plan_for(jail), jail=jail, journal=journal)
    assert journal.depths() == (0, 0)


def test_a_truncated_plan_reports_truncated(jail: PathJail, journal: Journal) -> None:
    for i in range(5):
        make(jail, f"file{i}.pdf")

    result = apply_plan(plan_for(jail, max_moves=2), jail=jail, journal=journal)

    assert result.ok is True
    assert result.code is ResultCode.OUTPUT_TRUNCATED
    assert result.detail["moved"] == 2


# --- apply_plan: staleness refuses everything -------------------------------


def test_a_stale_plan_moves_nothing(jail: PathJail, journal: Journal) -> None:
    """The whole reason plan and apply are separate tools."""
    make(jail, "a.pdf")
    make(jail, "b.pdf")
    make(jail, "c.pdf")
    plan = plan_for(jail)
    before = tree(jail.root)

    (jail.root / "b.pdf").write_text("changed after planning")

    result = apply_plan(plan, jail=jail, journal=journal)

    assert result.ok is False
    assert result.code is ResultCode.INVALID_REQUEST
    assert "stale" in result.reason
    assert tree(jail.root) == before, "a stale plan moved something"


def test_a_stale_plan_records_nothing(jail: PathJail, journal: Journal) -> None:
    make(jail, "a.pdf")
    plan = plan_for(jail)
    (jail.root / "a.pdf").write_text("changed")

    apply_plan(plan, jail=jail, journal=journal)

    assert journal.depths() == (0, 0)


def test_a_deleted_source_refuses_the_whole_plan(
    jail: PathJail, journal: Journal
) -> None:
    make(jail, "a.pdf")
    make(jail, "b.pdf")
    plan = plan_for(jail)

    (jail.root / "a.pdf").unlink()

    result = apply_plan(plan, jail=jail, journal=journal)

    assert result.ok is False
    assert (jail.root / "b.pdf").exists(), "b must not have moved"


def test_a_destination_that_appeared_since_planning_refuses_everything(
    jail: PathJail, journal: Journal
) -> None:
    make(jail, "a.pdf")
    make(jail, "b.pdf")
    plan = plan_for(jail)

    make(jail, "Documents/a.pdf", "got there first")
    before = tree(jail.root)

    result = apply_plan(plan, jail=jail, journal=journal)

    assert result.code is ResultCode.OPERATION_FAILED
    assert "refusing to overwrite" in result.reason
    assert tree(jail.root) == before


def test_the_stale_result_names_apply_plan_not_the_planner(
    jail: PathJail, journal: Journal
) -> None:
    make(jail, "a.pdf")
    plan = plan_for(jail)
    (jail.root / "a.pdf").write_text("changed")

    assert apply_plan(plan, jail=jail, journal=journal).action == "apply_plan"


def test_a_plan_can_be_applied_twice_only_if_still_fresh(
    jail: PathJail, journal: Journal
) -> None:
    """Second apply finds the sources gone and refuses. Replay protection here is
    a consequence of verification, not a separate mechanism."""
    make(jail, "a.pdf")
    plan = plan_for(jail)

    assert apply_plan(plan, jail=jail, journal=journal).ok is True
    second = apply_plan(plan, jail=jail, journal=journal)

    assert second.ok is False
    assert second.code is ResultCode.INVALID_REQUEST


# --- apply_plan: partial failure is reported honestly -----------------------


def test_a_mid_flight_failure_journals_what_was_done(
    jail: PathJail, journal: Journal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A race after pre-flight. The partial state must stay undoable."""
    make(jail, "a.pdf")
    make(jail, "b.pdf")
    make(jail, "c.pdf")
    plan = plan_for(jail)

    real_rename = Path.rename
    calls = {"n": 0}

    def flaky(self, target):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk gremlins")
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", flaky)

    result = apply_plan(plan, jail=jail, journal=journal)

    assert result.ok is False
    assert result.detail["moved"] == 1
    assert "stopped after 1 of 3" in result.reason
    assert journal.depths() == (1, 0), "the completed move must be undoable"
    assert len(journal.peek_undo().moves) == 1


def test_a_journal_failure_after_moving_is_reported_not_hidden(
    jail: PathJail, tmp_path: Path
) -> None:
    """The files moved. Reporting clean success would hide a lost undo."""
    make(jail, "a.pdf")
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    broken = Journal(blocker / "journal.json")

    result = apply_plan(plan_for(jail), jail=jail, journal=broken)

    assert result.ok is False
    assert "cannot be undone" in result.reason
    assert result.detail["moved"] == 1
    assert (jail.root / "Documents" / "a.pdf").exists(), "the move did happen"


def test_a_journal_failure_does_not_raise(jail: PathJail, tmp_path: Path) -> None:
    """An exception here would report a failure that undid nothing."""
    make(jail, "a.pdf")
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")

    try:
        apply_plan(plan_for(jail), jail=jail, journal=Journal(blocker / "j.json"))
    except JournalError:  # pragma: no cover
        pytest.fail("apply_plan let a JournalError escape")


# --- there is no delete -----------------------------------------------------


def test_the_module_exposes_no_delete() -> None:
    """Not a guarded delete, not a trash-can delete. The capability is absent."""
    import servers.files.apply as apply_module

    names = dir(apply_module)
    for forbidden in ("delete", "remove", "unlink", "trash", "send2trash", "rmtree"):
        assert not any(forbidden in name.lower() for name in names)


def test_applying_a_plan_never_reduces_the_file_count(
    jail: PathJail, journal: Journal
) -> None:
    make(jail, "a.pdf")
    make(jail, "b.png")
    before = sum(1 for p in jail.root.rglob("*") if p.is_file())

    apply_plan(plan_for(jail), jail=jail, journal=journal)

    assert sum(1 for p in jail.root.rglob("*") if p.is_file()) == before
