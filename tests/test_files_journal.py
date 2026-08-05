"""Tests for servers/files/journal.py.

The journal holds no filesystem logic, so these tests are about state machine
behaviour and about failing loudly. The case that matters most is corruption: the
reference organizer caught every exception and returned an empty history, which
silently threw away the user's undo stack at the exact moment they needed it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from servers.files.journal import Journal, JournalEntry, JournalError, JournalMove


def entry(action: str = "move_file", *pairs: tuple[str, str]) -> JournalEntry:
    moves = pairs or (("a.pdf", "Documents/a.pdf"),)
    return JournalEntry(
        action=action, moves=tuple(JournalMove(src=s, dest=d) for s, d in moves)
    )


@pytest.fixture
def journal(tmp_path: Path) -> Journal:
    return Journal(tmp_path / "journal.json")


# --- empty state ------------------------------------------------------------


def test_a_missing_file_reads_as_empty(journal: Journal) -> None:
    assert journal.peek_undo() is None
    assert journal.peek_redo() is None
    assert journal.depths() == (0, 0)


def test_committing_on_an_empty_stack_returns_none(journal: Journal) -> None:
    assert journal.commit_undo() is None
    assert journal.commit_redo() is None


def test_nothing_is_written_just_by_reading(journal: Journal) -> None:
    journal.peek_undo()
    assert not journal.path.exists()


# --- record / undo / redo ---------------------------------------------------


def test_record_then_peek(journal: Journal) -> None:
    journal.record(entry("move_file"))
    peeked = journal.peek_undo()
    assert peeked is not None
    assert peeked.action == "move_file"
    assert journal.depths() == (1, 0)


def test_peek_does_not_pop(journal: Journal) -> None:
    journal.record(entry())
    journal.peek_undo()
    journal.peek_undo()
    assert journal.depths() == (1, 0)


def test_undo_moves_an_entry_to_the_redo_stack(journal: Journal) -> None:
    journal.record(entry())
    assert journal.commit_undo() is not None
    assert journal.depths() == (0, 1)
    assert journal.peek_undo() is None
    assert journal.peek_redo() is not None


def test_redo_moves_it_back(journal: Journal) -> None:
    journal.record(entry())
    journal.commit_undo()
    assert journal.commit_redo() is not None
    assert journal.depths() == (1, 0)


def test_the_stack_is_last_in_first_out(journal: Journal) -> None:
    journal.record(entry("first"))
    journal.record(entry("second"))
    assert journal.peek_undo().action == "second"
    journal.commit_undo()
    assert journal.peek_undo().action == "first"


def test_new_work_clears_the_redo_stack(journal: Journal) -> None:
    """Otherwise a redo could reapply a move into a tree that has since changed."""
    journal.record(entry("first"))
    journal.commit_undo()
    assert journal.depths() == (0, 1)

    journal.record(entry("second"))

    assert journal.depths() == (1, 0)
    assert journal.peek_redo() is None


def test_a_full_undo_redo_cycle_returns_to_the_start(journal: Journal) -> None:
    journal.record(entry("a"))
    journal.record(entry("b"))
    journal.commit_undo()
    journal.commit_undo()
    assert journal.depths() == (0, 2)
    journal.commit_redo()
    journal.commit_redo()
    assert journal.depths() == (2, 0)
    assert journal.peek_undo().action == "b"


# --- entries hold whole actions ---------------------------------------------


def test_one_entry_can_hold_many_moves(journal: Journal) -> None:
    """An apply_plan of forty files is one undoable action, not forty."""
    journal.record(entry("apply_plan", ("a", "A/a"), ("b", "B/b"), ("c", "C/c")))
    assert journal.depths() == (1, 0)
    assert len(journal.peek_undo().moves) == 3


def test_reversed_moves_flips_each_pair(journal: Journal) -> None:
    e = entry("apply_plan", ("a", "A/a"), ("b", "B/b"))
    assert e.reversed_moves() == (
        JournalMove(src="B/b", dest="b"),
        JournalMove(src="A/a", dest="a"),
    )


def test_reversed_moves_unwinds_last_in_first_out(journal: Journal) -> None:
    e = entry("apply_plan", ("1", "2"), ("2", "3"))
    assert [m.src for m in e.reversed_moves()] == ["3", "2"]


def test_an_entry_gets_a_timestamp(journal: Journal) -> None:
    assert entry().ts


def test_an_explicit_timestamp_is_kept() -> None:
    e = JournalEntry(action="x", moves=(), ts="2020-01-01T00:00:00+00:00")
    assert e.ts == "2020-01-01T00:00:00+00:00"


# --- persistence ------------------------------------------------------------


def test_state_survives_a_new_journal_object(tmp_path: Path) -> None:
    path = tmp_path / "journal.json"
    Journal(path).record(entry("move_file", ("x.pdf", "Documents/x.pdf")))

    reopened = Journal(path)
    peeked = reopened.peek_undo()
    assert peeked is not None
    assert peeked.moves[0].src == "x.pdf"
    assert peeked.moves[0].dest == "Documents/x.pdf"


def test_the_file_is_valid_json_with_both_stacks(journal: Journal) -> None:
    journal.record(entry())
    data = json.loads(journal.path.read_text())
    assert set(data) == {"done", "undone"}
    assert data["done"][0]["action"] == "move_file"


def test_a_parent_directory_is_created(tmp_path: Path) -> None:
    j = Journal(tmp_path / "state" / "nested" / "journal.json")
    j.record(entry())
    assert j.path.exists()


def test_no_temp_files_are_left_behind(journal: Journal) -> None:
    journal.record(entry())
    journal.commit_undo()
    leftovers = [p.name for p in journal.path.parent.iterdir() if ".tmp" in p.name]
    assert leftovers == []


def test_unicode_names_round_trip(journal: Journal) -> None:
    journal.record(entry("move_file", ("résumé-🎉.pdf", "Documents/résumé-🎉.pdf")))
    assert Journal(journal.path).peek_undo().moves[0].src == "résumé-🎉.pdf"


# --- corruption fails loudly ------------------------------------------------


def test_invalid_json_raises(journal: Journal) -> None:
    journal.path.write_text("{not json")
    with pytest.raises(JournalError, match="not valid JSON"):
        journal.peek_undo()


def test_a_json_array_instead_of_an_object_raises(journal: Journal) -> None:
    journal.path.write_text("[]")
    with pytest.raises(JournalError, match="not a JSON object"):
        journal.peek_undo()


def test_a_non_array_stack_raises(journal: Journal) -> None:
    journal.path.write_text(json.dumps({"done": "nope", "undone": []}))
    with pytest.raises(JournalError, match="stacks must be arrays"):
        journal.peek_undo()


def test_an_entry_without_an_action_raises(journal: Journal) -> None:
    journal.path.write_text(json.dumps({"done": [{"moves": []}], "undone": []}))
    with pytest.raises(JournalError, match="missing an action"):
        journal.peek_undo()


def test_an_entry_without_moves_raises(journal: Journal) -> None:
    journal.path.write_text(json.dumps({"done": [{"action": "x"}], "undone": []}))
    with pytest.raises(JournalError, match="missing its moves"):
        journal.peek_undo()


def test_a_move_missing_dest_raises(journal: Journal) -> None:
    journal.path.write_text(
        json.dumps({"done": [{"action": "x", "moves": [{"src": "a"}]}], "undone": []})
    )
    with pytest.raises(JournalError, match="missing src or dest"):
        journal.peek_undo()


def test_corruption_is_not_silently_treated_as_empty(journal: Journal) -> None:
    """The reference returned [] here, discarding the user's undo stack."""
    journal.record(entry())
    journal.path.write_text("garbage")
    with pytest.raises(JournalError):
        journal.peek_undo()
    with pytest.raises(JournalError):
        journal.record(entry())


def test_an_unwritable_path_raises_rather_than_failing_quietly(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    with pytest.raises(JournalError, match="could not write journal"):
        Journal(blocker / "journal.json").record(entry())
