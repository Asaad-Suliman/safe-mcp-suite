"""Tests for servers/files/server.py.

These drive the tool functions directly rather than through an MCP client. The
transport is the SDK's business; what is worth testing here is the order the
server puts things in, what it writes down, and that a refusal is data rather
than an exception.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safety.audit import FAIL_CLOSED, AuditLogger
from safety.result import ResultCode
from servers.files import server
from servers.files.config import FilesConfig
from servers.files.config import load as load_config
from servers.files.journal import Journal

POLICY = """
[files]
workspace_root = "/replaced-by-fixture"
max_plan_moves = 100

[files.categories]
Documents = [".pdf", ".md"]
Images = [".png"]

[[files.skip]]
layer = "restraint"
when = ["hidden"]
reason = "dotfiles are configuration"

[[files.skip]]
layer = "restraint"
any_ext = [".exe"]
reason = "installers are left alone"

[[files.skip]]
layer = "protection"
when = ["unsafe-name"]
reason = "the name carries control characters"
"""


@pytest.fixture
def env(tmp_path: Path):
    """A configured server: a workspace, an audit log and a journal outside it."""
    root = tmp_path / "workspace"
    root.mkdir()
    audit_path = tmp_path / "audit.jsonl"
    journal_path = tmp_path / "journal.json"
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(POLICY)

    loaded = load_config(policy_path)
    cfg = FilesConfig(
        policy=loaded.policy,
        categories=loaded.categories,
        workspace_root=str(root),
        journal=str(journal_path),
        audit_log=str(audit_path),
        audit_fail_mode=FAIL_CLOSED,
        max_plan_moves=loaded.max_plan_moves,
    )
    server.configure(cfg, root)

    class Env:
        workspace = root
        audit = audit_path
        journal = Journal(journal_path)

        @staticmethod
        def make(name: str, content: str = "contents") -> Path:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            return path

        @staticmethod
        def tree() -> set[str]:
            return {str(p.relative_to(root)) for p in root.rglob("*")}

        @staticmethod
        def records() -> list[dict]:
            if not audit_path.exists():
                return []
            return [
                json.loads(line)
                for line in audit_path.read_text().splitlines()
                if line.strip()
            ]

    return Env()


# --- the tool surface -------------------------------------------------------


def test_exactly_six_tools_are_registered() -> None:
    import asyncio

    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert names == {
        "list_files",
        "plan_organize",
        "apply_plan",
        "move_file",
        "undo_last_action",
        "redo_last_action",
    }


def test_there_is_no_delete_tool() -> None:
    """Stated separately from the count so the intent survives a refactor."""
    import asyncio

    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    for forbidden in ("delete", "remove", "trash", "unlink", "purge", "clean"):
        assert not any(forbidden in name for name in names)


def test_a_refusal_crosses_the_boundary_as_data_not_an_error(env) -> None:
    import asyncio

    result = asyncio.run(
        server.mcp.call_tool("move_file", {"src": "../escape.pdf", "dest": "x.pdf"})
    )
    assert result.is_error is False
    assert result.structured_content["code"] == "PATH_ESCAPE"
    assert result.structured_content["ok"] is False


def test_calling_before_configure_does_not_leak_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "_CONFIG", None)
    result = server.plan_organize()
    assert result.code is ResultCode.INTERNAL_ERROR
    assert result.reason == "internal error"


# --- list_files -------------------------------------------------------------


def test_list_files_lists_the_workspace(env) -> None:
    env.make("a.pdf")
    env.make("b.png")

    result = server.list_files()

    assert result.ok is True
    assert result.detail["count"] == 2
    assert [e["name"] for e in result.detail["entries"]] == ["a.pdf", "b.png"]


def test_list_files_says_why_something_would_be_skipped(env) -> None:
    env.make(".hidden")
    entry = server.list_files().detail["entries"][0]
    assert entry["organizable"] is False
    assert entry["reason"] == "dotfiles are configuration"


def test_list_files_marks_ordinary_files_organizable(env) -> None:
    env.make("a.pdf")
    entry = server.list_files().detail["entries"][0]
    assert entry["organizable"] is True
    assert entry["category"] == "Documents"


def test_list_files_can_list_a_subdirectory(env) -> None:
    env.make("Documents/a.pdf")
    result = server.list_files("Documents")
    assert [e["name"] for e in result.detail["entries"]] == ["a.pdf"]


@pytest.mark.parametrize("escape", ["..", "../..", "../outside"])
def test_list_files_refuses_to_escape(env, escape: str) -> None:
    result = server.list_files(escape)
    assert result.code is ResultCode.PATH_ESCAPE


def test_list_files_refuses_an_absolute_path_outside(env, tmp_path: Path) -> None:
    assert server.list_files(str(tmp_path)).code is ResultCode.PATH_ESCAPE


def test_list_files_on_a_file_is_an_error(env) -> None:
    env.make("a.pdf")
    assert server.list_files("a.pdf").code is ResultCode.OPERATION_FAILED


def test_list_files_writes_nothing(env) -> None:
    env.make("a.pdf")
    before = env.tree()
    server.list_files()
    assert env.tree() == before


# --- plan_organize ----------------------------------------------------------


def test_plan_organize_proposes_without_moving(env) -> None:
    env.make("a.pdf")
    before = env.tree()

    result = server.plan_organize()

    assert result.ok is True
    assert result.detail["move_count"] == 1
    assert env.tree() == before
    assert not (env.workspace / "Documents").exists()


def test_plan_organize_reports_skips_with_reasons(env) -> None:
    env.make("setup.exe")
    skips = server.plan_organize().detail["skips"]
    assert skips[0]["name"] == "setup.exe"
    assert skips[0]["reason"] == "installers are left alone"


def test_plan_organize_returns_relative_paths_only(env, tmp_path: Path) -> None:
    env.make("a.pdf")
    assert str(tmp_path) not in json.dumps(server.plan_organize().detail)


def test_each_plan_gets_a_distinct_id(env) -> None:
    env.make("a.pdf")
    assert (
        server.plan_organize().detail["plan_id"]
        != server.plan_organize().detail["plan_id"]
    )


# --- apply_plan -------------------------------------------------------------


def test_apply_plan_carries_out_the_plan(env) -> None:
    env.make("a.pdf")
    plan_id = server.plan_organize().detail["plan_id"]

    result = server.apply_plan(plan_id)

    assert result.ok is True
    assert (env.workspace / "Documents" / "a.pdf").exists()


def test_apply_plan_rejects_an_unknown_id(env) -> None:
    result = server.apply_plan("not-a-real-plan")
    assert result.ok is False
    assert result.code is ResultCode.INVALID_REQUEST


def test_a_plan_is_single_use(env) -> None:
    """An approval must not be replayable."""
    env.make("a.pdf")
    plan_id = server.plan_organize().detail["plan_id"]

    assert server.apply_plan(plan_id).ok is True
    second = server.apply_plan(plan_id)

    assert second.ok is False
    assert second.code is ResultCode.INVALID_REQUEST


def test_apply_plan_refuses_a_stale_plan_entirely(env) -> None:
    env.make("a.pdf")
    env.make("b.pdf")
    plan_id = server.plan_organize().detail["plan_id"]
    before = env.tree()

    (env.workspace / "a.pdf").write_text("changed since planning")

    result = server.apply_plan(plan_id)

    assert result.ok is False
    assert result.code is ResultCode.INVALID_REQUEST
    assert env.tree() == before


def test_apply_plan_cannot_be_called_without_a_plan_id(env) -> None:
    """There is no argument that conjures a plan out of nothing."""
    with pytest.raises(TypeError):
        server.apply_plan()  # type: ignore[call-arg]


def test_old_plans_are_eventually_dropped(env) -> None:
    env.make("a.pdf")
    first = server.plan_organize().detail["plan_id"]
    for _ in range(server._MAX_PENDING_PLANS + 1):
        server.plan_organize()

    assert server.apply_plan(first).code is ResultCode.INVALID_REQUEST


# --- move_file --------------------------------------------------------------


def test_move_file_moves_a_file(env) -> None:
    env.make("a.pdf")
    result = server.move_file("a.pdf", "Documents/a.pdf")

    assert result.ok is True
    assert (env.workspace / "Documents" / "a.pdf").exists()


def test_move_file_refuses_an_existing_destination(env) -> None:
    env.make("a.pdf", "new")
    env.make("Documents/a.pdf", "original")

    result = server.move_file("a.pdf", "Documents/a.pdf")

    assert result.code is ResultCode.OPERATION_FAILED
    assert (env.workspace / "Documents" / "a.pdf").read_text() == "original"


# --- what a restraint rule does and does not stop ----------------------------


def test_the_organizer_skips_an_installer_but_move_file_moves_it(env) -> None:
    """The whole distinction, in one test.

    Same file, same policy, two tools. The organizer is guessing where an
    installer belongs and declines to. A request naming it is not guessing, so
    there is nothing left for the rule to protect anyone from.
    """
    env.make("setup.exe")

    plan = server.plan_organize()
    skip = next(s for s in plan.detail["skips"] if s["name"] == "setup.exe")
    assert skip["code"] == "NEEDS_EXPLICIT_REQUEST"

    result = server.move_file("setup.exe", "Documents/setup.exe")

    assert result.ok is True
    assert (env.workspace / "Documents" / "setup.exe").exists()
    assert not (env.workspace / "setup.exe").exists()


def test_move_file_moves_a_hidden_file(env) -> None:
    env.make(".bashrc")
    result = server.move_file(".bashrc", "Documents/.bashrc")
    assert result.ok is True
    assert (env.workspace / "Documents" / ".bashrc").exists()


def test_move_file_can_move_a_directory(env) -> None:
    """One rename. The contents come along and are not re-filed."""
    (env.workspace / "somedir").mkdir()
    (env.workspace / "somedir" / "inner.pdf").write_text("inner")

    result = server.move_file("somedir", "Archive/somedir")

    assert result.ok is True
    assert (env.workspace / "Archive" / "somedir" / "inner.pdf").read_text() == "inner"
    assert not (env.workspace / "somedir").exists()


def test_move_file_can_move_an_application_folder(env) -> None:
    (env.workspace / "Editor.app").mkdir()
    (env.workspace / "Editor.app" / "run").write_text("#!/bin/sh")

    result = server.move_file("Editor.app", "Applications/Editor.app")

    assert result.ok is True
    assert (env.workspace / "Applications" / "Editor.app" / "run").exists()


def test_a_restraint_that_was_passed_over_is_written_down(env) -> None:
    """A reviewer should be able to find this in the trail, not infer it."""
    env.make("setup.exe")
    server.move_file("setup.exe", "Documents/setup.exe")

    attempt = next(r for r in env.records() if r["record_type"] == "attempt")
    assert "over a restraint rule" in attempt["reason"]
    assert "installers are left alone" in attempt["reason"]


def test_a_directory_move_still_refuses_an_occupied_destination(env) -> None:
    """A directory gets every protection check a file gets. Nothing is merged."""
    (env.workspace / "somedir").mkdir()
    (env.workspace / "somedir" / "a.pdf").write_text("mine")
    (env.workspace / "Archive" / "somedir").mkdir(parents=True)
    (env.workspace / "Archive" / "somedir" / "b.pdf").write_text("theirs")

    result = server.move_file("somedir", "Archive/somedir")

    assert result.code is ResultCode.OPERATION_FAILED
    assert (env.workspace / "somedir" / "a.pdf").exists()
    assert (env.workspace / "Archive" / "somedir" / "b.pdf").read_text() == "theirs"


def test_move_file_refuses_a_name_carrying_control_characters(env) -> None:
    """Protection, not restraint. No way of asking makes this one permitted."""
    env.make("bad\x07name.pdf")
    result = server.move_file("bad\x07name.pdf", "Documents/bad\x07name.pdf")

    assert result.code is ResultCode.POLICY_DENIED
    assert (env.workspace / "bad\x07name.pdf").exists()


def test_move_file_cannot_move_a_symlink(env, tmp_path: Path) -> None:
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (env.workspace / "link.pdf").symlink_to(outside)

    result = server.move_file("link.pdf", "Documents/link.pdf")

    assert result.code is ResultCode.POLICY_DENIED
    assert outside.exists()


@pytest.mark.parametrize("escape", ["../out.pdf", "../../etc/passwd"])
def test_move_file_refuses_an_escaping_source(env, escape: str) -> None:
    assert server.move_file(escape, "Documents/x.pdf").code is ResultCode.PATH_ESCAPE


@pytest.mark.parametrize("escape", ["../out.pdf", "../../tmp/stolen.pdf"])
def test_move_file_refuses_an_escaping_destination(env, escape: str) -> None:
    env.make("a.pdf")
    result = server.move_file("a.pdf", escape)
    assert result.code is ResultCode.PATH_ESCAPE
    assert (env.workspace / "a.pdf").exists()


def test_move_file_reports_a_missing_source(env) -> None:
    result = server.move_file("absent.pdf", "Documents/absent.pdf")
    assert result.code is ResultCode.OPERATION_FAILED


# --- undo / redo ------------------------------------------------------------


def test_undo_reverses_a_move(env) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")

    result = server.undo_last_action()

    assert result.ok is True
    assert (env.workspace / "a.pdf").exists()
    assert not (env.workspace / "Documents" / "a.pdf").exists()


def test_undo_reverses_a_whole_plan_in_one_call(env) -> None:
    env.make("a.pdf")
    env.make("b.png")
    server.apply_plan(server.plan_organize().detail["plan_id"])

    result = server.undo_last_action()

    assert result.detail["moved"] == 2
    assert (env.workspace / "a.pdf").exists()
    assert (env.workspace / "b.png").exists()


def test_redo_reapplies(env) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    server.undo_last_action()

    result = server.redo_last_action()

    assert result.ok is True
    assert (env.workspace / "Documents" / "a.pdf").exists()


def test_undo_with_nothing_to_undo(env) -> None:
    result = server.undo_last_action()
    assert result.ok is False
    assert "nothing to undo" in result.reason


def test_redo_with_nothing_to_redo(env) -> None:
    result = server.redo_last_action()
    assert result.ok is False
    assert "nothing to redo" in result.reason


def test_new_work_clears_the_redo_stack(env) -> None:
    env.make("a.pdf")
    env.make("b.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    server.undo_last_action()

    server.move_file("b.pdf", "Documents/b.pdf")

    assert server.redo_last_action().ok is False


def test_undo_refuses_when_the_destination_is_occupied(env) -> None:
    """A file put back by hand must not be overwritten by an undo."""
    env.make("a.pdf", "original")
    server.move_file("a.pdf", "Documents/a.pdf")
    env.make("a.pdf", "a different file with the same name")

    result = server.undo_last_action()

    assert result.ok is False
    assert "already exists" in result.reason
    assert (env.workspace / "a.pdf").read_text() == "a different file with the same name"
    assert (env.workspace / "Documents" / "a.pdf").exists(), "nothing moved"


def test_a_refused_undo_leaves_the_journal_alone(env) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    env.make("a.pdf", "blocker")

    server.undo_last_action()

    assert env.journal.depths() == (1, 0), "the entry must still be undoable later"


def test_undo_refuses_when_the_moved_file_has_vanished(env) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    (env.workspace / "Documents" / "a.pdf").unlink()

    result = server.undo_last_action()

    assert result.ok is False
    assert "no longer there" in result.reason


def test_undo_then_redo_returns_to_the_moved_state(env) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    server.undo_last_action()
    server.redo_last_action()
    assert (env.workspace / "Documents" / "a.pdf").exists()


# --- auditing ---------------------------------------------------------------


def test_every_tool_writes_an_outcome_record(env) -> None:
    env.make("a.pdf")
    server.list_files()
    server.plan_organize()
    server.move_file("a.pdf", "Documents/a.pdf")
    server.undo_last_action()
    server.redo_last_action()

    outcomes = [r for r in env.records() if r["record_type"] == "outcome"]
    assert {r["action"] for r in outcomes} == {
        "list_files",
        "plan_organize",
        "move_file",
        "undo_last_action",
        "redo_last_action",
    }
    assert all(r["server"] == "files" for r in env.records())


def test_undo_and_redo_are_audited_as_well_as_journalled(env) -> None:
    """Decision 5: the journal tracks position, the audit log records the event."""
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    server.undo_last_action()
    server.redo_last_action()

    actions = [r["action"] for r in env.records()]
    assert "undo_last_action" in actions
    assert "redo_last_action" in actions


def test_a_mutating_tool_writes_attempt_before_outcome(env) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")

    kinds = [r["record_type"] for r in env.records()]
    assert kinds == ["attempt", "outcome"]


def test_a_read_only_tool_writes_no_attempt(env) -> None:
    """An attempt record means something was about to change."""
    server.list_files()
    assert [r["record_type"] for r in env.records()] == ["outcome"]


def test_plan_organize_writes_no_attempt(env) -> None:
    env.make("a.pdf")
    server.plan_organize()
    assert [r["record_type"] for r in env.records()] == ["outcome"]


def test_a_refusal_is_recorded(env) -> None:
    server.move_file("../escape.pdf", "x.pdf")
    records = env.records()
    assert len(records) == 1
    assert records[0]["code"] == "PATH_ESCAPE"


def test_a_policy_denial_records_the_decision(env) -> None:
    # A named protection rule rather than a symlink, which is refused by
    # deny-by-default and so has no rule to record.
    env.make("bad\x07name.pdf")
    server.move_file("bad\x07name.pdf", "Documents/bad\x07name.pdf")

    denial = next(r for r in env.records() if r["code"] == "POLICY_DENIED")
    assert denial["decision"] == "deny"
    assert denial["rule"] == "organize"


def test_a_denied_move_writes_no_attempt_record(env) -> None:
    """Nothing was about to happen, so nothing should claim it was."""
    (env.workspace / "link.pdf").symlink_to(env.workspace / "wherever.pdf")
    server.move_file("link.pdf", "Documents/link.pdf")
    assert all(r["record_type"] == "outcome" for r in env.records())


def test_the_audit_log_holds_no_absolute_paths(env, tmp_path: Path) -> None:
    env.make("a.pdf")
    server.move_file("a.pdf", "Documents/a.pdf")
    assert str(tmp_path) not in env.audit.read_text()


def test_nothing_moves_when_the_audit_log_cannot_be_written(env, tmp_path: Path) -> None:
    """Fail-closed: an unlogged move is worse than a refused one."""
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    env.make("a.pdf")
    server.configure(
        server._CONFIG,
        env.workspace,
        audit_logger=AuditLogger(blocker / "audit.jsonl", fail_mode=FAIL_CLOSED),
        journal=env.journal,
    )

    result = server.move_file("a.pdf", "Documents/a.pdf")

    assert result.code is ResultCode.AUDIT_UNAVAILABLE
    assert (env.workspace / "a.pdf").exists(), "the file must not have moved"
