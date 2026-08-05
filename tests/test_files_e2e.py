"""End-to-end: a refused file operation never reaches a rename.

This is the claim the file server rests on, so it is tested against the wired
system rather than against a mock of it. Everything is real — the shipped
policy.toml, the real inspector, the real policy evaluation, the real audit log,
the real journal, the real MCP tool entry points. The single substitution is a
spy in place of ``Path.rename``, and the spy's only behaviour is to fail the test
if it is ever called.

That placement matters. The spy sits at the *last* point before a file moves,
below every layer that might be expected to stop it. If any refusal in the chain
is wrong or bypassable, this is where it shows up.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safety.audit import FAIL_CLOSED
from safety.result import ResultCode
from servers.files import apply as apply_module
from servers.files import server
from servers.files.config import FilesConfig
from servers.files.config import load as load_config

# The file that actually ships, not a fixture written to pass.
SHIPPED_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"


@pytest.fixture
def wired(tmp_path: Path):
    """The real server, configured from the shipped policy file."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    audit_path = tmp_path / "audit.jsonl"
    journal_path = tmp_path / "journal.json"

    shipped = load_config(SHIPPED_POLICY)
    server.configure(
        FilesConfig(
            policy=shipped.policy,
            categories=shipped.categories,
            workspace_root=str(workspace),
            journal=str(journal_path),
            audit_log=str(audit_path),
            audit_fail_mode=FAIL_CLOSED,
            max_plan_moves=shipped.max_plan_moves,
        ),
        workspace,
    )

    class Wired:
        root = workspace
        elsewhere = outside
        audit = audit_path

        @staticmethod
        def make(name: str, content: str = "contents") -> Path:
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            return path

        @staticmethod
        def tree() -> set[str]:
            return {str(p.relative_to(workspace)) for p in workspace.rglob("*")}

        @staticmethod
        def records() -> list[dict]:
            if not audit_path.exists():
                return []
            return [
                json.loads(line)
                for line in audit_path.read_text().splitlines()
                if line.strip()
            ]

    return Wired()


@pytest.fixture
def nothing_may_move(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if anything reaches a rename."""

    def _tripwire(self, target):
        raise AssertionError(
            f"a file reached Path.rename and should not have: {self} -> {target}"
        )

    monkeypatch.setattr(Path, "rename", _tripwire)


def test_the_tripwire_itself_works(wired, nothing_may_move) -> None:
    """Guards the guard: prove the spy fires, so the tests below mean something.

    Without this, a spy wired to the wrong target would make every test here pass
    for the wrong reason. Asserted against ``move_one`` because that is the layer
    the spy guards; the server deliberately converts any escaping exception into
    a result, so it cannot be observed through a tool call.
    """
    wired.make("report.pdf")
    with pytest.raises(AssertionError, match="reached Path.rename"):
        apply_module.move_one(
            "report.pdf", "Documents/report.pdf", jail=server._JAIL
        )


def test_reaching_a_rename_through_a_tool_is_visibly_different(
    wired, nothing_may_move
) -> None:
    """A tripwire hit surfaces as INTERNAL_ERROR, which no refusal test expects.

    So a test below cannot pass for the wrong reason: every one of them asserts a
    specific refusal code, and a move that actually happened cannot produce one.
    """
    wired.make("report.pdf")
    result = server.move_file("report.pdf", "Documents/report.pdf")
    assert result.code is ResultCode.INTERNAL_ERROR


# --- path traversal ---------------------------------------------------------


TRAVERSALS = [
    "../stolen.pdf",
    "../../etc/passwd",
    "../outside/stolen.pdf",
    "sub/../../stolen.pdf",
    "./../../stolen.pdf",
]


@pytest.mark.parametrize("escape", TRAVERSALS)
def test_traversal_as_a_source_never_moves_anything(
    wired, nothing_may_move, escape: str
) -> None:
    result = server.move_file(escape, "Documents/x.pdf")
    assert result.ok is False
    assert result.code is ResultCode.PATH_ESCAPE


@pytest.mark.parametrize("escape", TRAVERSALS)
def test_traversal_as_a_destination_never_moves_anything(
    wired, nothing_may_move, escape: str
) -> None:
    wired.make("report.pdf")
    result = server.move_file("report.pdf", escape)
    assert result.ok is False
    assert result.code is ResultCode.PATH_ESCAPE


@pytest.mark.parametrize("escape", ["..", "../..", "../outside"])
def test_traversal_in_list_files_is_refused(wired, escape: str) -> None:
    assert server.list_files(escape).code is ResultCode.PATH_ESCAPE


# --- absolute paths ---------------------------------------------------------


def test_an_absolute_destination_outside_the_workspace_is_refused(
    wired, nothing_may_move
) -> None:
    wired.make("report.pdf")
    target = wired.elsewhere / "stolen.pdf"

    result = server.move_file("report.pdf", str(target))

    assert result.code is ResultCode.PATH_ESCAPE
    assert not target.exists()


def test_an_absolute_source_outside_the_workspace_is_refused(
    wired, nothing_may_move
) -> None:
    victim = wired.elsewhere / "secret.pdf"
    victim.write_text("secret")

    result = server.move_file(str(victim), "Documents/secret.pdf")

    assert result.code is ResultCode.PATH_ESCAPE
    assert victim.exists()


def test_an_absolute_path_inside_the_workspace_still_works(wired) -> None:
    """Containment, not a blanket ban on absolute paths."""
    wired.make("report.pdf")
    result = server.move_file(
        str(wired.root / "report.pdf"), str(wired.root / "Documents" / "report.pdf")
    )
    assert result.ok is True


# --- symlinks ---------------------------------------------------------------


def test_a_symlinked_directory_pointing_outside_is_refused(
    wired, nothing_may_move
) -> None:
    wired.make("report.pdf")
    (wired.root / "escape").symlink_to(wired.elsewhere, target_is_directory=True)

    result = server.move_file("report.pdf", "escape/stolen.pdf")

    assert result.code is ResultCode.PATH_ESCAPE
    assert not (wired.elsewhere / "stolen.pdf").exists()


def test_a_symlink_file_pointing_outside_is_never_moved(
    wired, nothing_may_move
) -> None:
    victim = wired.elsewhere / "secret.pdf"
    victim.write_text("secret")
    (wired.root / "link.pdf").symlink_to(victim)

    result = server.move_file("link.pdf", "Documents/link.pdf")

    assert result.code is ResultCode.POLICY_DENIED
    assert victim.exists()


def test_planning_never_proposes_moving_a_symlink(wired) -> None:
    victim = wired.elsewhere / "secret.pdf"
    victim.write_text("secret")
    (wired.root / "link.pdf").symlink_to(victim)
    wired.make("real.pdf")

    plan = server.plan_organize().detail

    assert [m["src"] for m in plan["moves"]] == ["real.pdf"]
    assert "link.pdf" in [s["name"] for s in plan["skips"]]


def test_applying_a_plan_leaves_a_symlinks_target_alone(wired) -> None:
    victim = wired.elsewhere / "secret.pdf"
    victim.write_text("secret")
    (wired.root / "link.pdf").symlink_to(victim)
    wired.make("real.pdf")

    server.apply_plan(server.plan_organize().detail["plan_id"])

    assert victim.read_text() == "secret"
    assert (wired.root / "link.pdf").is_symlink()


# --- destination collisions -------------------------------------------------


def test_a_collision_is_refused_and_both_files_survive(wired, nothing_may_move) -> None:
    wired.make("report.pdf", "the new one")
    wired.make("Documents/report.pdf", "the original")

    result = server.move_file("report.pdf", "Documents/report.pdf")

    assert result.code is ResultCode.OPERATION_FAILED
    assert "refusing to overwrite" in result.reason
    assert (wired.root / "Documents" / "report.pdf").read_text() == "the original"
    assert (wired.root / "report.pdf").read_text() == "the new one"


def test_no_numbered_variant_is_ever_invented(wired) -> None:
    """The reference silently wrote report(1).pdf instead of refusing."""
    wired.make("report.pdf", "new")
    wired.make("Documents/report.pdf", "original")

    server.move_file("report.pdf", "Documents/report.pdf")

    assert wired.tree() == {"report.pdf", "Documents", "Documents/report.pdf"}


def test_planning_reports_a_collision_instead_of_proposing_it(wired) -> None:
    wired.make("report.pdf")
    wired.make("Documents/report.pdf", "original")

    plan = server.plan_organize().detail

    assert plan["moves"] == []
    skip = next(s for s in plan["skips"] if s["name"] == "report.pdf")
    assert "already exists" in skip["reason"]


# --- stale plans ------------------------------------------------------------


def test_a_plan_whose_file_changed_moves_nothing_at_all(wired) -> None:
    """The required adversarial case, and the reason plan and apply are split."""
    for name in ("a.pdf", "b.pdf", "c.pdf"):
        wired.make(name)
    plan_id = server.plan_organize().detail["plan_id"]
    before = wired.tree()

    (wired.root / "b.pdf").write_text("changed after the plan was approved")

    result = server.apply_plan(plan_id)

    assert result.ok is False
    assert result.code is ResultCode.INVALID_REQUEST
    assert "stale" in result.reason
    assert wired.tree() == before, "a stale plan moved something"


def test_a_plan_whose_file_vanished_moves_nothing_at_all(wired) -> None:
    for name in ("a.pdf", "b.pdf"):
        wired.make(name)
    plan_id = server.plan_organize().detail["plan_id"]

    (wired.root / "a.pdf").unlink()

    result = server.apply_plan(plan_id)

    assert result.ok is False
    assert (wired.root / "b.pdf").exists(), "b must not have moved"


def test_a_plan_whose_destination_appeared_moves_nothing_at_all(wired) -> None:
    wired.make("a.pdf")
    wired.make("b.pdf")
    plan_id = server.plan_organize().detail["plan_id"]

    wired.make("Documents/a.pdf", "got there first")
    before = wired.tree()

    result = server.apply_plan(plan_id)

    assert result.code is ResultCode.OPERATION_FAILED
    assert wired.tree() == before


def test_an_unknown_plan_id_moves_nothing(wired, nothing_may_move) -> None:
    wired.make("a.pdf")
    result = server.apply_plan("00000000-0000-0000-0000-000000000000")
    assert result.code is ResultCode.INVALID_REQUEST


def test_a_plan_cannot_be_applied_twice(wired) -> None:
    wired.make("a.pdf")
    plan_id = server.plan_organize().detail["plan_id"]

    assert server.apply_plan(plan_id).ok is True
    assert server.apply_plan(plan_id).code is ResultCode.INVALID_REQUEST


# --- the shipped policy's own refusals --------------------------------------


SHIPPED_REFUSALS = [
    ("setup.exe", "installers"),
    ("installer.msi", "installers"),
    ("script.bat", "installers"),
    ("shortcut.lnk", "installers"),
    (".bashrc", "dotfiles"),
    ("desktop.ini", "os metadata"),
    ("thumbs.db", "os metadata"),
    ("Makefile", "project files"),
]


@pytest.mark.parametrize(
    ("name", "why"), SHIPPED_REFUSALS, ids=[f"{n}: {w}" for n, w in SHIPPED_REFUSALS]
)
def test_the_shipped_policy_never_moves_these(
    wired, nothing_may_move, name: str, why: str
) -> None:
    wired.make(name)
    result = server.move_file(name, f"Documents/{name}")
    assert result.ok is False, f"{name} was moved ({why})"
    assert result.code is ResultCode.POLICY_DENIED


def test_the_shipped_policy_still_organizes_ordinary_files(wired) -> None:
    """The other half of the claim: this is a guard, not a wall."""
    wired.make("report.pdf")
    wired.make("photo.png")
    wired.make("song.mp3")

    server.apply_plan(server.plan_organize().detail["plan_id"])

    assert (wired.root / "Documents" / "report.pdf").exists()
    assert (wired.root / "Images" / "photo.png").exists()
    assert (wired.root / "Audio" / "song.mp3").exists()


# --- there is no delete -----------------------------------------------------


def test_the_server_exposes_exactly_six_tools_and_none_of_them_delete() -> None:
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


def test_no_sequence_of_tools_reduces_the_file_count(wired) -> None:
    """Whatever the organizer does, every file is still somewhere afterwards."""
    for name in ("a.pdf", "b.png", "c.mp3", "setup.exe", ".hidden"):
        wired.make(name)
    before = sum(1 for p in wired.root.rglob("*") if p.is_file())

    server.apply_plan(server.plan_organize().detail["plan_id"])
    server.undo_last_action()
    server.redo_last_action()

    assert sum(1 for p in wired.root.rglob("*") if p.is_file()) == before


# --- everything is recorded -------------------------------------------------


def test_every_refusal_is_recorded(wired, nothing_may_move) -> None:
    """A refusal that leaves no trace is a refusal nobody can review."""
    wired.make("report.pdf")
    refusals = [
        ("../stolen.pdf", "Documents/x.pdf"),
        ("report.pdf", "../stolen.pdf"),
        ("absent.pdf", "Documents/absent.pdf"),
    ]
    for src, dest in refusals:
        server.move_file(src, dest)

    records = wired.records()
    assert len(records) == len(refusals)
    # No attempt records: an attempt means something was about to move.
    assert all(r["record_type"] == "outcome" for r in records)
    assert all(r["server"] == "files" for r in records)
    assert all(r["reason"] for r in records), "a refusal must say why"


def test_a_refused_operation_reports_no_moves(wired, nothing_may_move) -> None:
    wired.make("report.pdf")
    result = server.move_file("report.pdf", "../stolen.pdf")
    assert not result.detail.get("moved")


def test_the_audit_trail_leaks_no_absolute_paths(wired, tmp_path: Path) -> None:
    wired.make("report.pdf")
    server.move_file("report.pdf", "Documents/report.pdf")
    server.undo_last_action()
    server.list_files()

    assert str(tmp_path) not in wired.audit.read_text()
