"""policy.example.toml must start both servers with no editing.

policy.toml (the template) is deliberately inert — jail_root and
workspace_root are commented out, and startup refuses until an operator sets
them. policy.example.toml is the other half of that: it ships with real
values, and this is the test that keeps it that way. If either server ever
needs an edit to policy.example.toml before it starts, that regression must
fail here, not reach a reader running the Quickstart.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from servers.files import server as files_server
from servers.files.config import load as load_files_config
from servers.terminal import server as terminal_server
from servers.terminal.config import load as load_terminal_config

EXAMPLE_POLICY = Path(__file__).resolve().parent.parent / "policy.example.toml"


def test_example_policy_ships_with_real_roots_set() -> None:
    """The one thing the template refuses to have: this file must have it."""
    terminal_cfg = load_terminal_config(EXAMPLE_POLICY)
    files_cfg = load_files_config(EXAMPLE_POLICY)
    assert terminal_cfg.jail_root
    assert files_cfg.workspace_root


@pytest.fixture
def quickstart_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The Quickstart, reproduced: the example policy plus its mkdir -p."""
    shutil.copy(EXAMPLE_POLICY, tmp_path / "policy.example.toml")
    (tmp_path / "sandbox" / "terminal").mkdir(parents=True)
    (tmp_path / "sandbox" / "files").mkdir(parents=True)
    (tmp_path / "state").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_terminal_server_starts_with_the_example_policy(
    quickstart_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached_run = []
    monkeypatch.setattr(terminal_server.mcp, "run", lambda: reached_run.append(True))
    terminal_server.main(["--config", "policy.example.toml"])
    assert reached_run == [True]


def test_files_server_starts_with_the_example_policy(
    quickstart_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached_run = []
    monkeypatch.setattr(files_server.mcp, "run", lambda: reached_run.append(True))
    files_server.main(["--config", "policy.example.toml"])
    assert reached_run == [True]
