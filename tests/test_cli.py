"""Tests for servers/cli.py: the unified `safe-mcp <name>` entry point."""

from __future__ import annotations

import pytest

from servers import cli


def test_terminal_subcommand_dispatches_to_the_terminal_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = []
    monkeypatch.setattr(
        cli,
        "SERVERS",
        {
            "terminal": lambda argv: called.append("terminal"),
            "files": lambda argv: called.append("files"),
        },
    )
    monkeypatch.setattr("sys.argv", ["safe-mcp", "terminal"])
    cli.main()
    assert called == ["terminal"]


def test_files_subcommand_dispatches_to_the_files_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = []
    monkeypatch.setattr(
        cli,
        "SERVERS",
        {
            "terminal": lambda argv: called.append("terminal"),
            "files": lambda argv: called.append("files"),
        },
    )
    monkeypatch.setattr("sys.argv", ["safe-mcp", "files"])
    cli.main()
    assert called == ["files"]


def test_args_after_the_subcommand_are_forwarded_to_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received = []
    monkeypatch.setattr(
        cli,
        "SERVERS",
        {"terminal": lambda argv: received.append(argv), "files": lambda argv: None},
    )
    monkeypatch.setattr("sys.argv", ["safe-mcp", "terminal", "--config", "policy.toml"])
    cli.main()
    assert received == [["--config", "policy.toml"]]


def test_missing_subcommand_prints_usage_and_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["safe-mcp"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "usage" in capsys.readouterr().err


def test_unknown_subcommand_prints_usage_and_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["safe-mcp", "bogus"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "usage" in capsys.readouterr().err


def test_both_real_servers_are_registered() -> None:
    """The entry point resolves and both subcommands are reachable."""
    from servers.files.server import main as files_main
    from servers.terminal.server import main as terminal_main

    assert cli.SERVERS == {"terminal": terminal_main, "files": files_main}
