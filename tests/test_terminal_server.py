"""Tests for servers/terminal/server.py.

These drive the tool functions directly rather than through an MCP client. The
transport is the SDK's business; what is worth testing here is the order the
server puts things in and what it writes down.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from safety.audit import FAIL_CLOSED, FAIL_OPEN, AuditLogger
from safety.result import ResultCode
from servers.terminal import config as config_module
from servers.terminal import server
from servers.terminal.config import TerminalConfig, load

POLICY = """
[terminal.allowlist]
commands = ["echo", "git", "pwd", "ls"]

[terminal.denylist]
commands = ["rm", "curl"]

[[terminal.rules]]
command = "git"
deny_args = ["push --force"]
reason = "force-push rewrites shared history"
"""


@pytest.fixture
def env(tmp_path: Path):
    """A configured server: a jail, an audit log outside it, a small policy."""
    jail_root = tmp_path / "jail"
    jail_root.mkdir()
    audit_path = tmp_path / "audit.jsonl"
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(POLICY)

    cfg = load(policy_path)
    cfg = TerminalConfig(
        policy=cfg.policy,
        jail_root=str(jail_root),
        audit_log=str(audit_path),
        audit_fail_mode=FAIL_CLOSED,
        timeout=5.0,
        max_output_bytes=cfg.max_output_bytes,
    )
    server.configure(cfg, jail_root)

    class Env:
        root = jail_root
        audit = audit_path
        config = cfg

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


# --- run_command: the allowed path ----------------------------------------


def test_allowed_command_runs(env) -> None:
    result = server.run_command("echo hello")
    assert result.ok is True
    assert result.code is ResultCode.OK
    assert result.detail["stdout"].strip() == "hello"
    assert result.detail["exit_code"] == 0


def test_the_envelope_names_the_tool(env) -> None:
    assert server.run_command("echo hi").action == "run_command"
    assert server.explain_command("echo hi").action == "explain_command"


def test_a_command_runs_in_a_subdirectory_of_the_jail(env) -> None:
    (env.root / "work").mkdir()
    result = server.run_command("pwd", cwd="work")
    assert Path(result.detail["stdout"].strip()).resolve() == env.root / "work"


# --- run_command: refusals -------------------------------------------------


def test_denylisted_command_is_denied(env) -> None:
    result = server.run_command("rm -rf /")
    assert result.ok is False
    assert result.code is ResultCode.POLICY_DENIED
    assert result.detail == {}


def test_unlisted_command_is_denied_by_default(env) -> None:
    result = server.run_command("python evil.py")
    assert result.code is ResultCode.POLICY_DENIED
    assert "deny by default" in result.reason


def test_denied_argument_pattern_is_denied(env) -> None:
    result = server.run_command("git push --force")
    assert result.code is ResultCode.POLICY_DENIED
    assert result.reason == "force-push rewrites shared history"


def test_metacharacter_is_an_invalid_request(env) -> None:
    result = server.run_command("echo hi; rm -rf /")
    assert result.code is ResultCode.INVALID_REQUEST


def test_empty_command_is_an_invalid_request(env) -> None:
    assert server.run_command("   ").code is ResultCode.INVALID_REQUEST


def test_cwd_escape_is_refused(env) -> None:
    result = server.run_command("echo hi", cwd="../..")
    assert result.ok is False
    assert result.code is ResultCode.PATH_ESCAPE


def test_no_exception_reaches_the_caller(env) -> None:
    """Every refusal is data. Nothing raises out of a tool."""
    for command in ["rm -rf /", "echo a; b", "", "'", "nonexistent-binary-xyz"]:
        assert server.run_command(command).ok in (True, False)


# --- explain_command -------------------------------------------------------


def test_explain_reports_an_allowed_command_without_running_it(env) -> None:
    result = server.explain_command("echo hello")
    assert result.ok is True
    assert result.detail["would_execute"] is True
    assert "stdout" not in result.detail
    assert "exit_code" not in result.detail


def test_explain_reports_a_denial_with_its_reason(env) -> None:
    result = server.explain_command("git push --force")
    assert result.ok is False
    assert result.code is ResultCode.POLICY_DENIED
    assert result.reason == "force-push rewrites shared history"


def test_explain_never_spawns_a_process(
    env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*_args, **_kwargs):
        raise AssertionError("explain_command spawned a subprocess")

    monkeypatch.setattr(server.execute.subprocess, "run", _boom)
    for command in ["echo hi", "git status", "rm -rf /", "echo a; b"]:
        server.explain_command(command)


def test_explain_agrees_with_run(env) -> None:
    """The dry run must not drift from the real thing — same parse, same policy."""
    for command in ["echo hi", "rm -rf /", "git push --force", "python x.py"]:
        explained = server.explain_command(command)
        ran = server.run_command(command)
        assert explained.ok == ran.ok
        if not explained.ok:
            assert explained.code is ran.code


# --- auditing --------------------------------------------------------------


def test_every_outcome_is_audited(env) -> None:
    for command in ["echo hi", "rm -rf /", "echo a; b", "python x.py"]:
        server.run_command(command)
    actions = [r["code"] for r in env.records() if r["record_type"] == "outcome"]
    assert len(actions) == 4


def test_an_execution_writes_an_attempt_then_an_outcome(env) -> None:
    server.run_command("echo hi")
    records = env.records()
    assert [r["record_type"] for r in records] == ["attempt", "outcome"]
    assert records[0]["event_id"] == records[1]["event_id"]


def test_a_denial_writes_one_record_and_no_attempt(env) -> None:
    server.run_command("rm -rf /")
    records = env.records()
    assert len(records) == 1
    assert records[0]["record_type"] == "outcome"
    assert records[0]["decision"] == "deny"


def test_a_dry_run_writes_one_record(env) -> None:
    server.explain_command("echo hi")
    records = env.records()
    assert len(records) == 1
    assert records[0]["action"] == "explain_command"
    assert records[0]["record_type"] == "outcome"


def test_records_carry_counts_not_content(env) -> None:
    """The log records what was asked for, never what came back.

    The command itself is recorded on purpose — that is the audit trail's whole
    subject. So this uses a command whose output is nowhere in its own text: the
    filename appears only in stdout, and must not reach the log.
    """
    (env.root / "unique-output-marker.txt").touch()
    server.run_command("ls")

    outcome = env.records()[-1]
    assert outcome["metrics"]["stdout_bytes"] > 0
    assert "unique-output-marker" not in json.dumps(outcome)


def test_a_secret_in_the_command_is_redacted_in_the_log(env) -> None:
    server.run_command("echo sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    text = env.audit.read_text()
    assert "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in text
    assert "[REDACTED:openai_key]" in text


def test_a_secret_passed_as_a_split_flag_value_is_redacted(env) -> None:
    """`--password hunter2` is two argv tokens; the value alone looks ordinary."""
    server.run_command("echo --password hunter2")
    text = env.audit.read_text()
    assert "hunter2" not in text


def test_the_denied_command_itself_is_recorded(env) -> None:
    server.run_command("rm -rf /")
    assert env.records()[0]["subject"] == "rm -rf /"


def test_the_deciding_rule_is_recorded(env) -> None:
    server.run_command("git push --force")
    assert env.records()[0]["rule"] == "git"


# --- fail-closed auditing --------------------------------------------------


def test_an_unwritable_log_returns_audit_unavailable(env, tmp_path: Path) -> None:
    unwritable = tmp_path / "no-such-dir" / "audit.jsonl"
    server.configure(
        env.config,
        env.root,
        audit_logger=AuditLogger(unwritable, fail_mode=FAIL_CLOSED),
    )
    result = server.run_command("echo hi")
    assert result.ok is False
    assert result.code is ResultCode.AUDIT_UNAVAILABLE


def test_an_unwritable_log_prevents_execution(
    env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The property the fail-closed gate exists for: no unlogged execution."""
    unwritable = tmp_path / "no-such-dir" / "audit.jsonl"
    server.configure(
        env.config,
        env.root,
        audit_logger=AuditLogger(unwritable, fail_mode=FAIL_CLOSED),
    )

    def _boom(*_args, **_kwargs):
        raise AssertionError("a command executed without being logged")

    monkeypatch.setattr(server.execute.subprocess, "run", _boom)
    assert server.run_command("echo hi").code is ResultCode.AUDIT_UNAVAILABLE


def test_fail_open_lets_execution_proceed(env, tmp_path: Path) -> None:
    unwritable = tmp_path / "no-such-dir" / "audit.jsonl"
    server.configure(
        env.config,
        env.root,
        audit_logger=AuditLogger(unwritable, fail_mode=FAIL_OPEN),
    )
    result = server.run_command("echo hi")
    assert result.ok is True
    assert result.detail["stdout"].strip() == "hi"


# --- configuration ---------------------------------------------------------


def test_an_unconfigured_server_returns_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server, "_CONFIG", None)
    monkeypatch.setattr(server, "_JAIL", None)
    monkeypatch.setattr(server, "_AUDIT", None)
    result = server.run_command("echo hi")
    assert result.code is ResultCode.INTERNAL_ERROR
    assert result.reason == "internal error"


def test_internal_errors_leak_nothing(env, monkeypatch: pytest.MonkeyPatch) -> None:
    def _explode(*_args, **_kwargs):
        raise RuntimeError("/secret/path/with/token-abc123")

    monkeypatch.setattr(server, "evaluate", _explode)
    result = server.run_command("echo hi")
    assert result.code is ResultCode.INTERNAL_ERROR
    assert "token-abc123" not in result.reason
    assert "secret" not in result.reason


def test_redaction_can_be_disabled(env, tmp_path: Path) -> None:
    cfg = TerminalConfig(
        policy=env.config.policy,
        jail_root=str(env.root),
        audit_log=str(tmp_path / "plain.jsonl"),
        redaction_enabled=False,
    )
    server.configure(cfg, env.root)
    result = server.run_command("echo sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in result.detail["stdout"]


# --- startup refusals ------------------------------------------------------


def _run_main(monkeypatch: pytest.MonkeyPatch, **env_vars: str) -> pytest.ExceptionInfo:
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(SystemExit) as exc:
        server.main()
    return exc


def test_startup_refuses_without_a_jail_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text(POLICY)
    monkeypatch.delenv(config_module.ENV_JAIL_ROOT, raising=False)
    _run_main(monkeypatch, **{config_module.ENV_POLICY_FILE: str(policy)})
    assert "no jail root configured" in capsys.readouterr().err


def test_startup_refuses_a_jail_root_that_is_not_a_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text(POLICY)
    _run_main(
        monkeypatch,
        **{
            config_module.ENV_POLICY_FILE: str(policy),
            config_module.ENV_JAIL_ROOT: str(tmp_path / "absent"),
        },
    )
    assert "not an existing directory" in capsys.readouterr().err


def test_startup_refuses_an_audit_log_inside_the_jail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """A permitted command inside the jail could otherwise read or forge it."""
    jail = tmp_path / "jail"
    jail.mkdir()
    policy = tmp_path / "policy.toml"
    policy.write_text(POLICY)
    _run_main(
        monkeypatch,
        **{
            config_module.ENV_POLICY_FILE: str(policy),
            config_module.ENV_JAIL_ROOT: str(jail),
            config_module.ENV_AUDIT_LOG: str(jail / "audit.jsonl"),
        },
    )
    assert "outside the jail root" in capsys.readouterr().err


def test_startup_refuses_an_unloadable_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    _run_main(
        monkeypatch,
        **{config_module.ENV_POLICY_FILE: str(tmp_path / "absent.toml")},
    )
    assert "could not load policy" in capsys.readouterr().err


# --- tool registration -----------------------------------------------------


def test_both_tools_are_registered() -> None:
    import asyncio

    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert names == {"run_command", "explain_command"}


def test_a_denial_crosses_the_boundary_as_data_not_an_error(env) -> None:
    """A refusal is a normal result. It must not surface as a protocol error."""
    import asyncio

    result = asyncio.run(server.mcp.call_tool("run_command", {"command": "rm -rf /"}))
    assert result.is_error is False
    assert result.structured_content["code"] == "POLICY_DENIED"
    assert result.structured_content["ok"] is False
