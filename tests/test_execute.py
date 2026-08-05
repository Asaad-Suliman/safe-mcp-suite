"""Tests for servers/terminal/execute.py.

These spawn real subprocesses. Mocking ``subprocess.run`` here would test the
mock's idea of a timeout, not the real kill; the point of this module is what
happens to an actual child process.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from safety.paths import PathJail
from safety.policy import Decision, Rule
from safety.redact import make_redactor
from safety.result import ResultCode
from servers.terminal import execute
from servers.terminal.parse import ParsedCommand, parse

ALLOWED = Decision(allowed=True, rule=Rule(action="test"), reason="allowed for test")
DENIED = Decision(allowed=False, rule=None, reason="denied for test")


@pytest.fixture
def jail(tmp_path: Path) -> PathJail:
    return PathJail.create(tmp_path)


def _parsed(raw: str) -> ParsedCommand:
    """Parse a command that is known to be well-formed."""
    result = parse(raw)
    assert isinstance(result, ParsedCommand)
    return result


def _python(code: str) -> ParsedCommand:
    """A ParsedCommand invoking this interpreter with inline code.

    Built directly rather than through ``parse`` because the code often needs
    characters the metacharacter scan rejects, and what is under test here is
    execution, not parsing.
    """
    return ParsedCommand(
        action="python",
        args=("-c", code),
        argv=(sys.executable, "-c", code),
        attributes=frozenset({"-c", code}),
    )


def _run(parsed: ParsedCommand, jail: PathJail, **kwargs):
    return execute.run(parsed, ALLOWED, jail=jail, **kwargs)


# --- the happy path --------------------------------------------------------


def test_stdout_is_captured(jail: PathJail) -> None:
    result = _run(_python("print('hello')"), jail)
    assert result.ok is True
    assert result.code is ResultCode.OK
    assert result.detail["stdout"].strip() == "hello"
    assert result.detail["exit_code"] == 0


def test_stderr_is_captured_separately(jail: PathJail) -> None:
    result = _run(_python("import sys; sys.stderr.write('problem')"), jail)
    assert result.detail["stdout"] == ""
    assert result.detail["stderr"] == "problem"


def test_nonzero_exit_is_a_successful_execution(jail: PathJail) -> None:
    """The guard worked; the command failed. Those are different facts."""
    result = _run(_python("raise SystemExit(3)"), jail)
    assert result.ok is True
    assert result.code is ResultCode.OK
    assert result.detail["exit_code"] == 3


def test_duration_is_recorded(jail: PathJail) -> None:
    result = _run(_python("import time; time.sleep(0.05)"), jail)
    assert result.duration_ms >= 40


def test_runs_in_the_jail_root_by_default(jail: PathJail) -> None:
    result = _run(_python("import os; print(os.getcwd())"), jail)
    assert Path(result.detail["stdout"].strip()).resolve() == jail.root


def test_runs_in_a_subdirectory_when_asked(jail: PathJail) -> None:
    (jail.root / "work").mkdir()
    result = _run(_python("import os; print(os.getcwd())"), jail, cwd="work")
    assert Path(result.detail["stdout"].strip()).resolve() == jail.root / "work"


# --- containment -----------------------------------------------------------


def test_traversal_cwd_escape_is_refused(jail: PathJail) -> None:
    result = _run(_python("print('ran')"), jail, cwd="../..")
    assert result.ok is False
    assert result.code is ResultCode.PATH_ESCAPE
    assert result.detail["stdout"] == ""


def test_absolute_cwd_outside_the_jail_is_refused(jail: PathJail) -> None:
    result = _run(_python("print('ran')"), jail, cwd="/etc")
    assert result.code is ResultCode.PATH_ESCAPE


def test_symlink_cwd_escape_is_refused(tmp_path: Path) -> None:
    inside = tmp_path / "jail"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (inside / "escape").symlink_to(outside)

    result = _run(_python("print('ran')"), PathJail.create(inside), cwd="escape")
    assert result.code is ResultCode.PATH_ESCAPE


def test_escaping_cwd_never_spawns_a_process(
    jail: PathJail, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*_args, **_kwargs):
        raise AssertionError("subprocess was spawned despite a jail escape")

    monkeypatch.setattr(execute.subprocess, "run", _boom)
    assert _run(_python("print('ran')"), jail, cwd="/etc").code is ResultCode.PATH_ESCAPE


def test_cwd_pointing_at_a_file_fails_without_spawning(jail: PathJail) -> None:
    (jail.root / "notadir.txt").write_text("x")
    result = _run(_python("print('ran')"), jail, cwd="notadir.txt")
    assert result.code is ResultCode.OPERATION_FAILED


# --- the decision gate -----------------------------------------------------


def test_a_denied_decision_is_refused(jail: PathJail) -> None:
    result = execute.run(_python("print('ran')"), DENIED, jail=jail)
    assert result.ok is False
    assert result.code is ResultCode.POLICY_DENIED
    assert result.reason == "denied for test"


def test_a_denied_decision_never_spawns_a_process(
    jail: PathJail, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(*_args, **_kwargs):
        raise AssertionError("subprocess was spawned for a denied decision")

    monkeypatch.setattr(execute.subprocess, "run", _boom)
    assert execute.run(_python("print('x')"), DENIED, jail=jail).ok is False


# --- the deadline ----------------------------------------------------------


def test_a_hanging_command_is_killed(jail: PathJail) -> None:
    result = _run(_python("import time; time.sleep(30)"), jail, timeout=0.5)
    assert result.ok is False
    assert result.code is ResultCode.TIMEOUT
    assert result.duration_ms < 5000


def test_timeout_surfaces_partial_output(jail: PathJail) -> None:
    code = "import sys,time; print('started'); sys.stdout.flush(); time.sleep(30)"
    result = _run(_python(code), jail, timeout=1.0)
    assert result.code is ResultCode.TIMEOUT
    assert "started" in result.detail["stdout"]


def test_timeout_reports_no_exit_code(jail: PathJail) -> None:
    result = _run(_python("import time; time.sleep(30)"), jail, timeout=0.5)
    assert result.detail["exit_code"] is None


# --- the output cap --------------------------------------------------------


def test_oversized_output_is_truncated(jail: PathJail) -> None:
    result = _run(_python("print('x' * 100000)"), jail, max_output_bytes=1000)
    assert result.ok is True
    assert result.code is ResultCode.OUTPUT_TRUNCATED
    assert result.detail["stdout"].endswith("...[truncated]")
    assert len(result.detail["stdout"].encode()) <= 1000 + len("...[truncated]")


def test_output_under_the_cap_is_not_marked_truncated(jail: PathJail) -> None:
    result = _run(_python("print('small')"), jail, max_output_bytes=1000)
    assert result.code is ResultCode.OK
    assert "truncated" not in result.detail["stdout"]


def test_oversized_stderr_alone_marks_truncation(jail: PathJail) -> None:
    code = "import sys; sys.stderr.write('e' * 100000)"
    result = _run(_python(code), jail, max_output_bytes=500)
    assert result.code is ResultCode.OUTPUT_TRUNCATED


# --- redaction -------------------------------------------------------------


def test_a_secret_in_output_is_redacted(jail: PathJail) -> None:
    secret = "sk-" + "a" * 32
    result = _run(
        _python(f"print('token: {secret}')"), jail, redactor=make_redactor()
    )
    assert secret not in result.detail["stdout"]
    assert "[REDACTED:openai_key]" in result.detail["stdout"]


def test_a_secret_in_stderr_is_redacted(jail: PathJail) -> None:
    secret = "ghp_" + "b" * 36
    code = f"import sys; sys.stderr.write('{secret}')"
    result = _run(_python(code), jail, redactor=make_redactor())
    assert secret not in result.detail["stderr"]


def test_redaction_happens_before_truncation(jail: PathJail) -> None:
    """A secret straddling the cut must not survive as a readable fragment.

    Truncating first would cut the token mid-way, leaving a head that no pattern
    matches and nothing removes. Redacting first replaces it before any cap runs.
    """
    secret = "sk-" + "c" * 32
    # A separator, because the builtin pattern is \b-anchored: a token welded to
    # the preceding word characters is not a token as far as the regex is
    # concerned. Real command output puts a space or newline here.
    padding = "A" * 50 + " "

    # 51 + 35 = 86 bytes of output capped at 60. Truncating first would cut the
    # token nine characters in and leave "sk-cccccc" readable, matched by
    # nothing; redacting first replaces all 35 characters before the cap runs.
    result = _run(
        _python(f"print('{padding}{secret}')"),
        jail,
        max_output_bytes=60,
        redactor=make_redactor(),
    )
    assert result.code is ResultCode.OUTPUT_TRUNCATED
    assert "sk-" not in result.detail["stdout"]
    assert "ccc" not in result.detail["stdout"]
    assert "[REDACTED" in result.detail["stdout"]


def test_no_redactor_leaves_output_alone(jail: PathJail) -> None:
    result = _run(_python("print('sk-plain-text')"), jail, redactor=None)
    assert "sk-plain-text" in result.detail["stdout"]


# --- environment scrubbing -------------------------------------------------


def test_parent_secrets_do_not_reach_the_child(
    jail: PathJail, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MY_API_KEY", "super-secret-value")
    code = "import os; print(os.environ.get('MY_API_KEY', 'ABSENT'))"
    result = _run(_python(code), jail)
    assert result.detail["stdout"].strip() == "ABSENT"


def test_only_allowlisted_variables_reach_the_child(jail: PathJail) -> None:
    code = "import os; print(','.join(sorted(os.environ)))"
    result = _run(_python(code), jail)
    names = set(result.detail["stdout"].strip().split(","))
    assert names <= set(execute.ENV_ALLOWLIST)


def test_path_is_always_present(
    jail: PathJail, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even a parent with no PATH must not break command resolution."""
    monkeypatch.delenv("PATH", raising=False)
    assert execute._child_env()["PATH"] == execute.PATH_FALLBACK


# --- execution failures ----------------------------------------------------


def test_missing_binary_is_an_operation_failure(jail: PathJail) -> None:
    result = execute.run(
        _parsed("definitely-not-a-real-binary-xyz --help"), ALLOWED, jail=jail
    )
    assert result.ok is False
    assert result.code is ResultCode.OPERATION_FAILED
    assert result.detail["exit_code"] is None


def test_a_non_executable_file_is_an_operation_failure(jail: PathJail) -> None:
    script = jail.root / "not_executable.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    parsed = ParsedCommand(
        action=str(script), args=(), argv=(str(script),), attributes=frozenset()
    )
    result = execute.run(parsed, ALLOWED, jail=jail)
    assert result.code is ResultCode.OPERATION_FAILED


def test_execution_failures_never_raise(jail: PathJail) -> None:
    """Every failure mode comes back as data, so no traceback crosses the wire."""
    for parsed in (
        _parsed("no-such-binary-abc"),
        _python("import time; time.sleep(30)"),
    ):
        result = execute.run(parsed, ALLOWED, jail=jail, timeout=0.5)
        assert result.ok is False


# --- no shell --------------------------------------------------------------


def test_the_child_is_never_run_through_a_shell(
    jail: PathJail, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict = {}
    real = execute.subprocess.run

    def _spy(argv, **kwargs):
        seen["argv"] = argv
        seen["shell"] = kwargs.get("shell")
        return real(argv, **kwargs)

    monkeypatch.setattr(execute.subprocess, "run", _spy)
    _run(_python("print('hi')"), jail)

    assert seen["shell"] is False
    assert isinstance(seen["argv"], list)


def test_shell_syntax_in_an_argument_is_inert(jail: PathJail) -> None:
    """Proof that shell=False holds: the child prints the operator, not runs it."""
    parsed = ParsedCommand(
        action="python",
        args=("-c", "import sys; print(sys.argv[1])", "; rm -rf /"),
        argv=(sys.executable, "-c", "import sys; print(sys.argv[1])", "; rm -rf /"),
        attributes=frozenset(),
    )
    result = execute.run(parsed, ALLOWED, jail=jail)
    assert result.detail["stdout"].strip() == "; rm -rf /"
