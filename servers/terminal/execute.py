"""Run an already-approved command, and contain the blast radius while it runs.

This is the second half that ``safety/`` deliberately does not have. A file
organizer has no argv, no child process, and no environment to scrub, so none of
this generalizes — but everything here that *is* general is borrowed rather than
rebuilt: containment comes from ``safety.paths.PathJail``, output scrubbing and
the redact-before-truncate ordering from ``safety.redact``, and the envelope from
``safety.result``. If this module ever grows its own path check or its own
redactor, that is the bug.

The four things it enforces that nothing else can:

* **No shell.** ``shell=False`` with an argv list. The child never sees a string
  a shell could reinterpret, which is what makes ``parse``'s metacharacter scan a
  second line of defence rather than the only one.
* **A deadline.** A command that hangs must not hang the server with it.
* **An output cap.** A command that prints forever must not exhaust memory or
  flood the transport.
* **A scrubbed environment.** The parent process holds API keys and tokens; a
  permitted command has no business inheriting them.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from safety.paths import PathJail
from safety.policy import Decision
from safety.redact import redact_and_truncate
from safety.result import OperationResult, ResultCode, failed, succeeded
from servers.terminal.parse import ParsedCommand

__all__ = ["ACTION", "ENV_ALLOWLIST", "PATH_FALLBACK", "run"]

#: Action name used on results produced by this module.
ACTION = "run_command"

# The only variables that reach the child. Everything else in the parent
# environment — API keys, session tokens, cloud credentials — is dropped, so a
# permitted command cannot read a secret it was never given and cannot pass one
# to a network call. PATH keeps command resolution working, HOME keeps tools that
# expect a home directory from misbehaving, LANG keeps output encoding sane.
ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "HOME", "LANG")

# Used when the parent has no PATH at all; without it the child could not resolve
# a binary by name and every command would fail as "not found".
PATH_FALLBACK = "/usr/bin:/bin"


def _child_env() -> dict[str, str]:
    """Build the child's environment: allowlisted variables only."""
    env = {key: os.environ[key] for key in ENV_ALLOWLIST if key in os.environ}
    env.setdefault("PATH", PATH_FALLBACK)
    return env


def _finalize(
    raw: bytes, redactor: Callable[[str], str] | None, max_bytes: int
) -> tuple[str, bool]:
    """Decode one captured stream, then redact and cap it.

    Decoding is lenient because a child's output is arbitrary bytes, not
    guaranteed UTF-8, and a decode error must not turn a successful command into
    a server exception. The redact-then-cap ordering is not re-implemented here —
    it is the guarantee ``safety.redact.redact_and_truncate`` exists to provide.
    """
    return redact_and_truncate(
        raw.decode("utf-8", errors="replace"), redactor, max_bytes=max_bytes
    )


def run(
    parsed: ParsedCommand,
    decision: Decision,
    *,
    jail: PathJail,
    cwd: str | None = None,
    timeout: float = 30.0,
    max_output_bytes: int = 65536,
    redactor: Callable[[str], str] | None = None,
) -> OperationResult:
    """Execute ``parsed`` inside ``jail``, having been told it is allowed.

    ``decision`` is required rather than assumed. The caller has already
    evaluated the policy, so re-evaluating here would mean holding a ``Policy``
    and duplicating logic that now lives in ``safety.policy`` — but taking the
    decision as an argument keeps the property that mattered: this function
    cannot run anything without a decision existing first, and it refuses if that
    decision is a denial. Combined with taking a ``ParsedCommand`` rather than a
    string, there is no way to reach a subprocess from raw client input without
    passing through both earlier stages.
    """
    if not decision.allowed:
        # Should be unreachable through the server, which does not call this on a
        # denial. Kept because "unreachable" is a claim about today's callers.
        return failed(
            ResultCode.POLICY_DENIED,
            ACTION,
            decision.reason,
            detail={"stdout": "", "stderr": "", "exit_code": None},
        )

    resolved = jail.resolve(cwd)
    if resolved is None:
        return failed(
            ResultCode.PATH_ESCAPE,
            ACTION,
            f"working directory escapes the jail root: {cwd!r}",
            detail={"stdout": "", "stderr": "", "exit_code": None},
        )
    if not resolved.is_dir():
        return failed(
            ResultCode.OPERATION_FAILED,
            ACTION,
            f"working directory is not a directory: {resolved}",
            detail={"stdout": "", "stderr": "", "exit_code": None},
        )

    start = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            list(parsed.argv),
            shell=False,  # explicit: argv is executed directly, never via a shell
            cwd=resolved,
            env=_child_env(),
            capture_output=True,
            timeout=timeout,
        )
        stdout_raw = completed.stdout
        stderr_raw = completed.stderr
        exit_code: int | None = completed.returncode
    except subprocess.TimeoutExpired as exc:
        # subprocess.run has already killed the child by the time this is raised.
        # Whatever it managed to print before the kill is still worth returning —
        # a timeout with no output tells an operator much less than a timeout
        # showing where the command got stuck.
        timed_out = True
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b""
        exit_code = None
    except OSError as exc:
        # Binary not found, not executable, cwd deleted between the check above
        # and the spawn. Covers FileNotFoundError and PermissionError, both
        # OSError subclasses.
        return failed(
            ResultCode.OPERATION_FAILED,
            ACTION,
            f"could not execute command: {exc}",
            detail={"stdout": "", "stderr": "", "exit_code": None},
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    duration_ms = int((time.monotonic() - start) * 1000)

    stdout, stdout_cut = _finalize(stdout_raw, redactor, max_output_bytes)
    stderr, stderr_cut = _finalize(stderr_raw, redactor, max_output_bytes)
    detail = {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}
    truncated = stdout_cut or stderr_cut

    if timed_out:
        return failed(
            ResultCode.TIMEOUT,
            ACTION,
            f"command exceeded its {timeout}s time budget and was killed",
            detail=detail,
            duration_ms=duration_ms,
        )

    # A non-zero exit is a *successful execution* of a command that failed. The
    # envelope reports whether the guard did its job; the command's own verdict
    # is exit_code, which the caller can read from detail. Conflating the two
    # would make `grep` finding no match look like a policy failure.
    return succeeded(
        ACTION,
        code=ResultCode.OUTPUT_TRUNCATED if truncated else ResultCode.OK,
        reason=decision.reason,
        detail=detail,
        duration_ms=duration_ms,
    )
