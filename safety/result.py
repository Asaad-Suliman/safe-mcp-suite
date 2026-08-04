"""The envelope every guarded operation returns, and the error taxonomy.

Errors are *data*, not exceptions. An operation that is denied, escapes its
jail, or fails outright returns an :class:`OperationResult` describing what
happened — it does not raise. Callers (MCP tool handlers) can therefore hand the
result straight back to a client with no chance of a Python traceback leaking
across the wire.

The envelope is deliberately action-shaped rather than command-shaped: it names
*what was attempted* and carries any server-specific payload in ``detail``. A
terminal server puts stdout/exit_code there; a file organizer puts src/dest.
Neither vocabulary belongs in the shared core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = ["ResultCode", "OperationResult", "succeeded", "failed"]


class ResultCode(str, Enum):
    """Outcome taxonomy. Each value maps to exactly one condition.

    Inheriting from ``str`` means ``json.dumps`` serializes a code as its plain
    string value, so audit lines and tool responses stay readable.

    | Code              | Condition                                             |
    |-------------------|-------------------------------------------------------|
    | OK                | The operation ran and completed.                      |
    | POLICY_DENIED     | Policy refused it. It was never attempted.            |
    | INVALID_REQUEST   | The request was malformed and could not be evaluated. |
    | PATH_ESCAPE       | A path resolved outside the jail root. Not attempted. |
    | TIMEOUT           | The operation exceeded its time budget and was killed.|
    | OUTPUT_TRUNCATED  | It completed, but the returned output hit a size cap. |
    | OPERATION_FAILED  | Allowed and attempted, but it failed (missing target, |
    |                   | permission denied, target vanished mid-flight).       |
    | AUDIT_UNAVAILABLE | The audit record could not be written under           |
    |                   | fail-closed, so the operation was NOT performed.      |
    | INTERNAL_ERROR    | Unexpected server-side exception. Generic message.    |
    """

    OK = "OK"
    POLICY_DENIED = "POLICY_DENIED"
    INVALID_REQUEST = "INVALID_REQUEST"
    PATH_ESCAPE = "PATH_ESCAPE"
    TIMEOUT = "TIMEOUT"
    OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"
    OPERATION_FAILED = "OPERATION_FAILED"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# The only codes that describe an operation that actually happened. Everything
# else means nothing was done, or it was done and broke.
_SUCCESS_CODES = frozenset({ResultCode.OK, ResultCode.OUTPUT_TRUNCATED})


@dataclass(frozen=True)
class OperationResult:
    """Uniform, immutable outcome of one guarded operation.

    ``action`` names what was attempted ("run_command", "move_file"). ``reason``
    explains the outcome in operator-readable prose. ``detail`` carries whatever
    the specific server needs to return; the safety core never inspects it.
    """

    ok: bool
    code: ResultCode
    action: str
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


def succeeded(
    action: str,
    *,
    code: ResultCode = ResultCode.OK,
    reason: str = "",
    detail: dict[str, Any] | None = None,
    duration_ms: int = 0,
) -> OperationResult:
    """Build a successful result. ``code`` must be a success code.

    Constructing results through these two helpers instead of by hand is what
    keeps ``ok`` and ``code`` from drifting apart — an ``ok=True`` result
    carrying POLICY_DENIED would be a silent authorization bug.
    """
    if code not in _SUCCESS_CODES:
        raise ValueError(f"{code.value} is not a success code")
    return OperationResult(
        ok=True,
        code=code,
        action=action,
        reason=reason,
        detail=detail if detail is not None else {},
        duration_ms=duration_ms,
    )


def failed(
    code: ResultCode,
    action: str,
    reason: str,
    *,
    detail: dict[str, Any] | None = None,
    duration_ms: int = 0,
) -> OperationResult:
    """Build a failed result. ``code`` must not be a success code."""
    if code in _SUCCESS_CODES:
        raise ValueError(f"{code.value} is a success code")
    return OperationResult(
        ok=False,
        code=code,
        action=action,
        reason=reason,
        detail=detail if detail is not None else {},
        duration_ms=duration_ms,
    )
