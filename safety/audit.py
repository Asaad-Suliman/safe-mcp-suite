"""Append-only JSONL audit trail. One JSON object per line, one line per event.

The trail answers "what did the agent actually do", so its failure mode matters
more than its features. Two rules follow from that:

* **Fail-closed by default.** If a record cannot be written, the operation must
  not happen. An unlogged action is worse than a refused one, because the whole
  point of the guard is that nothing it permits is invisible afterwards.
  Fail-open exists, but only as an explicit opt-in.
* **Content-free.** Records carry counts, not payloads — how many bytes a
  command printed, how many files a move touched, never the bytes or the file
  contents themselves. A log that quietly accumulates output is a second copy of
  every secret that passed through.

Records are shaped around an *action*, not a command, so one format covers both
servers: a command run and a file move are the same kind of event with different
targets and metrics.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "AuditError",
    "AuditUnavailable",
    "AuditRecord",
    "AuditLogger",
    "FAIL_CLOSED",
    "FAIL_OPEN",
    "new_event_id",
    "utc_now",
]

FAIL_CLOSED = "closed"
FAIL_OPEN = "open"

ATTEMPT = "attempt"
OUTCOME = "outcome"


class AuditError(Exception):
    """Raised when a record could not be durably written."""


class AuditUnavailable(Exception):
    """Raised under fail-closed. The caller must not perform the operation."""


def utc_now() -> str:
    """Current time as an ISO-8601 UTC string."""
    return datetime.now(timezone.utc).isoformat()


def new_event_id() -> str:
    """A fresh event id. The attempt and outcome of one operation share it."""
    return str(uuid.uuid4())


@dataclass(frozen=True)
class AuditRecord:
    """One audited event.

    ``record_type`` distinguishes the two records of an operation that actually
    runs: ``"attempt"`` is written *before* it happens (this is the fail-closed
    gate — if that write fails, nothing runs) and ``"outcome"`` afterwards. Paths
    that never reach execution — a denial, a jail escape, a dry run — write a
    single ``"outcome"`` record. Read this field rather than inferring it from
    the code.

    ``targets`` and ``metrics`` are what make one format fit both servers: a
    command run records its cwd and ``{"stdout_bytes": 120}``; a move records its
    source and destination and ``{"files_moved": 1}``.
    """

    ts: str
    event_id: str
    record_type: str
    server: str
    action: str
    code: str
    subject: str | None = None  # the raw request text, e.g. the command line
    attributes: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    decision: str | None = None  # "allow" | "deny"
    rule: str | None = None  # which rule decided
    reason: str = ""
    duration_ms: int = 0
    metrics: dict[str, int] = field(default_factory=dict)

    def to_json_line(self) -> str:
        """Serialize to exactly one line of JSON.

        ``ensure_ascii`` stays on so a record can never contain a raw newline
        from an exotic codepoint and split itself across two lines — a log whose
        line count no longer matches its event count is a log you cannot trust.
        """
        return json.dumps(asdict(self), ensure_ascii=True) + "\n"


class AuditLogger:
    """Thread-safe, append-only JSONL writer that owns its own failure policy."""

    def __init__(
        self,
        path: str | Path,
        *,
        fail_mode: str = FAIL_CLOSED,
        redactor: Callable[[str], str] | None = None,
    ) -> None:
        if fail_mode not in (FAIL_CLOSED, FAIL_OPEN):
            raise ValueError(
                f"fail_mode must be {FAIL_CLOSED!r} or {FAIL_OPEN!r}, got {fail_mode!r}"
            )
        self._path = Path(path)
        self._fail_mode = fail_mode
        self._redactor = redactor
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def fail_mode(self) -> str:
        return self._fail_mode

    def write(self, record: AuditRecord) -> None:
        """Append one record durably. Raises :class:`AuditError` on I/O failure.

        Open-per-append: a fresh handle for every write means an unwritable path
        or a deleted parent directory surfaces on the next write rather than
        silently swallowing records, and there is no long-lived buffer to lose in
        a crash. flush + fsync makes the line durable before this returns.
        """
        line = self._scrub(record).to_json_line()
        try:
            with self._lock:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError as exc:
            raise AuditError(f"could not write audit record: {exc}") from exc

    def record(self, record: AuditRecord) -> None:
        """Write one record, applying the configured failure policy.

        Under fail-closed a write failure raises :class:`AuditUnavailable`, and
        the caller is expected to abandon the operation. Under fail-open it warns
        on **stderr** and returns — stderr specifically, because stdout carries
        JSON-RPC on an MCP stdio transport and a warning printed there would
        corrupt the protocol stream.
        """
        try:
            self.write(record)
        except AuditError as exc:
            if self._fail_mode == FAIL_OPEN:
                print(
                    f"warning: audit unavailable, proceeding (fail-open): {exc}",
                    file=sys.stderr,
                )
                return
            raise AuditUnavailable(str(exc)) from exc

    def _scrub(self, record: AuditRecord) -> AuditRecord:
        """Apply the redactor to the record's free-text fields.

        Redacting here rather than trusting every call site is deliberate: a
        secret passed as an argument is the likeliest leak path into a log, and
        "the caller will remember" is how logs end up full of credentials.
        """
        if self._redactor is None:
            return record
        r = self._redactor
        return AuditRecord(
            ts=record.ts,
            event_id=record.event_id,
            record_type=record.record_type,
            server=record.server,
            action=record.action,
            code=record.code,
            subject=r(record.subject) if record.subject is not None else None,
            attributes=[r(a) for a in record.attributes],
            targets=[r(t) for t in record.targets],
            decision=record.decision,
            rule=record.rule,
            reason=r(record.reason),
            duration_ms=record.duration_ms,
            metrics=record.metrics,
        )
