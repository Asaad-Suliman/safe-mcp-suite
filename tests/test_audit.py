"""Audit trail tests.

Every log lands in tmp_path, never the repo. The secret-shaped strings here are
synthetic fixtures for the redaction test; see .gitleaks.toml.
"""

import json
import threading

import pytest

from safety.audit import (
    FAIL_CLOSED,
    FAIL_OPEN,
    AuditError,
    AuditLogger,
    AuditRecord,
    AuditUnavailable,
    new_event_id,
    utc_now,
)
from safety.redact import make_redactor

_EXPECTED_KEYS = {
    "ts", "event_id", "record_type", "server", "action", "code", "subject",
    "attributes", "targets", "decision", "rule", "reason", "duration_ms", "metrics",
}


def _record(**overrides) -> AuditRecord:
    base = dict(
        ts=utc_now(),
        event_id=new_event_id(),
        record_type="outcome",
        server="terminal",
        action="run_command",
        code="OK",
    )
    return AuditRecord(**{**base, **overrides})


def _lines(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- format ---------------------------------------------------------------

def test_one_json_object_per_line(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.write(_record())
    logger.write(_record())
    records = _lines(log)
    assert len(records) == 2
    assert all(isinstance(r, dict) for r in records)


def test_schema_keys_are_stable(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLogger(log).write(_record())
    assert set(_lines(log)[0]) == _EXPECTED_KEYS


def test_appends_never_overwrite(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    for _ in range(5):
        logger.write(_record())
    assert len(_lines(log)) == 5


def test_record_stays_on_one_line_with_exotic_input(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLogger(log).write(_record(subject="line one\nline two still one record"))
    # A record that split itself would make the line count lie about the event
    # count, which is the one thing an audit log must not do.
    assert len(log.read_text().splitlines()) == 1
    assert _lines(log)[0]["subject"] == "line one\nline two still one record"


# --- generic enough for both servers -------------------------------------

def test_describes_a_command_run(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLogger(log).write(
        _record(
            action="run_command",
            subject="echo hi",
            attributes=["hi"],
            targets=["/jail"],
            decision="allow",
            rule="allowlist",
            metrics={"stdout_bytes": 3, "stderr_bytes": 0},
        )
    )
    r = _lines(log)[0]
    assert r["metrics"]["stdout_bytes"] == 3
    assert r["targets"] == ["/jail"]


def test_describes_a_file_move(tmp_path):
    # The same record shape, no command vocabulary anywhere in it.
    log = tmp_path / "audit.jsonl"
    AuditLogger(log).write(
        _record(
            server="files",
            action="move_file",
            subject="move inbox/a.pdf -> archive/2026/a.pdf",
            attributes=["ext:.pdf"],
            targets=["/jail/inbox/a.pdf", "/jail/archive/2026/a.pdf"],
            decision="allow",
            metrics={"files_moved": 1},
        )
    )
    r = _lines(log)[0]
    assert r["server"] == "files"
    assert r["metrics"] == {"files_moved": 1}
    assert len(r["targets"]) == 2


def test_attempt_and_outcome_share_an_event_id(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    event = new_event_id()
    logger.write(_record(record_type="attempt", event_id=event))
    logger.write(_record(record_type="outcome", event_id=event, metrics={"files_moved": 1}))
    a, b = _lines(log)
    assert a["event_id"] == b["event_id"]
    assert (a["record_type"], b["record_type"]) == ("attempt", "outcome")


# --- fail modes -----------------------------------------------------------

@pytest.fixture
def unwritable(tmp_path):
    """A path whose parent directory does not exist."""
    return tmp_path / "missing-dir" / "audit.jsonl"


def test_write_raises_on_unwritable_path(unwritable):
    with pytest.raises(AuditError):
        AuditLogger(unwritable).write(_record())


def test_fail_closed_is_the_default(unwritable):
    assert AuditLogger(unwritable).fail_mode == FAIL_CLOSED


def test_fail_closed_blocks_the_operation(unwritable):
    # The caller is expected to treat this as "do not proceed".
    with pytest.raises(AuditUnavailable):
        AuditLogger(unwritable).record(_record())


def test_fail_open_proceeds_and_warns_on_stderr(unwritable, capsys):
    AuditLogger(unwritable, fail_mode=FAIL_OPEN).record(_record())  # must not raise
    captured = capsys.readouterr()
    assert "audit unavailable" in captured.err
    # stdout carries JSON-RPC on an MCP stdio transport; a warning there would
    # corrupt the protocol stream.
    assert captured.out == ""


def test_invalid_fail_mode_rejected_at_construction(tmp_path):
    with pytest.raises(ValueError):
        AuditLogger(tmp_path / "audit.jsonl", fail_mode="maybe")


def test_successful_record_writes_normally(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLogger(log, fail_mode=FAIL_OPEN).record(_record())
    assert len(_lines(log)) == 1


# --- redaction ------------------------------------------------------------

def test_redactor_scrubs_free_text_fields(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, redactor=make_redactor())
    logger.write(
        _record(
            subject="curl --token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa https://x",
            attributes=["--token", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            targets=["/jail/AKIAIOSFODNN7EXAMPLE"],
            reason="allowed: AKIAIOSFODNN7EXAMPLE",
        )
    )
    raw = log.read_text()
    assert "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in raw
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "REDACTED" in raw


def test_redaction_leaves_structural_fields_alone(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLogger(log, redactor=make_redactor()).write(
        _record(decision="allow", rule="allowlist", metrics={"files_moved": 2})
    )
    r = _lines(log)[0]
    assert (r["decision"], r["rule"]) == ("allow", "allowlist")
    assert r["metrics"] == {"files_moved": 2}


def test_no_redactor_leaves_text_untouched(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLogger(log).write(_record(subject="echo hi"))
    assert _lines(log)[0]["subject"] == "echo hi"


# --- concurrency ----------------------------------------------------------

def test_concurrent_writes_produce_intact_lines(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    threads = [
        threading.Thread(target=logger.write, args=(_record(action=f"op-{i}"),))
        for i in range(40)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    records = _lines(log)  # would raise on an interleaved, half-written line
    assert len(records) == 40
    assert {r["action"] for r in records} == {f"op-{i}" for i in range(40)}
