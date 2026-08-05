"""Result envelope tests.

The envelope's job is to make a wrong outcome impossible to express, so these
tests mostly probe the ok/code pairing and the JSON shape the audit log and MCP
clients depend on.
"""

import dataclasses
import json

import pytest

from safety.result import OperationResult, ResultCode, failed, succeeded


# --- ok/code consistency -------------------------------------------------

def test_succeeded_is_ok():
    r = succeeded("move_file")
    assert r.ok is True
    assert r.code is ResultCode.OK


def test_truncated_is_still_a_success():
    # The operation ran; only the returned text was capped.
    r = succeeded("run_command", code=ResultCode.OUTPUT_TRUNCATED)
    assert r.ok is True


def test_failed_is_not_ok():
    r = failed(ResultCode.POLICY_DENIED, "run_command", "'rm' is denied")
    assert r.ok is False
    assert r.reason == "'rm' is denied"


@pytest.mark.parametrize(
    "code",
    [
        ResultCode.POLICY_DENIED,
        ResultCode.NEEDS_EXPLICIT_REQUEST,
        ResultCode.PATH_ESCAPE,
        ResultCode.AUDIT_UNAVAILABLE,
        ResultCode.INTERNAL_ERROR,
    ],
)
def test_failure_code_cannot_be_marked_successful(code):
    with pytest.raises(ValueError):
        succeeded("move_file", code=code)


def test_a_restraint_refusal_is_its_own_code():
    """"Forbidden" and "ask me directly" must not arrive as the same code.

    A caller that cannot tell them apart can only find out by trying, which is
    exactly what a refusal is meant to prevent.
    """
    restrained = failed(
        ResultCode.NEEDS_EXPLICIT_REQUEST, "plan_organize", "installers are left alone"
    )
    forbidden = failed(ResultCode.POLICY_DENIED, "move_file", "a symlink is not moved")

    assert restrained.ok is False
    assert restrained.code is not forbidden.code
    assert restrained.code.value == "NEEDS_EXPLICIT_REQUEST"


@pytest.mark.parametrize("code", [ResultCode.OK, ResultCode.OUTPUT_TRUNCATED])
def test_success_code_cannot_be_marked_failed(code):
    with pytest.raises(ValueError):
        failed(code, "move_file", "boom")


# --- payload -------------------------------------------------------------

def test_detail_carries_server_specific_payload():
    terminal = succeeded("run_command", detail={"stdout": "hi\n", "exit_code": 0})
    files = succeeded("move_file", detail={"src": "a.txt", "dest": "docs/a.txt"})
    assert terminal.detail["exit_code"] == 0
    assert files.detail["dest"] == "docs/a.txt"


def test_detail_is_not_shared_between_instances():
    # The classic mutable-default trap: mutating one result's detail must not
    # bleed into the next result built without one.
    a = succeeded("move_file")
    a.detail["touched"] = True
    b = succeeded("move_file")
    assert b.detail == {}


# --- serialization + immutability ---------------------------------------

def test_serializes_with_code_as_plain_string():
    r = failed(ResultCode.PATH_ESCAPE, "move_file", "dest escapes jail")
    payload = json.loads(json.dumps(dataclasses.asdict(r)))
    assert payload["code"] == "PATH_ESCAPE"
    assert payload["ok"] is False
    assert payload["action"] == "move_file"


def test_result_is_frozen():
    r = succeeded("move_file")
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.ok = False  # type: ignore[misc]


def test_direct_construction_still_available_for_servers():
    # Servers may build an envelope directly; the helpers are the guarded path,
    # not a lock.
    r = OperationResult(ok=True, code=ResultCode.OK, action="ping")
    assert r.duration_ms == 0
