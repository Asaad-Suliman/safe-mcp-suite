"""Undo/redo state. A separate file from the audit log, on purpose.

The two are easy to confuse and must not be merged. The **audit log**
(``safety/audit.py``) is append-only, content-free, and exists so that what the
server did can be reviewed afterwards; nothing is ever removed from it. The
**journal** here is mutable working state: entries move between two stacks as the
user undoes and redoes, and popping one is normal operation. A trail you pop
entries off is not an audit trail, which is exactly the mistake the reference
organizer made — it wrote skip notices into the same ``history.json`` that undo
popped from, so undoing a move could surface a "system file skipped" record.

Every undo and redo therefore writes to **both**: the journal to track position,
the audit log to record that it happened.

One entry is one *action*, not one file. An ``apply_plan`` that moved forty files
is a single entry holding forty moves, so ``undo_last_action`` reverses the whole
plan in one call rather than needing forty. It also means one file write per
action instead of one per file.

This module knows nothing about the filesystem. It never checks whether a path
exists and never performs a move. The caller does the rename and then tells the
journal it succeeded — which is the ordering the reference got right and is worth
keeping: state advances only after the thing it describes actually happened.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from safety.audit import utc_now

__all__ = ["JournalError", "JournalMove", "JournalEntry", "Journal"]


class JournalError(Exception):
    """Raised when journal state cannot be read or written.

    Deliberately fatal to the operation that triggered it. A move whose undo
    record cannot be written is a move that cannot be taken back, and the caller
    should refuse rather than proceed — the same fail-closed reasoning the audit
    log uses. The reference swallowed a corrupt journal with a bare ``except``
    and returned an empty history, silently discarding every undo the user had.
    """


@dataclass(frozen=True)
class JournalMove:
    """One rename that happened: ``src`` became ``dest``."""

    src: str
    dest: str

    def to_dict(self) -> dict[str, str]:
        return {"src": self.src, "dest": self.dest}

    @classmethod
    def from_dict(cls, data: object) -> JournalMove:
        if not isinstance(data, dict):
            raise JournalError("journal move is not an object")
        src, dest = data.get("src"), data.get("dest")
        if not isinstance(src, str) or not isinstance(dest, str):
            raise JournalError("journal move is missing src or dest")
        return cls(src=src, dest=dest)


@dataclass(frozen=True)
class JournalEntry:
    """One undoable action and every move it made, in the order it made them."""

    action: str
    moves: tuple[JournalMove, ...]
    ts: str = ""

    def __post_init__(self) -> None:
        if not self.ts:
            object.__setattr__(self, "ts", utc_now())
        object.__setattr__(self, "moves", tuple(self.moves))

    def reversed_moves(self) -> tuple[JournalMove, ...]:
        """The moves needed to undo this entry: each flipped, in reverse order.

        Reverse order matters when one action moved several files: undoing
        last-in-first-out unwinds the action along the path it took, so an
        intermediate state the forward pass created is not stepped on.
        """
        return tuple(
            JournalMove(src=m.dest, dest=m.src) for m in reversed(self.moves)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "ts": self.ts,
            "moves": [m.to_dict() for m in self.moves],
        }

    @classmethod
    def from_dict(cls, data: object) -> JournalEntry:
        if not isinstance(data, dict):
            raise JournalError("journal entry is not an object")
        action, ts, moves = data.get("action"), data.get("ts", ""), data.get("moves")
        if not isinstance(action, str) or not action:
            raise JournalError("journal entry is missing an action")
        if not isinstance(ts, str):
            raise JournalError("journal entry has a non-string timestamp")
        if not isinstance(moves, list):
            raise JournalError("journal entry is missing its moves")
        return cls(
            action=action,
            moves=tuple(JournalMove.from_dict(m) for m in moves),
            ts=ts,
        )


class Journal:
    """Two stacks in one JSON file: what was done, and what was undone."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    # --- reading ------------------------------------------------------------

    def _load(self) -> tuple[list[JournalEntry], list[JournalEntry]]:
        """Read both stacks. A missing file is empty; a corrupt one is an error."""
        if not self._path.exists():
            return [], []
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise JournalError(f"could not read journal: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise JournalError(f"journal is not valid JSON: {exc}") from exc

        if not isinstance(raw, dict):
            raise JournalError("journal is not a JSON object")
        done, undone = raw.get("done", []), raw.get("undone", [])
        if not isinstance(done, list) or not isinstance(undone, list):
            raise JournalError("journal stacks must be arrays")
        return (
            [JournalEntry.from_dict(e) for e in done],
            [JournalEntry.from_dict(e) for e in undone],
        )

    def _save(self, done: list[JournalEntry], undone: list[JournalEntry]) -> None:
        """Replace the file atomically, so a crash cannot leave it half-written.

        Written to a temp file in the *same directory* and then ``os.replace``d,
        because replace is only atomic within a filesystem. fsync before the
        rename makes the contents durable, not merely the directory entry.
        """
        payload = json.dumps(
            {
                "done": [e.to_dict() for e in done],
                "undone": [e.to_dict() for e in undone],
            },
            ensure_ascii=True,
            indent=2,
        )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".tmp",
                delete=False,
            )
            try:
                with handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(handle.name, self._path)
            except BaseException:
                # Do not leave a stray temp file behind on a failed write.
                Path(handle.name).unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise JournalError(f"could not write journal: {exc}") from exc

    # --- the operations -----------------------------------------------------

    def record(self, entry: JournalEntry) -> None:
        """Push a completed action, and drop the redo stack.

        New work invalidates redo. Keeping it would let a redo reapply a move
        into a tree that has since changed under it, which is how a "redo" turns
        into an overwrite of something the user created in the meantime.
        """
        with self._lock:
            done, _ = self._load()
            done.append(entry)
            self._save(done, [])

    def peek_undo(self) -> JournalEntry | None:
        """The action that would be undone next, without changing anything."""
        with self._lock:
            done, _ = self._load()
            return done[-1] if done else None

    def commit_undo(self) -> JournalEntry | None:
        """Move the top of ``done`` onto ``undone``. Call only after it worked."""
        with self._lock:
            done, undone = self._load()
            if not done:
                return None
            entry = done.pop()
            undone.append(entry)
            self._save(done, undone)
            return entry

    def peek_redo(self) -> JournalEntry | None:
        """The action that would be redone next, without changing anything."""
        with self._lock:
            _, undone = self._load()
            return undone[-1] if undone else None

    def commit_redo(self) -> JournalEntry | None:
        """Move the top of ``undone`` back onto ``done``. Call only after it worked."""
        with self._lock:
            done, undone = self._load()
            if not undone:
                return None
            entry = undone.pop()
            done.append(entry)
            self._save(done, undone)
            return entry

    def depths(self) -> tuple[int, int]:
        """``(undoable, redoable)`` — how deep each stack is, for reporting."""
        with self._lock:
            done, undone = self._load()
            return len(done), len(undone)


# NOTE: the whole journal is rewritten on every action, so cost grows with
# history length — fine at one write per action with human-scale histories, but
# it is O(n) per action and the file never shrinks. Upgrade path if it matters:
# cap `done` at a configured depth and drop the oldest, or move to an append-only
# log with a compaction pass.
