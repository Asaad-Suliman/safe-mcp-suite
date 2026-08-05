"""Path jail validation — is this path inside the sandbox, really?

The single question this module answers: given a jail root and a candidate path,
does the candidate land inside the jail *after* ``..`` segments are collapsed and
symlinks are followed? Answering it in one place is the point — every server that
touches a path (a terminal server's cwd, a file organizer's source and
destination) asks the same function, so a hole closed here is closed everywhere.

The jail root is required. There is no default and no fallback to the current
working directory: a silent fallback once turned an entire home directory into
the sandbox, and a jail you did not choose is not a jail.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["PathJail"]


@dataclass(frozen=True)
class PathJail:
    """An absolute, symlink-free directory that paths must stay inside.

    Build one with :meth:`create`, which validates the root. Constructing the
    dataclass directly bypasses that validation and is only for callers that
    already hold a resolved directory.
    """

    root: Path

    @classmethod
    def create(cls, root: str | Path) -> PathJail:
        """Validate ``root`` and return a jail anchored to it.

        Raises ``ValueError`` if the root is empty or is not an existing
        directory. Failing loudly at startup is deliberate — a jail rooted at a
        typo'd path would either reject everything or, worse, be created later by
        something else and silently become writable.
        """
        if not str(root).strip():
            raise ValueError("jail root is required; it has no default")
        resolved = Path(root).expanduser().resolve()
        if not resolved.is_dir():
            raise ValueError(f"jail root is not an existing directory: {resolved}")
        return cls(root=resolved)

    def resolve(self, candidate: str | Path | None = None) -> Path | None:
        """Resolve ``candidate`` against the jail, or return None if it escapes.

        ``None`` as input means "the jail root itself". A relative candidate is
        joined to the root; an absolute one is taken as given and then checked.
        Either way the result goes through ``Path.resolve()``, which normalizes
        ``..`` and follows symlinks — so traversal escapes, symlink escapes, and
        plain absolute paths outside the root all collapse into one containment
        check instead of three separate special cases.

        Resolution is non-strict, so a path that does not exist yet still
        resolves. That matters for a file organizer: the destination of a move is
        exactly the path that does not exist yet, and it still has to be inside
        the jail.
        """
        if candidate is None:
            return self.root
        raw = Path(candidate).expanduser()
        base = raw if raw.is_absolute() else self.root / raw
        resolved = base.resolve()
        return resolved if self._inside(resolved) else None

    def resolve_for_write(self, candidate: str | Path) -> Path | None:
        """Resolve where ``candidate`` *lives*, without following a link at its name.

        :meth:`resolve` answers "what does this path point at", which is the right
        question for a directory a command will run in. It is the wrong question
        for the target of a write. If a symlink sits at ``Documents/report.pdf``,
        resolving the whole path returns the link's *target*, and a caller that
        renames onto the result writes somewhere it never named — the symlink
        silently redirects the operation.

        So only the parent is resolved and checked for containment; the final
        component is appended verbatim and never followed. The parent being inside
        the jail is enough, because a bare filename cannot climb out of it.

        A candidate whose final component is empty, ``.``, or ``..`` has no
        meaningful name to write to and returns None rather than a path pointing
        at a directory the caller did not ask for.
        """
        raw = Path(candidate).expanduser()
        if raw.name in ("", ".", ".."):
            return None
        base = raw if raw.is_absolute() else self.root / raw
        parent = base.parent.resolve()
        return parent / raw.name if self._inside(parent) else None

    def contains(self, path: str | Path) -> bool:
        """True if ``path`` resolves to the jail root or somewhere beneath it."""
        return self.resolve(path) is not None

    def _inside(self, resolved: Path) -> bool:
        """Containment on resolved paths. Path-segment aware, not textual.

        ``is_relative_to`` compares path components, so a sibling directory whose
        name merely starts with the root's name (``/jail-evil`` next to
        ``/jail``) is correctly outside. A string ``startswith`` check would let
        it through.
        """
        # ponytail: check-then-use. A symlink swapped between this check and the
        # caller's open/move is not covered (TOCTOU). Upgrade path is O_NOFOLLOW
        # plus dir-fd relative operations if an attacker is assumed to have write
        # access inside the jail.
        return resolved == self.root or resolved.is_relative_to(self.root)
