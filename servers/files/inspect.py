"""Turn a path into facts a policy can judge. Decides nothing.

This is the file server's counterpart to the terminal server's ``parse.py``.
``safety.policy.evaluate`` speaks *action name + attributes*; a filesystem speaks
inodes. Bridging the two is server work, because only this server knows that a
leading dot means hidden and that ``st_mtime_ns`` is what makes a plan go stale.

The discipline that matters here is the one the reference organizer did not have:
**this module reports, it never refuses.** It does not know that ``.exe`` is
risky or that ``desktop.ini`` should be left alone. It says "this file's extension
is ``.exe``" and "this file's name is ``desktop.ini``", and
``safety.policy`` — configured from ``policy.toml`` — decides what that means.
The reference spread those judgements across four modules as hardcoded ``if``
statements that had already drifted out of step with each other.

So the vocabulary below is deliberately *raw*. There is no ``installer``
attribute and no ``system-file`` attribute, because both would be a judgement
smuggled into code as a hardcoded extension list. There is only ``ext:.exe``,
which is a fact, and a policy file that says what to do about it.

Symlinks are the one place this module is opinionated about *how* it looks: every
stat is an ``lstat``, so a link is described as a link rather than silently
described as whatever it points at.
"""

from __future__ import annotations

import stat as stat_module
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from safety.patterns import UNSAFE_NAME_CHARACTERS, first_match

__all__ = [
    "ACTION",
    "FILE",
    "DIRECTORY",
    "SYMLINK",
    "HIDDEN",
    "EMPTY",
    "UNSAFE_NAME",
    "OTHER_CATEGORY",
    "BARE_ATTRIBUTES",
    "EXT_PREFIX",
    "NAME_PREFIX",
    "ATTRIBUTE_PREFIXES",
    "FileFacts",
    "facts",
]

#: The policy action every file question is asked under. One action, because a
#: file server has one verb worth gating: may this thing be moved by the
#: organizer at all? Tool names stay out of it — ``move_file`` and ``apply_plan``
#: ask the same question about the same file and must get the same answer.
ACTION = "organize"

# --- the attribute vocabulary ----------------------------------------------
# Every string this module can put in FileFacts.attributes. servers/files/config
# validates skip rules against exactly this vocabulary, so a typo'd rule fails at
# startup instead of silently never matching — a guardrail that never fires is
# worse than no guardrail, because it looks like protection.

FILE = "file"
DIRECTORY = "dir"
SYMLINK = "symlink"
HIDDEN = "hidden"
EMPTY = "empty"
UNSAFE_NAME = "unsafe-name"

#: Attributes that stand alone, with no value attached.
BARE_ATTRIBUTES = frozenset({FILE, DIRECTORY, SYMLINK, HIDDEN, EMPTY, UNSAFE_NAME})

#: Attributes that carry a value: ``ext:.pdf``, ``name:desktop.ini``.
EXT_PREFIX = "ext:"
NAME_PREFIX = "name:"
ATTRIBUTE_PREFIXES = (EXT_PREFIX, NAME_PREFIX)

#: Where a file goes when its extension matches no configured category.
OTHER_CATEGORY = "Other"


@dataclass(frozen=True)
class FileFacts:
    """Everything known about one path, and nothing concluded from it.

    ``size`` and ``mtime_ns`` are captured here rather than re-read later because
    they are the fingerprint ``plan.verify`` compares against to decide whether a
    plan has gone stale. Reading them once, at the moment the file was inspected,
    is what makes that comparison meaningful — a fingerprint taken at apply time
    would always match itself.
    """

    path: Path
    name: str
    attributes: frozenset[str]
    category: str
    size: int
    mtime_ns: int


def facts(path: Path, *, categories: Mapping[str, str]) -> FileFacts:
    """Describe ``path`` without following it and without judging it.

    ``categories`` maps a lowercased extension to a category name; anything
    unmatched lands in ``OTHER_CATEGORY``. The mapping is passed in rather than
    imported so this module holds no configuration of its own.

    Raises ``OSError`` if the path cannot be stat'd. That is deliberate: callers
    here are walking a directory they just listed, so a failure means the tree
    changed underfoot, and the caller — not this module — decides whether that is
    a skipped entry or a refused operation.
    """
    st = path.lstat()
    mode = st.st_mode
    is_symlink = stat_module.S_ISLNK(mode)

    name = path.name
    attributes: set[str] = set()

    if is_symlink:
        # Described as a link, full stop. Not as a file, not as a directory, and
        # explicitly not as whatever it resolves to — asking the target what it
        # is would mean following the very thing being flagged.
        attributes.add(SYMLINK)
    elif stat_module.S_ISDIR(mode):
        attributes.add(DIRECTORY)
    elif stat_module.S_ISREG(mode):
        attributes.add(FILE)
        if st.st_size == 0:
            attributes.add(EMPTY)

    # A leading dot. POSIX convention, and the only hidden-file notion that means
    # anything on this platform.
    if name.startswith("."):
        attributes.add(HIDDEN)

    if first_match(name, UNSAFE_NAME_CHARACTERS) is not None:
        attributes.add(UNSAFE_NAME)

    # Lowercased so a rule written for `.exe` also covers `.EXE`, matching how
    # safety.policy lowercases action names for the same reason.
    suffix = path.suffix.lower()
    if suffix:
        attributes.add(f"{EXT_PREFIX}{suffix}")
    attributes.add(f"{NAME_PREFIX}{name.lower()}")

    return FileFacts(
        path=path,
        name=name,
        attributes=frozenset(attributes),
        category=categories.get(suffix, OTHER_CATEGORY),
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
    )
