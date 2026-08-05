"""Tests for servers/files/inspect.py.

Everything runs against a real filesystem under ``tmp_path`` — the module's whole
job is reading inode metadata, so a mock would test the mock. The cases that
matter most are the ones the reference organizer got wrong: symlinks (it followed
them), hidden files (it ignored the concept), and names carrying control
characters (it never looked).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from servers.files.inspect import (
    DIRECTORY,
    EMPTY,
    EXT_PREFIX,
    FILE,
    HIDDEN,
    NAME_PREFIX,
    OTHER_CATEGORY,
    SYMLINK,
    UNSAFE_NAME,
    BARE_ATTRIBUTES,
    facts,
)

CATEGORIES = {
    ".pdf": "Documents",
    ".md": "Documents",
    ".png": "Images",
    ".jpg": "Images",
    ".exe": "Applications",
}


def make(tmp_path: Path, name: str, content: str = "hi") -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


# --- the basic shape --------------------------------------------------------


def test_a_plain_file(tmp_path: Path) -> None:
    path = make(tmp_path, "report.pdf")
    f = facts(path, categories=CATEGORIES)

    assert f.path == path
    assert f.name == "report.pdf"
    assert FILE in f.attributes
    assert f.category == "Documents"
    assert f.size == 2
    assert f.mtime_ns > 0


def test_a_directory(tmp_path: Path) -> None:
    path = tmp_path / "Photos"
    path.mkdir()
    f = facts(path, categories=CATEGORIES)

    assert DIRECTORY in f.attributes
    assert FILE not in f.attributes
    assert EMPTY not in f.attributes, "empty is about byte size, not directory contents"


def test_an_empty_file_is_both_file_and_empty(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "blank.txt", ""), categories=CATEGORIES)
    assert {FILE, EMPTY} <= f.attributes
    assert f.size == 0


# --- symlinks: described, never followed -------------------------------------


def test_a_symlink_is_a_symlink_not_its_target(tmp_path: Path) -> None:
    """The reference used is_file(), which follows. That is the bug being fixed."""
    target = make(tmp_path, "real.pdf")
    link = tmp_path / "link.pdf"
    link.symlink_to(target)

    f = facts(link, categories=CATEGORIES)

    assert SYMLINK in f.attributes
    assert FILE not in f.attributes
    assert DIRECTORY not in f.attributes


def test_a_symlink_to_a_directory_is_not_reported_as_a_directory(
    tmp_path: Path,
) -> None:
    target = tmp_path / "somewhere"
    target.mkdir()
    link = tmp_path / "shortcut"
    link.symlink_to(target, target_is_directory=True)

    f = facts(link, categories=CATEGORIES)

    assert SYMLINK in f.attributes
    assert DIRECTORY not in f.attributes


def test_a_symlink_pointing_outside_the_tree_still_only_reports_symlink(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside-target.txt"
    outside.write_text("secret")
    link = workspace / "escape.txt"
    link.symlink_to(outside)

    f = facts(link, categories=CATEGORIES)

    assert SYMLINK in f.attributes
    assert FILE not in f.attributes


def test_a_broken_symlink_does_not_raise(tmp_path: Path) -> None:
    """lstat succeeds where stat would not. A dangling link is still describable."""
    link = tmp_path / "dangling.pdf"
    link.symlink_to(tmp_path / "does-not-exist")

    f = facts(link, categories=CATEGORIES)
    assert SYMLINK in f.attributes


# --- hidden -----------------------------------------------------------------


def test_a_dotfile_is_hidden(tmp_path: Path) -> None:
    f = facts(make(tmp_path, ".bashrc"), categories=CATEGORIES)
    assert HIDDEN in f.attributes


def test_a_hidden_directory_is_hidden(tmp_path: Path) -> None:
    path = tmp_path / ".git"
    path.mkdir()
    f = facts(path, categories=CATEGORIES)
    assert {HIDDEN, DIRECTORY} <= f.attributes


def test_a_dot_inside_a_name_does_not_make_it_hidden(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "my.report.pdf"), categories=CATEGORIES)
    assert HIDDEN not in f.attributes


# --- unsafe names -----------------------------------------------------------


def test_a_newline_in_a_name_is_flagged(tmp_path: Path) -> None:
    """Such a name would split an audit record across two lines."""
    f = facts(make(tmp_path, "report\nfake.pdf"), categories=CATEGORIES)
    assert UNSAFE_NAME in f.attributes


def test_an_escape_sequence_in_a_name_is_flagged(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "sneaky\x1b[2K.txt"), categories=CATEGORIES)
    assert UNSAFE_NAME in f.attributes


def test_an_ordinary_name_is_not_flagged(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "My Report (final).pdf"), categories=CATEGORIES)
    assert UNSAFE_NAME not in f.attributes


def test_non_ascii_is_not_an_unsafe_name(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "résumé-ünïcödé.pdf"), categories=CATEGORIES)
    assert UNSAFE_NAME not in f.attributes


# --- ext: and name: ---------------------------------------------------------


def test_extension_and_name_attributes_are_emitted(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "Setup.EXE"), categories=CATEGORIES)
    assert f"{EXT_PREFIX}.exe" in f.attributes
    assert f"{NAME_PREFIX}setup.exe" in f.attributes


def test_extension_matching_is_case_insensitive(tmp_path: Path) -> None:
    """A rule written for `.exe` must not be dodged by naming the file `.EXE`."""
    upper = facts(make(tmp_path, "a.EXE"), categories=CATEGORIES)
    lower = facts(make(tmp_path, "b.exe"), categories=CATEGORIES)
    assert f"{EXT_PREFIX}.exe" in upper.attributes
    assert f"{EXT_PREFIX}.exe" in lower.attributes
    assert upper.category == lower.category == "Applications"


def test_a_file_with_no_extension_emits_no_ext_attribute(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "Makefile"), categories=CATEGORIES)
    assert not any(a.startswith(EXT_PREFIX) for a in f.attributes)
    assert f"{NAME_PREFIX}makefile" in f.attributes
    assert f.category == OTHER_CATEGORY


def test_a_dotfile_extension_is_read_the_way_pathlib_reads_it(tmp_path: Path) -> None:
    """`.bashrc` has no suffix as far as pathlib is concerned. Documented, not fixed."""
    f = facts(make(tmp_path, ".bashrc"), categories=CATEGORIES)
    assert not any(a.startswith(EXT_PREFIX) for a in f.attributes)
    assert f"{NAME_PREFIX}.bashrc" in f.attributes


def test_system_filenames_surface_as_plain_name_attributes(tmp_path: Path) -> None:
    """No `system-file` attribute exists. That judgement belongs to policy."""
    f = facts(make(tmp_path, "Thumbs.db"), categories=CATEGORIES)
    assert f"{NAME_PREFIX}thumbs.db" in f.attributes
    assert "system-file" not in f.attributes


def test_installer_extensions_surface_as_plain_ext_attributes(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "installer.msi"), categories=CATEGORIES)
    assert f"{EXT_PREFIX}.msi" in f.attributes
    assert "installer" not in f.attributes


# --- categories -------------------------------------------------------------


def test_unmatched_extension_falls_to_other(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "archive.tar.zst"), categories=CATEGORIES)
    assert f.category == OTHER_CATEGORY


def test_an_empty_category_map_sends_everything_to_other(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "report.pdf"), categories={})
    assert f.category == OTHER_CATEGORY


# --- contract ---------------------------------------------------------------


def test_every_bare_attribute_produced_is_in_the_declared_vocabulary(
    tmp_path: Path,
) -> None:
    """config.py validates skip rules against BARE_ATTRIBUTES.

    If this module ever emits a bare attribute missing from that set, a rule
    written for it would be rejected at startup as a typo. Catch the drift here.
    """
    paths = []
    paths.append(make(tmp_path, "plain.pdf"))
    paths.append(make(tmp_path, "empty.txt", ""))
    paths.append(make(tmp_path, ".hidden"))
    paths.append(make(tmp_path, "bad\nname.txt"))
    directory = tmp_path / "dir"
    directory.mkdir()
    paths.append(directory)
    link = tmp_path / "link"
    link.symlink_to(directory)
    paths.append(link)

    for path in paths:
        produced = facts(path, categories=CATEGORIES).attributes
        bare = {a for a in produced if ":" not in a}
        assert bare <= BARE_ATTRIBUTES, f"{path.name} emitted {bare - BARE_ATTRIBUTES}"


def test_facts_are_frozen(tmp_path: Path) -> None:
    f = facts(make(tmp_path, "report.pdf"), categories=CATEGORIES)
    with pytest.raises(AttributeError):
        f.category = "Elsewhere"  # type: ignore[misc]


def test_a_missing_path_raises_oserror(tmp_path: Path) -> None:
    """The caller decides what a vanished file means; this module does not guess."""
    with pytest.raises(OSError):
        facts(tmp_path / "not-there.pdf", categories=CATEGORIES)


def test_inspecting_does_not_modify_anything(tmp_path: Path) -> None:
    path = make(tmp_path, "report.pdf")
    before = sorted(p.name for p in tmp_path.iterdir())
    stat_before = path.stat().st_mtime_ns

    facts(path, categories=CATEGORIES)

    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert path.stat().st_mtime_ns == stat_before
