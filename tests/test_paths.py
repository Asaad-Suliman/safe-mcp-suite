"""Path jail tests, escape attempts included.

Everything is tmp_path-isolated, so no test can touch a real directory even if
the jail logic is broken.
"""

import pytest

from safety.paths import PathJail


@pytest.fixture
def jail(tmp_path):
    root = tmp_path / "jail"
    root.mkdir()
    return PathJail.create(root)


# --- the root is required and must be real -------------------------------

@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_root_rejected(bad):
    with pytest.raises(ValueError):
        PathJail.create(bad)


def test_nonexistent_root_rejected(tmp_path):
    with pytest.raises(ValueError):
        PathJail.create(tmp_path / "does-not-exist")


def test_file_as_root_rejected(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(ValueError):
        PathJail.create(f)


def test_root_is_stored_resolved(tmp_path):
    root = tmp_path / "jail"
    root.mkdir()
    j = PathJail.create(str(root) + "/./")
    assert j.root == root.resolve()
    assert j.root.is_absolute()


# --- paths that belong inside --------------------------------------------

def test_none_means_the_root_itself(jail):
    assert jail.resolve(None) == jail.root


def test_relative_path_is_joined_to_root(jail):
    assert jail.resolve("sub/file.txt") == jail.root / "sub" / "file.txt"


def test_absolute_path_inside_jail_accepted(jail):
    target = jail.root / "sub" / "file.txt"
    assert jail.resolve(target) == target


def test_nonexistent_destination_inside_jail_accepted(jail):
    # The file-move case: a destination that does not exist yet must still
    # resolve and still be checked.
    dest = jail.resolve("archive/2026/report.pdf")
    assert dest is not None
    assert not dest.exists()


def test_harmless_dotdot_that_stays_inside_is_accepted(jail):
    (jail.root / "a").mkdir()
    assert jail.resolve("a/../b.txt") == jail.root / "b.txt"


# --- escapes -------------------------------------------------------------

def test_traversal_escape_rejected(jail):
    assert jail.resolve("../../etc/passwd") is None


def test_absolute_path_outside_jail_rejected(jail):
    assert jail.resolve("/etc/passwd") is None


def test_parent_of_jail_rejected(jail):
    assert jail.resolve("..") is None


def test_symlink_pointing_outside_rejected(jail, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s3cret")
    (jail.root / "escape").symlink_to(outside)
    # The link lives inside the jail, but resolving it lands outside.
    assert jail.resolve("escape/secret.txt") is None


def test_symlinked_root_still_contains_its_own_children(tmp_path):
    # A jail whose root is itself reached through a symlink must not reject its
    # own contents: create() resolves the root so both sides compare resolved.
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    j = PathJail.create(link)
    assert j.resolve("file.txt") == real.resolve() / "file.txt"


def test_sibling_with_shared_prefix_rejected(tmp_path):
    # /jail-evil must not count as inside /jail. A textual startswith check
    # would wrongly allow this; component-wise containment does not.
    root = tmp_path / "jail"
    root.mkdir()
    evil = tmp_path / "jail-evil"
    evil.mkdir()
    j = PathJail.create(root)
    assert j.resolve(evil / "loot.txt") is None


# --- contains() ----------------------------------------------------------

def test_contains_agrees_with_resolve(jail):
    assert jail.contains("sub/file.txt") is True
    assert jail.contains("../../etc/passwd") is False
    assert jail.contains(jail.root) is True
