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


# --- contains_external(): the outside-the-jail check for a path the app opens
# directly (the audit log, the undo journal), not one it joins onto the root.


def test_contains_external_resolves_relative_to_cwd_not_the_root(
    jail, tmp_path, monkeypatch
):
    # A relative audit-log path sits next to the jail, not inside it — but
    # contains() joins any relative candidate onto the root, so it always
    # says "inside" regardless of the filename. contains_external() resolves
    # it the way audit.py / journal.py actually open it: against the process
    # cwd.
    monkeypatch.chdir(tmp_path)
    assert jail.contains("audit.jsonl") is True
    assert jail.contains_external("audit.jsonl") is False


def test_contains_external_still_catches_a_path_really_inside(jail, monkeypatch):
    monkeypatch.chdir(jail.root)
    assert jail.contains_external("audit.jsonl") is True


def test_contains_external_accepts_an_absolute_path_outside(jail, tmp_path):
    assert jail.contains_external(tmp_path / "outside" / "audit.jsonl") is False


# --- resolve_for_write: containment without following the leaf ------------
#
# resolve() answers "what does this point at", which is right for a directory a
# command runs in and wrong for the target of a write: a symlink at the target
# name would redirect the write to somewhere the caller never named.


def test_resolve_for_write_returns_the_named_path_not_the_link_target(jail):
    """The property the whole method exists for."""
    target = jail.root / "real.txt"
    target.write_text("x")
    link = jail.root / "link.txt"
    link.symlink_to(target)

    assert jail.resolve_for_write("link.txt") == jail.root / "link.txt"
    assert jail.resolve("link.txt") == target, "resolve still follows, by design"


def test_resolve_for_write_allows_a_path_that_does_not_exist_yet(jail):
    assert jail.resolve_for_write("Documents/new.pdf") == (
        jail.root / "Documents" / "new.pdf"
    )


def test_resolve_for_write_accepts_a_plain_name(jail):
    assert jail.resolve_for_write("a.txt") == jail.root / "a.txt"


@pytest.mark.parametrize(
    "escape", ["../outside.txt", "../../etc/passwd", "sub/../../outside.txt"]
)
def test_resolve_for_write_refuses_traversal(jail, escape):
    assert jail.resolve_for_write(escape) is None


def test_resolve_for_write_refuses_an_absolute_path_outside(jail, tmp_path):
    assert jail.resolve_for_write(tmp_path / "elsewhere" / "x.txt") is None


def test_resolve_for_write_accepts_an_absolute_path_inside(jail):
    assert jail.resolve_for_write(jail.root / "a.txt") == jail.root / "a.txt"


def test_resolve_for_write_refuses_a_symlinked_parent_pointing_outside(jail, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (jail.root / "escape").symlink_to(outside, target_is_directory=True)

    assert jail.resolve_for_write("escape/stolen.txt") is None


def test_resolve_for_write_allows_a_symlinked_parent_pointing_inside(jail):
    (jail.root / "real").mkdir()
    (jail.root / "alias").symlink_to(jail.root / "real", target_is_directory=True)

    assert jail.resolve_for_write("alias/x.txt") == jail.root / "real" / "x.txt"


@pytest.mark.parametrize("bad", ["", ".", "..", "sub/.."])
def test_resolve_for_write_refuses_a_candidate_with_no_real_name(jail, bad):
    """There is nothing to write to; returning the parent would be a surprise."""
    assert jail.resolve_for_write(bad) is None


def test_resolve_for_write_lets_pathlib_normalize_a_trailing_dot(jail):
    """`sub/.` is just `sub` by the time pathlib is done with it.

    Documented rather than special-cased: the result is still inside the jail, so
    it is a naming oddity and not an escape. A caller using it as a move
    destination is refused later anyway, because the directory already exists.
    """
    assert jail.resolve_for_write("sub/.") == jail.root / "sub"


def test_resolve_for_write_does_not_create_anything(jail):
    jail.resolve_for_write("Documents/deeply/nested/new.pdf")
    assert list(jail.root.iterdir()) == []
