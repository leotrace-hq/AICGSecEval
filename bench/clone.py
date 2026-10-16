"""Copy-on-write copies of the task repo, so a cycle costs no disk until the agent edits it.

Every cycle starts from a full copy of the upstream repo and the agent changes a few lines, so
on APFS `clonefile(2)` makes that copy share the source's blocks until one side is written.
Readers (grading, scanning, the reports) see ordinary, independent files. Where cloning is not
possible (another filesystem, another volume, not macOS) each helper falls back to the plain
copy it replaces. Kept in step with LeoBench's harness/_clone.py (LEO-556).
"""
import ctypes
import ctypes.util
import os
import shutil
import sys

_CLONE_NOFOLLOW = 0x0001          # clone a symlink itself, never its target
_libc = None
if sys.platform == "darwin":
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        _libc.clonefile.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32)
        _libc.clonefile.restype = ctypes.c_int
    except (OSError, AttributeError):
        _libc = None


def clonefile(src, dst):
    """Clone `src` (a file, a symlink or a whole directory tree) to `dst`, which must not exist.

    True when cloned, False when this filesystem cannot clone (the caller copies instead). Any
    other failure, a missing source or an existing destination, raises as a copy would."""
    if _libc is None:
        return False
    if _libc.clonefile(os.fsencode(src), os.fsencode(dst), _CLONE_NOFOLLOW) == 0:
        return True
    err = ctypes.get_errno()
    if err in (18, 45, 78, 22):   # EXDEV, ENOTSUP, ENOSYS, EINVAL: not clonable here
        return False
    raise OSError(err, os.strerror(err), src)


def clone_file(src, dst):
    """shutil.copy2, as a clone where the filesystem allows. Usable as copytree's copy_function.

    Like copy2, an existing `dst` is replaced and a directory `dst` receives the file under its
    own name."""
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))
    if os.path.lexists(dst):
        os.remove(dst)
    # copy2 follows a symlink source; clonefile would copy the link itself
    if not clonefile(os.path.realpath(src), dst):
        shutil.copy2(src, dst)
    return dst


def clone_tree(src, dst, *, ignore=None, symlinks=True, dirs_exist_ok=False):
    """shutil.copytree, sharing blocks with `src` where the filesystem allows.

    With nothing to filter and a fresh destination the whole tree is one clonefile call;
    otherwise copytree walks it and clones each file. A symlinked `src` (a run's raw_repo/<repo>
    after finish_run points into the shared clone cache) is resolved first, as copytree does:
    cloning the link itself would let the agent edit the cache through it."""
    if ignore is None and symlinks and not os.path.lexists(dst):
        if clonefile(os.path.realpath(src), dst):
            return dst
    return shutil.copytree(src, dst, symlinks=symlinks, ignore=ignore,
                           copy_function=clone_file, dirs_exist_ok=dirs_exist_ok)
