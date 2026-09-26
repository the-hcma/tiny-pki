"""Atomic file writes that never follow a symlink at the destination."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_file_atomic(path: Path, data: bytes, *, mode: int) -> None:
    """Replace ``path`` with ``data`` (file mode ``mode``) via a temp file and ``rename``.

    A symlink already at ``path`` is refused. The temp file is created with
    ``O_EXCL`` in the destination directory, and ``os.replace`` swaps the
    directory entry instead of following a link, so a symlink planted between
    the check and the rename is replaced rather than written through. Readers
    see either the old file or the complete new one, never a truncated file.
    """
    if path.is_symlink():
        raise ValueError(f"Expected {path} to not already exist as a symlink")
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError(f"Expected progress writing {path}, got {written} bytes")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_directory(directory)


def _fsync_directory(directory: Path) -> None:
    """Persist the rename; best effort because some platforms cannot open a directory."""
    with contextlib.suppress(OSError):
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
