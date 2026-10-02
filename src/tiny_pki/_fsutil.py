"""Atomic file writes that never follow a symlink at the destination."""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
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
    write_files_atomic([(path, data, mode)])


def write_files_atomic(files: list[tuple[Path, bytes, int]]) -> None:
    """Write every ``(path, data, mode)`` as :func:`write_file_atomic` does, or none of them.

    Each file is staged in full next to its destination before any is renamed
    into place, so a failed write (a full disk, a missing directory, a symlink
    at a destination) leaves every destination as it was. With more than one
    file, each existing destination is kept aside first, so a rename that fails
    after earlier ones succeeded puts those back and removes the ones it created.
    """
    for path, _, _ in files:
        if path.is_symlink():
            raise ValueError(f"Expected {path} to not already exist as a symlink")
    staged: list[tuple[Path, Path]] = []
    backups: list[Path | None] = []
    replaced: list[tuple[Path, Path | None]] = []
    try:
        for path, data, mode in files:
            staged.append((_stage(path, data, mode), path))
        if len(staged) > 1:
            for _, path in staged:
                backups.append(_backup(path))
        for index, (tmp, path) in enumerate(staged):
            os.replace(tmp, path)
            replaced.append((path, backups[index] if backups else None))
    except BaseException:
        for path, backup in reversed(replaced):
            with contextlib.suppress(OSError):
                if backup is None:
                    path.unlink(missing_ok=True)
                else:
                    os.replace(backup, path)
        for tmp, _ in staged:
            tmp.unlink(missing_ok=True)
        for backup in backups:
            if backup is not None:
                backup.unlink(missing_ok=True)
        raise
    for backup in backups:
        if backup is not None:
            # Every file is already replaced: a leftover backup must not turn a finished write into a failure.
            with contextlib.suppress(OSError):
                backup.unlink(missing_ok=True)
    for directory in {path.parent for _, path in staged}:
        _fsync_directory(directory)


def _backup(path: Path) -> Path | None:
    """Keep the current ``path`` under a new name beside it; ``None`` if there is nothing there yet."""
    try:
        current_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None
    for _ in range(100):
        backup = path.with_name(f".{path.name}.{secrets.token_hex(8)}.bak")
        try:
            os.link(path, backup)
        except FileExistsError:
            continue
        except OSError:
            return _stage(path, path.read_bytes(), current_mode)
        return backup
    raise FileExistsError(f"Expected a free backup name beside {path}")


def _stage(path: Path, data: bytes, mode: int) -> Path:
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        try:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(fd, mode)
            else:
                tmp.chmod(mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError(f"Expected progress writing {path}, got {written} bytes")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _fsync_directory(directory: Path) -> None:
    """Persist the rename; best effort because some platforms cannot open a directory."""
    with contextlib.suppress(OSError):
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
