from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path

from agent_bailiff.docket.private_dir import open_private_dir

PRIVATE_MODE = 0o600
READER_MODE = 0o640


class StateFileInvalid(ValueError):
    pass


class DirectorySyncFailed(OSError):
    pass


def read_state_file(
    path: Path, *, uid: int, reader_gid: int | None, max_bytes: int, dir_fd: int | None = None
) -> bytes | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path.name if dir_fd is not None else path, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StateFileInvalid(f"{path} cannot be opened: {exc.strerror}") from None
    try:
        _check_file(fd, path, uid, reader_gid)
        content = os.read(fd, max_bytes + 1)
    except OSError as exc:
        raise StateFileInvalid(f"{path} cannot be read: {exc.strerror}") from None
    finally:
        os.close(fd)
    if len(content) > max_bytes:
        raise StateFileInvalid(f"{path} is larger than {max_bytes} bytes")
    return content


def replace_state_file(
    path: Path,
    content: bytes,
    *,
    reader_gid: int | None,
    fsync: Callable[[int], None] = os.fsync,
) -> None:
    temporary = f"{path.name}.tmp"
    directory_fd = open_private_dir(path.parent)
    try:
        _unlink_if_present(temporary, directory_fd)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(temporary, flags, PRIVATE_MODE, dir_fd=directory_fd)
        try:
            try:
                _share(fd, reader_gid)
                _write_all(fd, content)
                fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        except BaseException:
            _unlink_if_present(temporary, directory_fd)
            raise
        try:
            fsync(directory_fd)
        except OSError as exc:
            raise DirectorySyncFailed(exc.errno, f"{path} was replaced but its directory fsync failed") from exc
    finally:
        os.close(directory_fd)


def _check_file(fd: int, path: Path, uid: int, reader_gid: int | None) -> None:
    info = os.fstat(fd)
    mode = PRIVATE_MODE if reader_gid is None else READER_MODE
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != mode
        or (reader_gid is not None and info.st_gid != reader_gid)
    ):
        group = "" if reader_gid is None else f", group {reader_gid},"
        raise StateFileInvalid(f"{path} must be a regular file owned by uid {uid}{group} with mode {mode:04o}")


def _share(fd: int, reader_gid: int | None) -> None:
    os.fchmod(fd, PRIVATE_MODE)
    if reader_gid is None:
        return
    os.fchown(fd, -1, reader_gid)
    os.fchmod(fd, READER_MODE)


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        view = view[os.write(fd, view) :]


def _unlink_if_present(name: str, directory_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        pass
