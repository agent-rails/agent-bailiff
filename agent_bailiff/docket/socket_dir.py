from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path

SOCKET_DIR_MODE = 0o750
SOCKET_MODE = 0o660


def prepare_socket_dir(directory: Path, gid: int) -> None:
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    else:
        os.chown(directory, -1, gid)
        os.chmod(directory, SOCKET_DIR_MODE)
    info = os.lstat(directory)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != SOCKET_DIR_MODE
    ):
        raise PermissionError(f"{directory} must be a directory owned by uid {os.geteuid()}, group {gid}, mode 0750")


def remove_stale_socket(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise PermissionError(f"{path} exists and is not a socket owned by uid {os.geteuid()}")
    path.unlink()


def try_lock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def open_lock_file(path: Path) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        os.close(fd)
        raise PermissionError(f"{path} must be a regular file owned by uid {os.geteuid()}")
    return fd


def unlink_if_same(path: Path, identity: tuple[int, int]) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if (info.st_dev, info.st_ino) == identity:
        path.unlink()
