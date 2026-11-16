from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize

SUSPENSION_FILE = "suspended"
DIRECTORY_MODE = 0o750
FILE_MODE = 0o640
READER_FORBIDDEN_DIRECTORY_BITS = 0o027


class SuspensionError(Exception):
    pass


def create_suspension_directory(directory: Path, group: int) -> None:
    os.mkdir(directory, 0o700)
    os.chown(directory, -1, group)
    os.chmod(directory, DIRECTORY_MODE)


class Suspension:
    def __init__(self, directory: Path, group: int) -> None:
        self._directory = directory
        self._group = group

    @property
    def suspended(self) -> bool:
        try:
            directory_fd = self._open_directory()
        except SuspensionError:
            return True
        return _holds_suspension(directory_fd)

    def suspend(self, record: Mapping[str, Any]) -> bool:
        content = canonicalize(dict(record))
        directory_fd = self._open_directory()
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(SUSPENSION_FILE, flags, FILE_MODE, dir_fd=directory_fd)
            except FileExistsError:
                return False
            try:
                os.fchmod(fd, FILE_MODE)
                os.write(fd, content)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory_fd)
            return True
        finally:
            os.close(directory_fd)

    def resume(self) -> bool:
        directory_fd = self._open_directory()
        try:
            try:
                os.unlink(SUSPENSION_FILE, dir_fd=directory_fd)
            except FileNotFoundError:
                return False
            os.fsync(directory_fd)
            return True
        finally:
            os.close(directory_fd)

    def _open_directory(self) -> int:
        fd = _open_directory(self._directory)
        info = os.fstat(fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != self._group
            or stat.S_IMODE(info.st_mode) != DIRECTORY_MODE
        ):
            os.close(fd)
            raise SuspensionError(
                f"{self._directory} must be a directory owned by uid {os.geteuid()}, group {self._group}, mode 0750"
            )
        return fd


class SuspensionView:
    def __init__(self, directory: Path, owner_uid: int, group: int) -> None:
        self._directory = directory
        self._owner_uid = owner_uid
        self._group = group

    @property
    def suspended(self) -> bool:
        try:
            fd = _open_directory(self._directory)
        except SuspensionError:
            return True
        info = os.fstat(fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self._owner_uid
            or info.st_gid != self._group
            or stat.S_IMODE(info.st_mode) & READER_FORBIDDEN_DIRECTORY_BITS
        ):
            os.close(fd)
            return True
        return _holds_suspension(fd)


def _open_directory(directory: Path) -> int:
    try:
        return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise SuspensionError(f"cannot open the suspension directory: {exc.strerror}") from None


def _holds_suspension(directory_fd: int) -> bool:
    try:
        os.lstat(SUSPENSION_FILE, dir_fd=directory_fd)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    finally:
        os.close(directory_fd)
    return True
