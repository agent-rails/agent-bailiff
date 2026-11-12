from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize

SUSPENSION_FILE = "suspended"
FILE_MODE = 0o600
FORBIDDEN_DIRECTORY_BITS = 0o077


class SuspensionError(Exception):
    pass


class Suspension:
    def __init__(self, directory: Path) -> None:
        self._directory = directory

    @property
    def suspended(self) -> bool:
        try:
            directory_fd = self._open_directory()
        except SuspensionError:
            return True
        try:
            os.lstat(SUSPENSION_FILE, dir_fd=directory_fd)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        finally:
            os.close(directory_fd)
        return True

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
        try:
            fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise SuspensionError(f"cannot open the suspension directory: {exc.strerror}") from None
        info = os.fstat(fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & FORBIDDEN_DIRECTORY_BITS
        ):
            os.close(fd)
            raise SuspensionError(f"{self._directory} must be a directory owned by uid {os.geteuid()} with mode 0700")
        return fd
