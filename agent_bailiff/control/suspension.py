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
PARENT_FORBIDDEN_BITS = stat.S_IWGRP | stat.S_IWOTH


class SuspensionError(Exception):
    pass


def suspension_directory(ledger: Path) -> Path:
    return ledger.with_name(f"{ledger.name}.suspension")


def create_suspension_directory(directory: Path, group: int) -> None:
    parent_fd = _open_parent(directory, group, os.geteuid())
    try:
        os.mkdir(directory.name, 0o700, dir_fd=parent_fd)
        fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise SuspensionError(f"{directory} changed while it was being created")
        os.fchown(fd, -1, group)
        os.fchmod(fd, DIRECTORY_MODE)
    finally:
        os.close(fd)


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
        fd = _open_directory(self._directory, self._group, os.geteuid())
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
            fd = _open_directory(self._directory, self._group, self._owner_uid)
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


def _open_parent(directory: Path, group: int, owner: int) -> int:
    try:
        fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise SuspensionError(f"cannot open the suspension directory's parent: {exc.strerror}") from None
    try:
        info = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise SuspensionError(f"cannot inspect the suspension directory's parent: {exc.strerror}") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in (0, owner)
        or info.st_mode & PARENT_FORBIDDEN_BITS
        or info.st_gid != group
    ):
        os.close(fd)
        raise SuspensionError(
            f"{directory.parent} must be owned by root or uid {owner}, in group {group}, not group or other writable"
        )
    return fd


def _open_directory(directory: Path, group: int, owner: int) -> int:
    parent_fd = _open_parent(directory, group, owner)
    try:
        return os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError as exc:
        raise SuspensionError(f"cannot open the suspension directory: {exc.strerror}") from None
    finally:
        os.close(parent_fd)


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
