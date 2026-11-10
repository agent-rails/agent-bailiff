from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from urllib.parse import quote

OWNED_MODE = 0o600
FORBIDDEN_PARENT_BITS = 0o022
BUSY_TIMEOUT_SECONDS = 30


class OwnedFileError(Exception):
    pass


def read_owned(path: Path, label: str, max_bytes: int) -> bytes:
    fd = _open_owned(path, label, os.O_RDONLY)
    try:
        content = os.read(fd, max_bytes + 1)
    except OSError as exc:
        raise OwnedFileError(f"cannot read the {label}: {exc.strerror}") from None
    finally:
        os.close(fd)
    if len(content) > max_bytes:
        raise OwnedFileError(f"the {label} is larger than {max_bytes} bytes")
    return content


def create_owned(path: Path, label: str, content: bytes) -> None:
    _check_parent(path, label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, OWNED_MODE)
    except OSError as exc:
        raise OwnedFileError(f"cannot create the {label}: {exc.strerror}") from None
    try:
        os.fchmod(fd, OWNED_MODE)
        os.write(fd, content)
        os.fsync(fd)
    except OSError as exc:
        os.close(fd)
        os.unlink(path)
        raise OwnedFileError(f"cannot write the {label}: {exc.strerror}") from None
    os.close(fd)
    _sync_parent(path)


def check_owned(path: Path, label: str) -> None:
    os.close(_open_owned(path, label, os.O_RDONLY))


def connect_owned(path: Path, label: str, schema: str | None) -> sqlite3.Connection:
    if schema is not None:
        create_owned(path, label, b"")
    check_owned(path, label)
    try:
        connection = sqlite3.connect(
            f"file:{quote(str(path.absolute()), safe='/')}?mode=rw",
            uri=True,
            timeout=BUSY_TIMEOUT_SECONDS,
            isolation_level=None,
            check_same_thread=False,
        )
    except sqlite3.Error as exc:
        raise OwnedFileError(f"cannot open the {label}: {exc}") from None
    try:
        connection.execute("PRAGMA synchronous = FULL")
        if schema is not None:
            connection.executescript(schema)
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlite3.Error as exc:
        connection.close()
        raise OwnedFileError(f"the {label} is not a usable database: {exc}") from None
    check_owned(path, label)
    return connection


def _open_owned(path: Path, label: str, flags: int) -> int:
    _check_parent(path, label)
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise OwnedFileError(f"cannot open the {label}: {exc.strerror}") from None
    info = os.fstat(fd)
    problem = _file_problem(info)
    if problem:
        os.close(fd)
        raise OwnedFileError(f"the {label} {problem}")
    return fd


def _file_problem(info: os.stat_result) -> str | None:
    if not stat.S_ISREG(info.st_mode):
        return "is not a regular file"
    if info.st_uid != os.geteuid():
        return f"is not owned by uid {os.geteuid()}"
    if stat.S_IMODE(info.st_mode) != OWNED_MODE:
        return f"must have mode {oct(OWNED_MODE)}, found {oct(stat.S_IMODE(info.st_mode))}"
    if info.st_nlink != 1:
        return "has multiple hard links"
    return None


def _check_parent(path: Path, label: str) -> None:
    try:
        info = os.stat(path.parent)
    except OSError as exc:
        raise OwnedFileError(f"cannot inspect the {label} directory: {exc.strerror}") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & FORBIDDEN_PARENT_BITS:
        raise OwnedFileError(
            f"the {label} directory must be owned by uid {os.geteuid()} and not writable by group or others"
        )


def _sync_parent(path: Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
