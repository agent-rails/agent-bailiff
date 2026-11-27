import errno
import os
import sqlite3
import stat

import pytest

from agent_bailiff.custodian import files
from agent_bailiff.custodian.files import (
    OwnedFileError,
    commit_at,
    connect_owned,
    create_owned,
    raise_database_error,
    replace_at,
    stage_at,
)

TARGET = "target.json"
LABEL = "target file"


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "dir"
    path.mkdir()
    os.chmod(path, 0o755)
    (path / TARGET).write_bytes(b"old")
    return path


@pytest.fixture
def dir_fd(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    yield fd
    os.close(fd)


@pytest.fixture
def fsynced(monkeypatch):
    real_fsync = files.os.fsync
    inodes = []

    def recording_fsync(fd):
        inodes.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    monkeypatch.setattr(files.os, "fsync", recording_fsync)
    return inodes


def no_space(*args, **kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def test_stage_writes_and_fsyncs_without_touching_the_target(directory, dir_fd, fsynced):
    staged = stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    assert staged.startswith(f".{TARGET}.") and staged.endswith(files.STAGED_SUFFIX)
    assert (directory / staged).read_bytes() == b"new"
    assert stat.S_IMODE((directory / staged).stat().st_mode) == 0o644
    assert fsynced == [(directory / staged).stat().st_ino]
    assert (directory / TARGET).read_bytes() == b"old"
    assert sorted(os.listdir(directory)) == sorted([TARGET, staged])


def test_stage_sets_the_mode_despite_the_umask(directory, dir_fd):
    previous = os.umask(0o077)
    try:
        staged = stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    finally:
        os.umask(previous)
    assert stat.S_IMODE((directory / staged).stat().st_mode) == 0o644


def test_each_stage_gets_its_own_file(directory, dir_fd):
    first = stage_at(dir_fd, TARGET, LABEL, b"one", 0o600)
    second = stage_at(dir_fd, TARGET, LABEL, b"two", 0o600)
    assert first != second
    assert (directory / first).read_bytes() == b"one"
    assert (directory / second).read_bytes() == b"two"


def test_commit_renames_the_staged_file_onto_the_target_and_fsyncs_the_directory(directory, dir_fd, fsynced):
    staged = stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    staged_inode = (directory / staged).stat().st_ino
    fsynced.clear()
    commit_at(dir_fd, staged, TARGET, LABEL)
    assert (directory / TARGET).read_bytes() == b"new"
    assert (directory / TARGET).stat().st_ino == staged_inode
    assert fsynced == [os.fstat(dir_fd).st_ino]
    assert os.listdir(directory) == [TARGET]


def test_a_stage_that_cannot_create_leaves_nothing(directory, dir_fd):
    os.chmod(directory, 0o555)
    try:
        with pytest.raises(OwnedFileError, match="cannot create the target file"):
            stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    finally:
        os.chmod(directory, 0o755)
    assert os.listdir(directory) == [TARGET]
    assert (directory / TARGET).read_bytes() == b"old"


@pytest.mark.parametrize("call", ["write", "fsync", "fchmod"])
def test_a_stage_that_fails_to_write_removes_the_staged_file(directory, dir_fd, monkeypatch, call):
    monkeypatch.setattr(files.os, call, no_space)
    with pytest.raises(OwnedFileError, match="cannot write the target file: No space left on device"):
        stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    monkeypatch.undo()
    assert os.listdir(directory) == [TARGET]
    assert (directory / TARGET).read_bytes() == b"old"


def test_a_short_write_removes_the_staged_file(directory, dir_fd, monkeypatch):
    real_write = files.os.write
    monkeypatch.setattr(files.os, "write", lambda fd, content: real_write(fd, content[:1]))
    with pytest.raises(OwnedFileError, match="cannot write the target file"):
        stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    monkeypatch.undo()
    assert os.listdir(directory) == [TARGET]


def test_a_failed_rename_keeps_the_target_and_removes_the_staged_file(directory, dir_fd, monkeypatch):
    staged = stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    monkeypatch.setattr(files.os, "rename", no_space)
    with pytest.raises(OwnedFileError, match="cannot write the target file: No space left on device"):
        commit_at(dir_fd, staged, TARGET, LABEL)
    monkeypatch.undo()
    assert os.listdir(directory) == [TARGET]
    assert (directory / TARGET).read_bytes() == b"old"


def test_a_failed_directory_fsync_after_the_rename_is_reported(directory, dir_fd, monkeypatch):
    staged = stage_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    monkeypatch.setattr(files.os, "fsync", no_space)
    with pytest.raises(OwnedFileError, match="cannot write the target file"):
        commit_at(dir_fd, staged, TARGET, LABEL)
    monkeypatch.undo()
    assert os.listdir(directory) == [TARGET]
    assert (directory / TARGET).read_bytes() == b"new"


def test_replace_writes_the_target_whole_with_the_mode(directory, dir_fd, fsynced):
    replace_at(dir_fd, TARGET, LABEL, b"new", 0o600)
    assert (directory / TARGET).read_bytes() == b"new"
    assert stat.S_IMODE((directory / TARGET).stat().st_mode) == 0o600
    assert fsynced[-1] == os.fstat(dir_fd).st_ino
    assert len(fsynced) == 2
    assert os.listdir(directory) == [TARGET]


def test_replace_creates_a_missing_target(directory, dir_fd):
    os.unlink(directory / TARGET)
    replace_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    assert os.listdir(directory) == [TARGET]
    assert (directory / TARGET).read_bytes() == b"new"


@pytest.mark.parametrize("call", ["write", "rename"])
def test_a_failed_replace_keeps_the_target(directory, dir_fd, monkeypatch, call):
    monkeypatch.setattr(files.os, call, no_space)
    with pytest.raises(OwnedFileError, match="cannot write the target file"):
        replace_at(dir_fd, TARGET, LABEL, b"new", 0o644)
    monkeypatch.undo()
    assert os.listdir(directory) == [TARGET]
    assert (directory / TARGET).read_bytes() == b"old"


@pytest.fixture
def opened(monkeypatch):
    real_open = files.os.open
    fds = []

    def recording_open(*args, **kwargs):
        fds.append(real_open(*args, **kwargs))
        return fds[-1]

    monkeypatch.setattr(files.os, "open", recording_open)
    return fds


def assert_closed(fd):
    with pytest.raises(OSError) as raised:
        os.fstat(fd)
    assert raised.value.errno == errno.EBADF


def test_create_owned_removes_the_file_when_the_write_fails(directory, opened, monkeypatch):
    monkeypatch.setattr(files.os, "fsync", no_space)
    with pytest.raises(OwnedFileError, match="cannot write the target file: No space left on device"):
        create_owned(directory / "new.json", LABEL, b"x")
    assert os.listdir(directory) == [TARGET]
    assert_closed(opened[-1])


def test_create_owned_removes_the_file_and_reraises_an_error_that_is_not_an_os_error(directory, opened, monkeypatch):
    def interrupted(fd):
        raise KeyboardInterrupt

    monkeypatch.setattr(files.os, "fsync", interrupted)
    with pytest.raises(KeyboardInterrupt):
        create_owned(directory / "new.json", LABEL, b"x")
    assert os.listdir(directory) == [TARGET]
    assert_closed(opened[-1])


def test_create_owned_names_the_partial_file_it_cannot_remove(directory, opened, monkeypatch):
    def denied(path):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(files.os, "fsync", no_space)
    monkeypatch.setattr(files.os, "unlink", denied)
    path = directory / "new.json"
    with pytest.raises(OwnedFileError, match=f"cannot remove the partly written target file at {path}: Permission"):
        create_owned(path, LABEL, b"x")
    assert path.exists()
    assert_closed(opened[-1])


def test_create_owned_removes_the_file_when_closing_it_fails(directory, opened, monkeypatch):
    real_close = files.os.close
    closed = []

    def failing_close(fd):
        closed.append(fd)
        real_close(fd)
        if len(closed) == 1:
            raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(files.os, "fsync", no_space)
    monkeypatch.setattr(files.os, "close", failing_close)
    with pytest.raises(OwnedFileError, match="No space left on device; cannot close the partly written target file"):
        create_owned(directory / "new.json", LABEL, b"x")
    assert os.listdir(directory) == [TARGET]


def test_create_owned_keeps_an_interrupt_when_the_file_cannot_be_removed(directory, opened, monkeypatch):
    def interrupted(fd):
        raise KeyboardInterrupt

    def denied(path):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(files.os, "fsync", interrupted)
    monkeypatch.setattr(files.os, "unlink", denied)
    with pytest.raises(KeyboardInterrupt) as raised:
        create_owned(directory / "new.json", LABEL, b"x")
    assert raised.value.__notes__ == [
        f"cannot remove the partly written target file at {directory / 'new.json'}: Permission denied"
    ]
    assert_closed(opened[-1])


def sqlite_error(code, name):
    error = sqlite3.OperationalError("raw sqlite text")
    error.sqlite_errorcode = code
    error.sqlite_errorname = name
    return error


@pytest.mark.parametrize(
    ("code", "name", "problem"),
    [
        (sqlite3.SQLITE_FULL, "SQLITE_FULL", "its storage failed"),
        (sqlite3.SQLITE_IOERR_WRITE, "SQLITE_IOERR_WRITE", "its storage failed"),
        (sqlite3.SQLITE_CANTOPEN, "SQLITE_CANTOPEN", "its storage could not be opened"),
        (sqlite3.SQLITE_BUSY, "SQLITE_BUSY", "it is busy"),
        (sqlite3.SQLITE_READONLY, "SQLITE_READONLY", "it is not writable"),
        (sqlite3.SQLITE_NOTADB, "SQLITE_NOTADB", "it is not a usable database"),
        (sqlite3.SQLITE_CONSTRAINT_TRIGGER, "SQLITE_CONSTRAINT_TRIGGER", "the database refused it"),
    ],
)
def test_a_database_error_is_refused_by_its_primary_code(code, name, problem):
    with pytest.raises(OwnedFileError) as raised:
        raise_database_error("cannot write the store", sqlite_error(code, name))
    assert str(raised.value) == f"cannot write the store: {problem} ({name})"


def test_a_connection_that_cannot_open_names_the_path_without_the_sqlite_message(directory, monkeypatch):
    path = directory / "store.db"
    real_connect = files.sqlite3.connect

    def removed_first(*args, **kwargs):
        path.unlink()
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(files.sqlite3, "connect", removed_first)
    with pytest.raises(OwnedFileError) as raised:
        connect_owned(path, LABEL, "")
    assert str(raised.value) == f"cannot open the {LABEL} at {path}: its storage could not be opened (SQLITE_CANTOPEN)"
    assert "unable to open database file" not in str(raised.value)
