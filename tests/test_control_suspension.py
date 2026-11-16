import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from agent_bailiff.control.suspension import (
    SUSPENSION_FILE,
    Suspension,
    SuspensionError,
    SuspensionView,
    create_suspension_directory,
)

UID = os.geteuid()
GID = os.getegid()


def shared_suspension(parent):
    path = parent / "suspension"
    create_suspension_directory(path, GID)
    return path


@pytest.fixture
def directory():
    parent = Path(tempfile.mkdtemp(prefix="bs-", dir="/tmp"))
    yield shared_suspension(parent)
    shutil.rmtree(parent)


def view(directory):
    return SuspensionView(directory, UID, GID)


def test_a_new_directory_is_shared_with_the_group_read_only(directory):
    info = os.lstat(directory)
    assert (info.st_mode & 0o777, info.st_uid, info.st_gid) == (0o750, UID, GID)


def test_an_empty_trusted_directory_is_not_suspended(directory):
    assert Suspension(directory, GID).suspended is False
    assert view(directory).suspended is False


def test_suspend_then_resume_is_seen_by_the_view(directory):
    switch = Suspension(directory, GID)
    assert switch.suspend({"actor": "ops", "trace_id": "t"}) is True
    assert (switch.suspended, view(directory).suspended) == (True, True)
    assert switch.resume() is True
    assert (switch.suspended, view(directory).suspended) == (False, False)


def test_a_second_suspend_keeps_the_first_record(directory):
    switch = Suspension(directory, GID)
    switch.suspend({"actor": "first"})
    assert switch.suspend({"actor": "second"}) is False
    assert json.loads((directory / SUSPENSION_FILE).read_bytes()) == {"actor": "first"}


def test_resume_without_a_suspension_reports_nothing_to_resume(directory):
    assert Suspension(directory, GID).resume() is False


def test_the_suspension_file_is_group_readable_only(directory):
    Suspension(directory, GID).suspend({"actor": "ops"})
    info = os.lstat(directory / SUSPENSION_FILE)
    assert (info.st_mode & 0o777, info.st_uid) == (0o640, UID)


@pytest.mark.parametrize("mode", [0o700, 0o770, 0o755, 0o777])
def test_the_switch_refuses_any_mode_but_0750(directory, mode):
    os.chmod(directory, mode)
    assert Suspension(directory, GID).suspended is True
    with pytest.raises(SuspensionError):
        Suspension(directory, GID).suspend({"actor": "ops"})
    with pytest.raises(SuspensionError):
        Suspension(directory, GID).resume()


@pytest.mark.parametrize("mode", [0o770, 0o755, 0o751, 0o777])
def test_the_view_counts_a_directory_writable_by_the_group_or_open_to_others_as_suspended(directory, mode):
    os.chmod(directory, mode)
    assert view(directory).suspended is True


def test_the_switch_refuses_another_group(directory):
    assert Suspension(directory, GID + 1).suspended is True
    with pytest.raises(SuspensionError):
        Suspension(directory, GID + 1).suspend({"actor": "ops"})


def test_the_view_counts_another_owner_or_group_as_suspended(directory):
    assert SuspensionView(directory, UID + 1, GID).suspended is True
    assert SuspensionView(directory, UID, GID + 1).suspended is True


def test_a_directory_of_another_uid_counts_as_suspended(directory, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    assert Suspension(directory, GID).suspended is True
    with pytest.raises(SuspensionError):
        Suspension(directory, GID).suspend({"actor": "ops"})


def test_a_missing_directory_counts_as_suspended(directory):
    shutil.rmtree(directory)
    assert Suspension(directory, GID).suspended is True
    assert view(directory).suspended is True


def test_a_symlinked_directory_counts_as_suspended(directory):
    link = directory.parent / "link"
    link.symlink_to(directory)
    assert Suspension(link, GID).suspended is True
    assert view(link).suspended is True


def test_anything_at_the_suspension_path_counts_as_suspended(directory):
    (directory / SUSPENSION_FILE).mkdir()
    assert Suspension(directory, GID).suspended is True
    assert view(directory).suspended is True


def test_a_dangling_symlink_at_the_suspension_path_counts_as_suspended(directory):
    (directory / SUSPENSION_FILE).symlink_to(directory / "missing")
    assert Suspension(directory, GID).suspended is True
    assert view(directory).suspended is True


def test_an_unreadable_state_counts_as_suspended(directory, monkeypatch):
    real_lstat = os.lstat

    def failing(path, *args, **kwargs):
        if str(path).endswith(SUSPENSION_FILE):
            raise PermissionError("denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", failing)
    assert Suspension(directory, GID).suspended is True
    assert view(directory).suspended is True


def test_resume_refuses_to_remove_a_symlink_target(directory):
    target = directory.parent / "target"
    target.write_text("keep")
    (directory / SUSPENSION_FILE).symlink_to(target)
    assert Suspension(directory, GID).resume() is True
    assert target.read_text() == "keep"
    assert Suspension(directory, GID).suspended is False
