import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from agent_bailiff.control.suspension import SUSPENSION_FILE, Suspension, SuspensionError


@pytest.fixture
def directory():
    parent = Path(tempfile.mkdtemp(prefix="bs-", dir="/tmp"))
    path = parent / "suspension"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(parent)


def test_an_empty_trusted_directory_is_not_suspended(directory):
    assert Suspension(directory).suspended is False


def test_suspend_then_resume(directory):
    switch = Suspension(directory)
    assert switch.suspend({"actor": "ops", "trace_id": "t"}) is True
    assert switch.suspended is True
    assert Suspension(directory).suspended is True
    assert switch.resume() is True
    assert switch.suspended is False


def test_a_second_suspend_keeps_the_first_record(directory):
    switch = Suspension(directory)
    switch.suspend({"actor": "first"})
    assert switch.suspend({"actor": "second"}) is False
    assert json.loads((directory / SUSPENSION_FILE).read_bytes()) == {"actor": "first"}


def test_resume_without_a_suspension_reports_nothing_to_resume(directory):
    assert Suspension(directory).resume() is False


def test_the_suspension_file_is_private(directory):
    Suspension(directory).suspend({"actor": "ops"})
    info = os.lstat(directory / SUSPENSION_FILE)
    assert (info.st_mode & 0o777, info.st_uid) == (0o600, os.geteuid())


@pytest.mark.parametrize("mode", [0o750, 0o770, 0o705, 0o777])
def test_a_directory_open_to_others_counts_as_suspended(directory, mode):
    os.chmod(directory, mode)
    assert Suspension(directory).suspended is True
    with pytest.raises(SuspensionError):
        Suspension(directory).suspend({"actor": "ops"})
    with pytest.raises(SuspensionError):
        Suspension(directory).resume()


def test_a_directory_of_another_uid_counts_as_suspended(directory, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    assert Suspension(directory).suspended is True
    with pytest.raises(SuspensionError):
        Suspension(directory).suspend({"actor": "ops"})


def test_a_missing_directory_counts_as_suspended(directory):
    shutil.rmtree(directory)
    assert Suspension(directory).suspended is True


def test_a_symlinked_directory_counts_as_suspended(directory):
    link = directory.parent / "link"
    link.symlink_to(directory)
    assert Suspension(link).suspended is True


def test_anything_at_the_suspension_path_counts_as_suspended(directory):
    (directory / SUSPENSION_FILE).mkdir()
    assert Suspension(directory).suspended is True


def test_a_dangling_symlink_at_the_suspension_path_counts_as_suspended(directory):
    (directory / SUSPENSION_FILE).symlink_to(directory / "missing")
    assert Suspension(directory).suspended is True


def test_an_unreadable_state_counts_as_suspended(directory, monkeypatch):
    real_lstat = os.lstat

    def failing(path, *args, **kwargs):
        if str(path).endswith(SUSPENSION_FILE):
            raise PermissionError("denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", failing)
    assert Suspension(directory).suspended is True


def test_resume_refuses_to_remove_a_symlink_target(directory):
    target = directory.parent / "target"
    target.write_text("keep")
    (directory / SUSPENSION_FILE).symlink_to(target)
    assert Suspension(directory).resume() is True
    assert target.read_text() == "keep"
    assert Suspension(directory).suspended is False
