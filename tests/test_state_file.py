import os
import stat

import pytest

from agent_bailiff.docket.state_file import DirectorySyncFailed, replace_state_file


@pytest.fixture
def state(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    path = directory / "state.json"
    replace_state_file(path, b"old", reader_gid=None)
    return path


def failing_fsync(kind):
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) == (kind == "dir"):
            raise OSError(5, f"injected {kind} fsync failure")
        os.fsync(fd)

    return fsync


def test_a_directory_fsync_failure_after_the_replace_is_reported_as_such(state):
    with pytest.raises(DirectorySyncFailed, match="was replaced but its directory fsync failed") as raised:
        replace_state_file(state, b"new", reader_gid=None, fsync=failing_fsync("dir"))
    assert raised.value.errno == 5
    assert state.read_bytes() == b"new"


def test_a_file_fsync_failure_before_the_replace_keeps_the_old_content(state):
    with pytest.raises(OSError) as raised:
        replace_state_file(state, b"new", reader_gid=None, fsync=failing_fsync("file"))
    assert not isinstance(raised.value, DirectorySyncFailed)
    assert state.read_bytes() == b"old"
    assert sorted(os.listdir(state.parent)) == ["state.json"]
