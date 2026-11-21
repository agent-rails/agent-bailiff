import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.docket import snapshot as snapshot_module
from agent_bailiff.docket.manifest import MAX_SEGMENT
from agent_bailiff.docket.snapshot import (
    MAX_INTEGER,
    MAX_SNAPSHOT_BYTES,
    Anchor,
    Snapshot,
    SnapshotInvalid,
    SnapshotLegacy,
    read_snapshot,
    snapshot_path,
    write_snapshot,
)
from agent_bailiff.keys import encode_public_key, key_id
from agent_bailiff.service.settings import MAX_CONFIG_BYTES

EMPTY = Snapshot(1, 0, 0, hashlib.sha256(b"").hexdigest())
SEGMENT_START = Snapshot(3, 0, 5, hashlib.sha256(b"").hexdigest())
HASH_A = "A" * 43
HASH_B = "b-_9" * 10 + "xyz"
TWO_WRITERS = Snapshot(
    segment=1,
    offset=900,
    entries=5,
    prefix_sha256="0" * 64,
    anchors={"decide": Anchor(500, 3, HASH_A), "custodian": Anchor(700, 2, HASH_B)},
    kids=frozenset({"decide-1", "custodian-1"}),
)
UID = os.geteuid()
GID = os.getegid()


def round_trip(snapshot):
    return Snapshot.from_document(json.loads(snapshot.encode()))


@pytest.mark.parametrize("snapshot", [EMPTY, SEGMENT_START, TWO_WRITERS], ids=["empty", "segment-start", "two-writers"])
def test_snapshot_round_trips(snapshot):
    assert round_trip(snapshot) == snapshot


def largest_writer_set():
    public_key = encode_public_key(Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key())
    writers = {}
    size = len('{"writers":{}}')
    while True:
        name = f"w{len(writers)}"
        kid = key_id(name, Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key())
        entry = len(json.dumps({name: {kid: public_key}}, separators=(",", ":"))) - 1
        if size + entry > MAX_CONFIG_BYTES:
            return writers
        writers[name] = kid
        size += entry


def test_snapshot_of_the_largest_writer_set_fits_the_cap():
    writers = largest_writer_set()
    offset = MAX_INTEGER
    snapshot = Snapshot(
        segment=MAX_SEGMENT,
        offset=offset,
        entries=MAX_INTEGER,
        prefix_sha256="f" * 64,
        anchors={name: Anchor(offset - 1 - number, MAX_INTEGER, HASH_A) for number, name in enumerate(writers)},
        kids=frozenset(writers.values()),
    )
    assert len(snapshot.encode()) < MAX_SNAPSHOT_BYTES
    assert round_trip(snapshot) == snapshot


def document(**changes):
    base = json.loads(TWO_WRITERS.encode())
    base.update(changes)
    return base


def anchors_with(**changes):
    anchor = {"offset": 500, "seq": 3, "hash": HASH_A, **changes}
    return {"decide": anchor}


@pytest.mark.parametrize(
    "bad",
    [
        [],
        document(extra=1),
        {key: value for key, value in document().items() if key != "kids"},
        {key: value for key, value in document().items() if key != "segment"},
        document(version=3),
        document(version=0),
        document(segment=0),
        document(segment=MAX_SEGMENT + 1),
        document(segment=True),
        document(segment="1"),
        document(version=True),
        document(offset=True),
        document(offset=-1),
        document(offset=MAX_INTEGER + 1),
        document(offset=1.5),
        document(entries=False),
        document(entries=0),
        document(offset=0, entries=0),
        document(prefix_sha256="F" * 64),
        document(prefix_sha256="0" * 63),
        document(prefix_sha256=None),
        document(anchors=[]),
        document(anchors={"": {"offset": 1, "seq": 1, "hash": HASH_A}}),
        document(anchors={"decide": {"offset": 1, "seq": 1}}),
        document(anchors=anchors_with(offset=900)),
        document(anchors=anchors_with(offset=-1)),
        document(anchors=anchors_with(offset=True)),
        document(anchors=anchors_with(seq=0)),
        document(anchors=anchors_with(seq=True)),
        document(anchors=anchors_with(seq=6)),
        document(anchors=anchors_with(hash="short")),
        document(anchors=anchors_with(hash=1)),
        document(anchors={"a": {"offset": 1, "seq": 1, "hash": HASH_A}, "b": {"offset": 1, "seq": 1, "hash": HASH_B}}),
        document(entries=1, anchors={**anchors_with(seq=1), "other": {"offset": 2, "seq": 1, "hash": HASH_B}}),
        document(anchors={}),
        document(kids=[]),
        document(kids="decide-1"),
        document(kids=["decide-1", ""]),
        document(kids=["decide-1", "custodian-1"]),
        document(kids=["custodian-1", "custodian-1"]),
        document(kids=[1]),
        {**json.loads(EMPTY.encode()), "kids": ["decide-1"]},
        {**json.loads(EMPTY.encode()), "segment": 2},
        {**json.loads(SEGMENT_START.encode()), "kids": ["decide-1"]},
        {**json.loads(SEGMENT_START.encode()), "anchors": {"decide": {"offset": 0, "seq": 1, "hash": HASH_A}}},
        {**json.loads(EMPTY.encode()), "anchors": {"decide": {"offset": 0, "seq": 1, "hash": HASH_A}}},
    ],
)
def test_snapshot_refuses_an_invalid_document(bad):
    with pytest.raises(SnapshotInvalid):
        Snapshot.from_document(bad)


def legacy_document():
    value = {key: item for key, item in document().items() if key != "segment"}
    return {**value, "version": 1}


@pytest.mark.parametrize("legacy", [legacy_document(), {"version": 1}], ids=["whole", "version-only"])
def test_a_version_1_snapshot_is_legacy(legacy):
    with pytest.raises(SnapshotLegacy, match="version 1 predates segments"):
        Snapshot.from_document(legacy)


def test_a_snapshot_at_the_start_of_a_segment_keeps_the_global_entry_count():
    assert (SEGMENT_START.segment, SEGMENT_START.offset, SEGMENT_START.entries) == (3, 0, 5)
    assert (SEGMENT_START.anchors, SEGMENT_START.kids) == ({}, frozenset())


def test_snapshot_path_is_next_to_the_docket(tmp_path):
    assert snapshot_path(tmp_path / "docket.log") == tmp_path / "docket.log.snapshot"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "docket.log.snapshot"


def place(path, content, mode=0o600):
    path.write_bytes(content)
    os.chmod(path, mode)


def test_read_of_a_missing_snapshot_is_none(path):
    assert read_snapshot(path, uid=UID) is None


def test_read_returns_a_written_snapshot(path):
    write_snapshot(path, TWO_WRITERS)
    assert read_snapshot(path, uid=UID) == TWO_WRITERS


def test_read_relative_to_a_directory_fd(path):
    write_snapshot(path, TWO_WRITERS)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert read_snapshot(path, uid=UID, dir_fd=directory_fd) == TWO_WRITERS
    finally:
        os.close(directory_fd)


def test_read_refuses_a_symlink(path, tmp_path):
    target = tmp_path / "elsewhere"
    place(target, TWO_WRITERS.encode())
    path.symlink_to(target)
    with pytest.raises(SnapshotInvalid, match="cannot be opened"):
        read_snapshot(path, uid=UID)


def test_read_refuses_a_fifo_without_blocking(path):
    os.mkfifo(path, 0o600)
    with pytest.raises(SnapshotInvalid, match="regular file"):
        read_snapshot(path, uid=UID)


def test_read_refuses_another_owner(path):
    place(path, TWO_WRITERS.encode())
    with pytest.raises(SnapshotInvalid, match=f"uid {UID + 1}"):
        read_snapshot(path, uid=UID + 1)


@pytest.mark.parametrize("mode", [0o400, 0o640, 0o644, 0o660])
def test_read_without_a_reader_group_refuses_any_mode_but_0600(path, mode):
    place(path, TWO_WRITERS.encode(), mode)
    with pytest.raises(SnapshotInvalid, match="0600"):
        read_snapshot(path, uid=UID)


def test_read_with_a_reader_group_needs_0640_and_that_group(path):
    place(path, TWO_WRITERS.encode(), 0o640)
    os.chown(path, -1, GID)
    assert read_snapshot(path, uid=UID, reader_gid=GID) == TWO_WRITERS
    with pytest.raises(SnapshotInvalid, match=f"group {GID + 1000}"):
        read_snapshot(path, uid=UID, reader_gid=GID + 1000)
    os.chmod(path, 0o600)
    with pytest.raises(SnapshotInvalid, match="0640"):
        read_snapshot(path, uid=UID, reader_gid=GID)


def test_read_refuses_a_snapshot_over_the_cap(path):
    place(path, b" " * (MAX_SNAPSHOT_BYTES + 1))
    with pytest.raises(SnapshotInvalid, match="larger"):
        read_snapshot(path, uid=UID)


@pytest.mark.parametrize(
    "content",
    [b"", b"garbage", b"\xff", b'{"version":2,"version":2}', b"NaN", json.dumps(document(version=3)).encode()],
)
def test_read_refuses_invalid_content(path, content):
    place(path, content)
    with pytest.raises(SnapshotInvalid, match="not a valid snapshot"):
        read_snapshot(path, uid=UID)


def test_read_of_a_version_1_snapshot_is_legacy(path):
    place(path, json.dumps(legacy_document()).encode())
    with pytest.raises(SnapshotLegacy, match=f"{path}: snapshot version 1"):
        read_snapshot(path, uid=UID)


def test_write_gives_0600_whatever_the_umask(path):
    previous = os.umask(0o277)
    try:
        write_snapshot(path, TWO_WRITERS)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600


def test_write_with_a_reader_group_gives_0640_and_the_group(path):
    write_snapshot(path, TWO_WRITERS, reader_gid=GID)
    info = os.lstat(path)
    assert (stat.S_IMODE(info.st_mode), info.st_gid) == (0o640, GID)
    assert read_snapshot(path, uid=UID, reader_gid=GID) == TWO_WRITERS


def test_write_replaces_the_previous_snapshot(path):
    write_snapshot(path, EMPTY)
    write_snapshot(path, TWO_WRITERS)
    assert read_snapshot(path, uid=UID) == TWO_WRITERS
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_write_clears_a_leftover_temporary_file(path):
    leftover = path.with_name(f"{path.name}.tmp")
    place(leftover, b"left by a crash")
    write_snapshot(path, TWO_WRITERS)
    assert not leftover.exists()
    assert read_snapshot(path, uid=UID) == TWO_WRITERS


def fd_is_directory(fd):
    return stat.S_ISDIR(os.fstat(fd).st_mode)


def test_failed_file_sync_keeps_the_old_snapshot_and_no_temporary(path):
    write_snapshot(path, EMPTY)

    def failing_fsync(fd):
        if not fd_is_directory(fd):
            raise OSError(5, "injected fsync failure")

    with pytest.raises(OSError, match="injected"):
        write_snapshot(path, TWO_WRITERS, fsync=failing_fsync)
    assert read_snapshot(path, uid=UID) == EMPTY
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_failed_directory_sync_is_raised(path):
    synced = []

    def failing_directory_fsync(fd):
        synced.append("dir" if fd_is_directory(fd) else "file")
        if fd_is_directory(fd):
            raise OSError(5, "injected directory fsync failure")

    with pytest.raises(OSError, match="directory fsync"):
        write_snapshot(path, TWO_WRITERS, fsync=failing_directory_fsync)
    assert synced == ["file", "dir"]
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_write_refuses_a_snapshot_over_the_cap(path, monkeypatch):
    monkeypatch.setattr(snapshot_module, "MAX_SNAPSHOT_BYTES", len(TWO_WRITERS.encode()) - 1)
    with pytest.raises(SnapshotInvalid, match="larger"):
        write_snapshot(path, TWO_WRITERS)
    assert not path.exists()


def test_write_refuses_a_directory_writable_by_others(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    with pytest.raises(PermissionError, match="writable"):
        write_snapshot(shared / "docket.log.snapshot", TWO_WRITERS)
    assert list(Path(shared).iterdir()) == []
