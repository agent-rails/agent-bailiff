import json
import os
import stat

import pytest

from agent_bailiff.docket import manifest as manifest_module
from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.manifest import (
    MAX_INTEGER,
    MAX_MANIFEST_BYTES,
    MAX_SEGMENT,
    Base,
    Manifest,
    ManifestInvalid,
    SegmentEntry,
    manifest_path,
    read_manifest,
    segment_path,
    write_manifest,
)

HASH_A = "A" * 43
HASH_B = "b-_9" * 10 + "xyz"
HASH_C = "C" * 43
HASH_D = "D" * 43
HASH_E = "E" * 43
DOCKET_ID = "0123456789abcdef0123456789abcdef"
BASE = Base(3, 5, {"decide": Head(3, HASH_A), "custodian": Head(2, HASH_B)})
FOURTH = SegmentEntry(
    segment=4,
    sha256="0" * 64,
    size=1000,
    first_entry=6,
    entries=2,
    end_heads={"decide": Head(4, HASH_C), "custodian": Head(3, HASH_D)},
    kids=frozenset({"decide-1", "custodian-1"}),
)
FIFTH = SegmentEntry(
    segment=5,
    sha256="f" * 64,
    size=400,
    first_entry=8,
    entries=1,
    end_heads={"decide": Head(4, HASH_C), "custodian": Head(3, HASH_D), "effector": Head(1, HASH_E)},
    kids=frozenset({"effector-1"}),
)
TWO_SEGMENTS = Manifest(DOCKET_ID, 7, BASE, (FOURTH, FIFTH))
FIRST = SegmentEntry(1, "1" * 64, 300, 1, 2, {"decide": Head(2, HASH_A)}, frozenset({"decide-1"}))
UID = os.geteuid()
GID = os.getegid()


def round_trip(manifest):
    return Manifest.from_document(json.loads(manifest.encode()))


@pytest.mark.parametrize(
    "manifest",
    [Manifest(DOCKET_ID, 1), Manifest(DOCKET_ID, 1, segments=(FIRST,)), Manifest(DOCKET_ID, 2, BASE), TWO_SEGMENTS],
    ids=["empty", "first-segment", "base-only", "base-and-two"],
)
def test_manifest_round_trips(manifest):
    assert round_trip(manifest) == manifest


def test_a_new_manifest_has_a_random_docket_id_and_no_segments():
    first, second = Manifest.new(), Manifest.new()
    assert len(first.docket_id) == 32
    assert int(first.docket_id, 16) >= 0
    assert first.docket_id != second.docket_id
    assert (first.generation, first.base, first.segments) == (0, None, ())
    assert (first.active_segment, first.entries, first.seeds) == (1, 0, {})


def test_positions_follow_the_last_segment_then_the_base():
    assert (TWO_SEGMENTS.active_segment, TWO_SEGMENTS.entries) == (6, 8)
    assert TWO_SEGMENTS.seeds == FIFTH.end_heads
    base_only = Manifest(DOCKET_ID, 1, BASE)
    assert (base_only.active_segment, base_only.entries, base_only.seeds) == (4, 5, BASE.end_heads)


def test_sealing_appends_and_bumps_the_generation():
    sealed = Manifest(DOCKET_ID, 6, BASE, (FOURTH,)).sealed(FIFTH)
    assert sealed == TWO_SEGMENTS


def test_sealing_refuses_a_segment_that_does_not_follow():
    with pytest.raises(ManifestInvalid, match="first_entry"):
        Manifest(DOCKET_ID, 6, BASE, (FOURTH,)).sealed(SegmentEntry(**{**FIFTH.__dict__, "first_entry": 9}))
    with pytest.raises(ManifestInvalid, match="segment must be 5"):
        Manifest(DOCKET_ID, 6, BASE, (FOURTH,)).sealed(SegmentEntry(**{**FIFTH.__dict__, "segment": 6}))


def document(**changes):
    value = json.loads(TWO_SEGMENTS.encode())
    value.update(changes)
    return value


def base_with(**changes):
    return {**json.loads(TWO_SEGMENTS.encode())["base"], **changes}


def fourth_with(**changes):
    segments = json.loads(TWO_SEGMENTS.encode())["segments"]
    segments[0] = {**segments[0], **changes}
    return segments


def heads(**seqs):
    hashes = {"decide": HASH_C, "custodian": HASH_D, "effector": HASH_E}
    return {writer: {"seq": seq, "hash": hashes[writer]} for writer, seq in seqs.items()}


@pytest.mark.parametrize(
    "bad",
    [
        [],
        document(extra=1),
        {key: value for key, value in document().items() if key != "base"},
        document(version=2),
        document(version=True),
        document(docket_id="0123456789ABCDEF0123456789ABCDEF"),
        document(docket_id="0" * 31),
        document(docket_id=None),
        document(generation=0),
        document(generation=True),
        document(generation=MAX_INTEGER + 1),
        document(base=[]),
        document(base=base_with(extra=1)),
        document(base=base_with(segment=0)),
        document(base=base_with(segment=MAX_SEGMENT + 1)),
        document(base=base_with(entries=0)),
        document(base=base_with(entries=6)),
        document(base=base_with(end_heads={})),
        document(segments={}),
        document(segments=fourth_with(segment=5)),
        document(segments=fourth_with(first_entry=7)),
        document(segments=fourth_with(sha256="F" * 64)),
        document(segments=fourth_with(sha256="0" * 63)),
        document(segments=fourth_with(size=0)),
        document(segments=fourth_with(entries=0)),
        document(segments=fourth_with(entries=3)),
        document(segments=fourth_with(kids=[])),
        document(segments=fourth_with(kids=["decide-1", "custodian-1"])),
        document(segments=fourth_with(kids=["a", "b", "c"])),
        document(segments=fourth_with(end_heads=heads(decide=6))),
        document(segments=fourth_with(end_heads=heads(decide=5, custodian=1))),
        document(
            segments=fourth_with(
                end_heads={"decide": {"seq": 3, "hash": HASH_C}, "custodian": heads(custodian=4)["custodian"]}
            )
        ),
        document(
            segments=fourth_with(end_heads={**heads(decide=4, custodian=3), "decide": {"seq": 4, "hash": "short"}})
        ),
        document(segments=fourth_with(end_heads={**heads(decide=4, custodian=3), "": {"seq": 1, "hash": HASH_E}})),
        document(segments=fourth_with(end_heads={**heads(decide=4), "custodian": {"seq": 3}})),
        document(segments=fourth_with(end_heads={**heads(decide=4), "custodian": {"seq": 2**53, "hash": HASH_D}})),
    ],
)
def test_manifest_refuses_an_invalid_document(bad):
    with pytest.raises(ManifestInvalid):
        Manifest.from_document(bad)


def test_first_segment_without_a_base_is_one():
    with pytest.raises(ManifestInvalid, match="segment must be 1"):
        Manifest(DOCKET_ID, 1).sealed(SegmentEntry(**{**FIRST.__dict__, "segment": 2}))


def test_paths_sit_next_to_the_docket(tmp_path):
    docket = tmp_path / "docket.log"
    assert manifest_path(docket) == tmp_path / "docket.log.manifest"
    assert segment_path(docket, 1) == tmp_path / "docket.log.seg-000000000001"
    assert segment_path(docket, MAX_SEGMENT) == tmp_path / "docket.log.seg-999999999999"


def test_segment_names_sort_in_number_order(tmp_path):
    numbers = [1, 2, 9, 10, 99, 100, 123_456_789, MAX_SEGMENT]
    names = [segment_path(tmp_path / "d", number).name for number in numbers]
    assert sorted(names) == names


@pytest.mark.parametrize("number", [0, -1, MAX_SEGMENT + 1])
def test_segment_path_refuses_numbers_outside_twelve_digits(tmp_path, number):
    with pytest.raises(ValueError):
        segment_path(tmp_path / "d", number)


@pytest.fixture
def path(tmp_path):
    return tmp_path / "docket.log.manifest"


def place(path, content, mode=0o600):
    path.write_bytes(content)
    os.chmod(path, mode)


def test_read_of_a_missing_manifest_is_none(path):
    assert read_manifest(path, uid=UID) is None


def test_read_returns_a_written_manifest(path):
    write_manifest(path, TWO_SEGMENTS)
    assert read_manifest(path, uid=UID) == TWO_SEGMENTS
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600


def test_write_with_a_reader_group_gives_0640_and_the_group(path):
    write_manifest(path, TWO_SEGMENTS, reader_gid=GID)
    info = os.lstat(path)
    assert (stat.S_IMODE(info.st_mode), info.st_gid) == (0o640, GID)
    assert read_manifest(path, uid=UID, reader_gid=GID) == TWO_SEGMENTS
    with pytest.raises(ManifestInvalid, match=f"group {GID + 1000}"):
        read_manifest(path, uid=UID, reader_gid=GID + 1000)


def test_read_refuses_a_symlink(path, tmp_path):
    target = tmp_path / "elsewhere"
    place(target, TWO_SEGMENTS.encode())
    path.symlink_to(target)
    with pytest.raises(ManifestInvalid, match="cannot be opened"):
        read_manifest(path, uid=UID)


def test_read_refuses_another_owner_or_mode(path):
    place(path, TWO_SEGMENTS.encode(), 0o644)
    with pytest.raises(ManifestInvalid, match="0600"):
        read_manifest(path, uid=UID)
    os.chmod(path, 0o600)
    with pytest.raises(ManifestInvalid, match=f"uid {UID + 1}"):
        read_manifest(path, uid=UID + 1)


def test_read_refuses_a_manifest_over_the_cap(path):
    place(path, b" " * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ManifestInvalid, match="larger"):
        read_manifest(path, uid=UID)


@pytest.mark.parametrize(
    "content",
    [b"", b"garbage", b"\xff", b'{"version":1,"version":1}', b"NaN", json.dumps(document(version=2)).encode()],
)
def test_read_refuses_invalid_content(path, content):
    place(path, content)
    with pytest.raises(ManifestInvalid, match="not a valid manifest"):
        read_manifest(path, uid=UID)


def test_write_replaces_the_previous_manifest(path):
    write_manifest(path, Manifest(DOCKET_ID, 6, BASE, (FOURTH,)))
    write_manifest(path, TWO_SEGMENTS)
    assert read_manifest(path, uid=UID) == TWO_SEGMENTS
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_write_refuses_a_manifest_over_the_cap_before_touching_disk(path, monkeypatch):
    write_manifest(path, Manifest(DOCKET_ID, 6, BASE, (FOURTH,)))
    monkeypatch.setattr(manifest_module, "MAX_MANIFEST_BYTES", len(TWO_SEGMENTS.encode()) - 1)
    with pytest.raises(ManifestInvalid, match="larger"):
        write_manifest(path, TWO_SEGMENTS)
    assert read_manifest(path, uid=UID) == Manifest(DOCKET_ID, 6, BASE, (FOURTH,))
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]
