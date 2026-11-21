import hashlib
import json
import os
import threading

import pytest
from test_docket import make_entry
from test_docket_report import WRITERS, Docket

from agent_bailiff.docket import follower as follower_module
from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.follower import (
    CheckpointMismatch,
    DocketFollower,
    LegacyCheckpoint,
    SegmentRemoved,
    load_checkpoint,
    save_checkpoint,
)
from agent_bailiff.docket.manifest import Base, Manifest, SegmentEntry, manifest_path, segment_path, write_manifest
from agent_bailiff.docket.sink import build_kid_index

INDEX = build_kid_index(WRITERS)


class HandlerFailed(Exception):
    pass


@pytest.fixture
def docket(tmp_path):
    path = tmp_path / "docket.log"
    path.touch(mode=0o600)
    return Docket(path)


@pytest.fixture
def checkpoint(tmp_path):
    directory = tmp_path / "follower"
    directory.mkdir(mode=0o700)
    return directory / "checkpoint.json"


def follow(docket, checkpoint, handle, **options):
    return DocketFollower(docket.path, INDEX, checkpoint, handle, **options).run(threading.Event(), follow=False)


def test_handler_sees_each_verified_record_once_across_runs(docket, checkpoint):
    seen = []
    for number in range(1, 4):
        docket.append("decide", make_entry(number))
    assert follow(docket, checkpoint, lambda batch, stop: seen.extend(line.line for line in batch), batch_size=2) == 3
    docket.append("decide", make_entry(4))
    assert follow(docket, checkpoint, lambda batch, stop: seen.extend(line.line for line in batch)) == 1
    assert seen == [1, 2, 3, 4]
    assert load_checkpoint(checkpoint).entries == 4


def test_a_failing_handler_leaves_the_checkpoint_at_the_last_handled_batch(docket, checkpoint):
    for number in range(1, 5):
        docket.append("decide", make_entry(number))
    batches = []

    def handle(batch, stop):
        if batches:
            raise HandlerFailed
        batches.append([line.line for line in batch])

    with pytest.raises(HandlerFailed):
        follow(docket, checkpoint, handle, batch_size=2)
    assert batches == [[1, 2]]
    assert load_checkpoint(checkpoint).entries == 2


def test_batch_size_must_be_positive(docket, checkpoint):
    with pytest.raises(ValueError, match="batch size"):
        DocketFollower(docket.path, INDEX, checkpoint, lambda batch, stop: None, batch_size=0)


def collect(docket, checkpoint, **options):
    seen = []
    follow(docket, checkpoint, lambda batch, stop: seen.extend(line.line for line in batch), **options)
    return seen


def fill(docket, start, stop):
    for number in range(start, stop):
        docket.append("decide", make_entry(number))


def sealed_entry(docket, manifest):
    content = docket.path.read_bytes()
    before = manifest.entries
    records = docket.records[before:]
    return SegmentEntry(
        manifest.active_segment,
        hashlib.sha256(content).hexdigest(),
        len(content),
        before + 1,
        len(records),
        {writer: Head(*head) for writer, head in docket.heads.items()},
        frozenset(record.kid for record in records),
    )


def cut(docket, manifest=None, *, rename=True):
    previous = manifest or Manifest.new()
    sealed = previous.sealed(sealed_entry(docket, previous))
    write_manifest(manifest_path(docket.path), sealed)
    if rename:
        finish_cut(docket, sealed)
    return sealed


def finish_cut(docket, manifest):
    docket.path.rename(segment_path(docket.path, manifest.segments[-1].segment))
    docket.path.touch(mode=0o600)


def test_a_follower_crosses_a_cut_without_a_gap_or_a_duplicate(docket, checkpoint):
    fill(docket, 1, 4)
    assert collect(docket, checkpoint, batch_size=2) == [1, 2, 3]
    fill(docket, 4, 5)
    cut(docket)
    fill(docket, 5, 7)
    assert collect(docket, checkpoint, batch_size=2) == [4, 5, 6]
    saved = load_checkpoint(checkpoint)
    assert (saved.segment, saved.entries, saved.first_hash) == (2, 6, docket.records[4].hash)


def test_a_new_follower_reads_every_segment_in_order(docket, checkpoint):
    fill(docket, 1, 3)
    manifest = cut(docket)
    fill(docket, 3, 5)
    cut(docket, manifest)
    fill(docket, 5, 6)
    assert collect(docket, checkpoint) == [1, 2, 3, 4, 5]
    assert load_checkpoint(checkpoint).segment == 3


def test_an_empty_active_segment_keeps_the_checkpoint_on_the_sealed_one(docket, checkpoint):
    fill(docket, 1, 3)
    cut(docket)
    assert collect(docket, checkpoint) == [1, 2]
    assert (load_checkpoint(checkpoint).segment, load_checkpoint(checkpoint).entries) == (1, 2)
    fill(docket, 3, 4)
    assert collect(docket, checkpoint) == [3]
    assert load_checkpoint(checkpoint).segment == 2


def test_a_cut_between_the_manifest_reads_is_retried(docket, checkpoint, monkeypatch):
    fill(docket, 1, 3)
    cut(docket)
    fill(docket, 3, 4)
    real = follower_module.read_docket_manifest
    calls = []

    def stale_first(path):
        calls.append(path)
        return Manifest.new() if len(calls) == 1 else real(path)

    monkeypatch.setattr(follower_module, "read_docket_manifest", stale_first)
    assert collect(docket, checkpoint) == [1, 2, 3]


def test_a_committed_cut_before_its_rename_waits_for_the_next_pass(docket, checkpoint):
    fill(docket, 1, 3)
    assert collect(docket, checkpoint) == [1, 2]
    fill(docket, 3, 4)
    manifest = cut(docket, rename=False)
    assert collect(docket, checkpoint) == []
    finish_cut(docket, manifest)
    fill(docket, 4, 5)
    assert collect(docket, checkpoint) == [3, 4]


def test_a_follower_behind_a_removed_segment_is_refused(docket, checkpoint):
    fill(docket, 1, 3)
    manifest = cut(docket)
    assert collect(docket, checkpoint) == [1, 2]
    removed = Manifest(manifest.docket_id, manifest.generation + 1, Base(1, 2, manifest.seeds))
    write_manifest(manifest_path(docket.path), removed)
    segment_path(docket.path, 1).unlink()
    with pytest.raises(SegmentRemoved, match="segment 1"):
        collect(docket, checkpoint)


def test_a_new_follower_starts_after_the_removed_segments(docket, checkpoint):
    fill(docket, 1, 3)
    manifest = cut(docket)
    write_manifest(manifest_path(docket.path), Manifest(manifest.docket_id, 2, Base(1, 2, manifest.seeds)))
    segment_path(docket.path, 1).unlink()
    fill(docket, 3, 5)
    assert collect(docket, checkpoint) == [3, 4]


def test_a_sealed_segment_rewritten_in_place_is_refused(docket, checkpoint):
    fill(docket, 1, 3)
    assert collect(docket, checkpoint) == [1, 2]
    cut(docket)
    with open(segment_path(docket.path, 1), "r+b") as stream:
        stream.seek(5)
        stream.write(b"X")
    with pytest.raises(CheckpointMismatch, match="first record"):
        collect(docket, checkpoint)


def test_a_sealed_segment_of_another_size_is_refused(docket, checkpoint):
    fill(docket, 1, 3)
    cut(docket)
    with open(segment_path(docket.path, 1), "ab") as stream:
        stream.write(b"x")
    with pytest.raises(CheckpointMismatch, match="bytes, not the"):
        collect(docket, checkpoint)


def test_a_sealed_segment_that_stops_short_of_its_heads_is_refused(docket, checkpoint):
    fill(docket, 1, 3)
    manifest = cut(docket)
    entry = manifest.segments[0]
    forged = Manifest(
        manifest.docket_id,
        manifest.generation,
        segments=(SegmentEntry(**{**entry.__dict__, "entries": 3, "end_heads": {"decide": Head(3, "A" * 43)}}),),
    )
    write_manifest(manifest_path(docket.path), forged)
    with pytest.raises(CheckpointMismatch, match="heads its manifest entry says"):
        collect(docket, checkpoint)


def legacy_checkpoint(checkpoint, docket):
    saved = load_checkpoint(checkpoint)
    info = os.stat(docket.path)
    save_checkpoint(
        checkpoint,
        LegacyCheckpoint(
            info.st_dev,
            info.st_ino,
            saved.first_hash,
            saved.offset,
            saved.entries,
            saved.last_start,
            saved.last_hash,
            saved.heads,
        ),
    )


@pytest.mark.parametrize("cut_first", [False, True], ids=["before-a-cut", "after-a-cut"])
def test_a_version_1_checkpoint_is_migrated_in_place(docket, checkpoint, cut_first, caplog):
    fill(docket, 1, 3)
    collect(docket, checkpoint)
    legacy_checkpoint(checkpoint, docket)
    fill(docket, 3, 4)
    if cut_first:
        cut(docket)
        fill(docket, 4, 5)
    with caplog.at_level("WARNING", logger="agent_bailiff.docket.follower"):
        seen = collect(docket, checkpoint)
    assert seen == ([3, 4] if cut_first else [3])
    assert json.loads(checkpoint.read_text())["version"] == 2
    assert any("migrated the version 1 checkpoint" in record.getMessage() for record in caplog.records)


def test_a_version_1_checkpoint_of_another_file_is_refused(docket, checkpoint):
    fill(docket, 1, 3)
    collect(docket, checkpoint)
    legacy_checkpoint(checkpoint, docket)
    content = docket.path.read_bytes()
    docket.path.unlink()
    docket.path.write_bytes(content)
    os.chmod(docket.path, 0o600)
    with pytest.raises(CheckpointMismatch, match="not the file"):
        collect(docket, checkpoint)


def test_sealed_segments_are_closed_after_each_pass(docket, checkpoint):
    fill(docket, 1, 3)
    cut(docket)
    fill(docket, 3, 5)
    open_fds = []
    follow(docket, checkpoint, lambda batch, stop: open_fds.append(len(os.listdir("/dev/fd"))), batch_size=2)
    assert len(open_fds) == 2
    assert open_fds[0] == open_fds[1]


def test_an_active_segment_not_yet_created_waits_for_the_next_pass(docket, checkpoint):
    fill(docket, 1, 3)
    cut(docket)
    docket.path.unlink()
    assert collect(docket, checkpoint) == [1, 2]
    docket.path.touch(mode=0o600)
    fill(docket, 3, 4)
    assert collect(docket, checkpoint) == [3]
