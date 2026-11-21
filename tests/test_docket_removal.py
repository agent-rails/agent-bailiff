import asyncio
import errno
import logging
import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest
from test_docket import WRITERS, token_of

from agent_bailiff.docket import DocketCorrupt, DocketSink, repair
from agent_bailiff.docket import sink as sink_module
from agent_bailiff.docket.manifest import read_docket_manifest, segment_path
from agent_bailiff.docket.receipt import Receipt, ReceiptDir
from agent_bailiff.docket.report import RecordFilter, verify_records
from agent_bailiff.docket.retention import MAX_RECEIPT_AGE, MIN_RECEIPT_AGE, Retention
from agent_bailiff.docket.sink import MAX_REMOVALS
from agent_bailiff.docket.state_file import DirectorySyncFailed

NOW = 1795262400
UID = os.geteuid()
GID = os.getegid()


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bf-", dir="/tmp"))
    yield path
    shutil.rmtree(path)


@pytest.fixture
def paths(workdir):
    return workdir / "docket.log", workdir / "s" / "docket.sock"


@pytest.fixture
def receipt_dir(workdir):
    path = workdir / "receipts"
    path.mkdir()
    os.chown(path, -1, GID)
    os.chmod(path, 0o750)
    return path


def retention(receipt_dir, cap):
    return Retention(receipt_dir, UID, cap, 86400)


def sink_of(paths, receipt_dir, cap, **options):
    options.setdefault("wall_clock", lambda: NOW)
    return DocketSink(
        paths[0],
        paths[1],
        WRITERS,
        {UID},
        reader_gid=GID,
        segment_bytes=1,
        retention=retention(receipt_dir, cap),
        **options,
    )


def run(sink, scenario):
    async def body():
        await sink.start()
        try:
            return await scenario(sink)
        finally:
            await sink.close()

    return asyncio.run(body())


async def fill(sink, count, first=1, prev=None):
    for number in range(first, first + count):
        record = token_of(number, prev)
        assert sink._append(record.token.encode())["ok"]
        prev = record.hash
        while sink._cut_pending:
            await asyncio.sleep(0)
    return prev


async def settle(sink):
    while sink._cut_pending or (sink._removal is not None and not sink._removal.done()):
        await asyncio.sleep(0)


async def remove_due(sink):
    await settle(sink)
    sink._start_removal()
    await sink._removal


def write_receipts(paths, receipt_dir, segments=None, verified_at=NOW, **changes):
    manifest = read_docket_manifest(paths[0])
    with ReceiptDir.open(receipt_dir, archiver_uid=UID, reader_gid=GID) as receipts:
        for entry in manifest.segments:
            if segments is not None and entry.segment not in segments:
                continue
            fields = {
                "docket_id": manifest.docket_id,
                "segment": entry.segment,
                "sha256": entry.sha256,
                "size": entry.size,
                "end_heads": entry.end_heads,
                "verified_at": verified_at,
            }
            receipts.write(Receipt(**{**fields, **changes}))


def segment_size(paths):
    return max(entry.size for entry in read_docket_manifest(paths[0]).segments)


def sealed_on_disk(paths):
    return sorted(int(path.name.rsplit("-", 1)[1]) for path in paths[0].parent.glob(f"{paths[0].name}.seg-*"))


def verify(paths):
    return verify_records(paths[0], WRITERS, RecordFilter(), lambda line: None)


def three_segments(paths, receipt_dir):
    async def scenario(sink):
        await fill(sink, 3)
        await settle(sink)

    run(sink_of(paths, receipt_dir, 1 << 30), scenario)
    return segment_size(paths)


def test_segments_over_the_cap_with_fresh_receipts_are_removed(paths, receipt_dir):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir)
    before = read_docket_manifest(paths[0])

    async def scenario(sink):
        await remove_due(sink)

    run(sink_of(paths, receipt_dir, size), scenario)
    manifest = read_docket_manifest(paths[0])
    assert manifest.base.segment == 2
    assert manifest.base.end_heads == before.segments[1].end_heads
    assert manifest.generation == before.generation + 2
    assert [entry.segment for entry in manifest.segments] == [3]
    assert sealed_on_disk(paths) == [3]
    assert verify(paths).ok


def test_removal_runs_at_start(paths, receipt_dir):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir)

    async def scenario(sink):
        await settle(sink)

    run(sink_of(paths, receipt_dir, size), scenario)
    assert sealed_on_disk(paths) == [3]


def test_removal_runs_after_a_cut(paths, receipt_dir):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir, segments={1})

    async def scenario(sink):
        await settle(sink)
        assert sealed_on_disk(paths) == [2, 3]
        write_receipts(paths, receipt_dir, segments={2})
        await fill(sink, 1, 4, read_docket_manifest(paths[0]).seeds["decide"].hash)
        await settle(sink)

    run(sink_of(paths, receipt_dir, 2 * size), scenario)
    assert sealed_on_disk(paths) == [3, 4]


def test_removal_runs_on_its_timer(paths, receipt_dir, monkeypatch):
    size = three_segments(paths, receipt_dir)
    monkeypatch.setattr(sink_module, "REMOVAL_INTERVAL", 0.01)

    async def scenario(sink):
        await settle(sink)
        write_receipts(paths, receipt_dir)
        async with asyncio.timeout(5):
            while sealed_on_disk(paths) != [3]:
                await asyncio.sleep(0.01)

    run(sink_of(paths, receipt_dir, size), scenario)


def test_segments_under_the_cap_are_kept(paths, receipt_dir):
    three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir)

    async def scenario(sink):
        await remove_due(sink)

    run(sink_of(paths, receipt_dir, 1 << 30), scenario)
    assert sealed_on_disk(paths) == [1, 2, 3]


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {"verified_at": NOW - 86401},
        {"verified_at": NOW + 61},
        {"sha256": "0" * 64},
        {"size": 1},
        {"docket_id": "0" * 32},
    ],
    ids=["missing", "stale", "future", "sha256", "size", "docket_id"],
)
def test_a_segment_without_a_matching_fresh_receipt_is_kept(paths, receipt_dir, receipt, caplog):
    size = three_segments(paths, receipt_dir)
    if receipt is not None:
        write_receipts(paths, receipt_dir, **receipt)
    before = read_docket_manifest(paths[0])

    async def scenario(sink):
        await remove_due(sink)

    with caplog.at_level(logging.ERROR):
        run(sink_of(paths, receipt_dir, size), scenario)
    assert read_docket_manifest(paths[0]) == before
    assert sealed_on_disk(paths) == [1, 2, 3]
    assert "over its" in caplog.text


def test_an_unreadable_receipt_keeps_the_segment(paths, receipt_dir, caplog):
    size = three_segments(paths, receipt_dir)
    (receipt_dir / "seg-000000000001.receipt").symlink_to("/dev/null")

    async def scenario(sink):
        await remove_due(sink)

    with caplog.at_level(logging.ERROR):
        run(sink_of(paths, receipt_dir, size), scenario)
    assert sealed_on_disk(paths) == [1, 2, 3]
    assert "receipt for docket segment 1 cannot be read" in caplog.text


def test_one_pass_removes_at_most_the_batch(paths, receipt_dir):
    count = MAX_REMOVALS + 2

    async def fill_all(sink):
        await fill(sink, count)
        await settle(sink)

    run(sink_of(paths, receipt_dir, 1 << 30), fill_all)
    size = segment_size(paths)
    write_receipts(paths, receipt_dir)

    async def scenario(sink):
        await settle(sink)
        assert read_docket_manifest(paths[0]).base.segment == MAX_REMOVALS
        await remove_due(sink)

    run(sink_of(paths, receipt_dir, size), scenario)
    assert sealed_on_disk(paths) == [count]


def test_a_failed_manifest_write_keeps_the_segment_and_is_retried(paths, receipt_dir, monkeypatch, caplog):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir)
    real = sink_module.write_manifest
    calls = []

    def flaky(*args, **kwargs):
        calls.append(args[1].generation)
        if len(calls) == 1:
            raise OSError(errno.ENOSPC, "injected manifest failure")
        real(*args, **kwargs)

    monkeypatch.setattr(sink_module, "write_manifest", flaky)

    async def scenario(sink):
        await settle(sink)
        assert sealed_on_disk(paths) == [1, 2, 3]
        assert not sink._failed
        await remove_due(sink)

    with caplog.at_level(logging.ERROR):
        run(sink_of(paths, receipt_dir, size), scenario)
    assert "docket removal of segment 1 failed; it is retried" in caplog.text
    assert sealed_on_disk(paths) == [3]


def test_a_failed_unlink_is_retried_before_the_next_removal(paths, receipt_dir, caplog):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir)
    sink = sink_of(paths, receipt_dir, size)
    real = sink._unlink_segment
    calls = []

    def flaky(segment):
        calls.append(segment)
        if len(calls) == 1:
            raise OSError(errno.EIO, "injected unlink failure")
        real(segment)

    sink._unlink_segment = flaky

    async def scenario(sink):
        await settle(sink)
        assert read_docket_manifest(paths[0]).base.segment == 1
        assert sealed_on_disk(paths) == [1, 2, 3]
        await remove_due(sink)

    with caplog.at_level(logging.ERROR):
        run(sink, scenario)
    assert calls == [1, 1, 2]
    assert "segment 1 left the manifest but its file was not removed" in caplog.text
    assert sealed_on_disk(paths) == [3]


def test_a_cut_during_an_unlink_keeps_both_changes(paths, receipt_dir):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir, segments={1})
    sink = sink_of(paths, receipt_dir, 3 * size)
    entered = threading.Event()
    release = threading.Event()
    real = sink._unlink_segment

    def blocked(segment):
        entered.set()
        assert release.wait(5)
        real(segment)

    sink._unlink_segment = blocked

    async def scenario(sink):
        await fill(sink, 1, 4, read_docket_manifest(paths[0]).seeds["decide"].hash)
        await asyncio.to_thread(entered.wait, 5)
        while sink._cut_pending:
            await asyncio.sleep(0)
        release.set()
        await settle(sink)

    run(sink, scenario)
    manifest = read_docket_manifest(paths[0])
    assert manifest.base.segment == 1
    assert [entry.segment for entry in manifest.segments] == [2, 3, 4]
    assert sealed_on_disk(paths) == [2, 3, 4]
    assert verify(paths).ok


def test_an_unsynced_removal_stops_removals_and_restart_finishes_it(paths, receipt_dir, monkeypatch, caplog):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir)
    real = sink_module.write_manifest

    def unsynced(*args, **kwargs):
        real(*args, **kwargs)
        raise DirectorySyncFailed(errno.EIO, "injected directory fsync failure")

    monkeypatch.setattr(sink_module, "write_manifest", unsynced)

    async def scenario(sink):
        await remove_due(sink)
        await remove_due(sink)
        return sink._failed

    with caplog.at_level(logging.ERROR):
        assert not run(sink_of(paths, receipt_dir, size), scenario)
    assert "may not be durable; removals stop until restart" in caplog.text
    assert read_docket_manifest(paths[0]).base.segment == 1
    assert sealed_on_disk(paths) == [1, 2, 3]
    monkeypatch.setattr(sink_module, "write_manifest", real)

    async def settled(sink):
        await settle(sink)

    run(sink_of(paths, receipt_dir, size), settled)
    assert sealed_on_disk(paths) == [3]
    assert verify(paths).ok


def faults():
    def manifest_tmp(real):
        def write(*args, **kwargs):
            raise OSError(errno.ENOSPC, "injected before replace")

        return write

    def manifest_dir(real):
        def write(*args, **kwargs):
            real(*args, **kwargs)
            raise DirectorySyncFailed(errno.EIO, "injected after replace")

        return write

    return {"manifest_before_replace": manifest_tmp, "manifest_after_replace": manifest_dir}


@pytest.mark.parametrize("boundary", ["manifest_before_replace", "manifest_after_replace", "unlink", "directory_fsync"])
def test_a_removal_interrupted_at_each_boundary_restarts_to_a_valid_docket(paths, receipt_dir, monkeypatch, boundary):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir, segments={1})
    real = sink_module.write_manifest
    sink = sink_of(paths, receipt_dir, 2 * size)
    if boundary in faults():
        monkeypatch.setattr(sink_module, "write_manifest", faults()[boundary](real))
    else:

        def interrupted(segment):
            if boundary == "directory_fsync":
                os.unlink(segment_path(paths[0], segment))
            raise OSError(errno.EIO, f"injected at {boundary}")

        sink._unlink_segment = interrupted

    async def scenario(sink):
        await settle(sink)

    run(sink, scenario)
    monkeypatch.setattr(sink_module, "write_manifest", real)
    run(sink_of(paths, receipt_dir, 2 * size), scenario)
    manifest = read_docket_manifest(paths[0])
    assert sealed_on_disk(paths) == [entry.segment for entry in manifest.segments]
    assert manifest.first_segment in (1, 2)
    assert verify(paths).ok


def test_restart_refuses_a_removed_segment_that_differs_from_its_receipt(paths, receipt_dir, monkeypatch):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir, segments={1})
    real = sink_module.write_manifest
    monkeypatch.setattr(sink_module, "write_manifest", faults()["manifest_after_replace"](real))

    async def scenario(sink):
        await settle(sink)

    run(sink_of(paths, receipt_dir, 2 * size), scenario)
    monkeypatch.setattr(sink_module, "write_manifest", real)
    with open(segment_path(paths[0], 1), "ab") as segment:
        segment.write(b"x")
    with pytest.raises(DocketCorrupt, match="segment 1 left the manifest"):
        run(sink_of(paths, receipt_dir, 2 * size), scenario)


def test_restart_without_retention_refuses_a_removed_segment(paths, receipt_dir, monkeypatch, workdir):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir, segments={1})
    real = sink_module.write_manifest
    monkeypatch.setattr(sink_module, "write_manifest", faults()["manifest_after_replace"](real))

    async def scenario(sink):
        await settle(sink)

    run(sink_of(paths, receipt_dir, 2 * size), scenario)
    with pytest.raises(DocketCorrupt, match="segment 1 left the manifest"):
        repair(paths[0], workdir / "side", WRITERS, reader_gid=GID)


def test_a_start_finishes_the_removal_before_it_refuses_a_torn_tail_so_repair_can_run(
    paths, receipt_dir, monkeypatch, workdir
):
    size = three_segments(paths, receipt_dir)
    write_receipts(paths, receipt_dir, segments={1})
    real = sink_module.write_manifest
    monkeypatch.setattr(sink_module, "write_manifest", faults()["manifest_after_replace"](real))

    async def scenario(sink):
        await settle(sink)

    run(sink_of(paths, receipt_dir, 2 * size), scenario)
    monkeypatch.setattr(sink_module, "write_manifest", real)
    with open(paths[0], "ab") as docket:
        docket.write(b"torn")
    with pytest.raises(DocketCorrupt, match="torn_tail"):
        run(sink_of(paths, receipt_dir, 2 * size), scenario)
    assert not segment_path(paths[0], 1).exists()
    assert repair(paths[0], workdir / "side", WRITERS, reader_gid=GID).ok
    assert (workdir / "side").read_bytes() == b"torn"


def test_low_free_space_within_the_cap_is_logged(paths, receipt_dir, caplog):
    three_segments(paths, receipt_dir)
    free = [1 << 40]

    def statvfs(fd):
        usage = os.fstatvfs(fd)
        return os.statvfs_result((*usage[:4], free[0] // usage.f_frsize, *usage[5:]))

    async def scenario(sink):
        await settle(sink)
        free[0] = sink._free_space_floor - 1
        await remove_due(sink)

    with caplog.at_level(logging.ERROR):
        run(sink_of(paths, receipt_dir, 1 << 30, statvfs=statvfs), scenario)
    assert "an open reader or another file holds the space" in caplog.text


def test_retention_needs_a_reader_group(paths, receipt_dir):
    with pytest.raises(ValueError, match="reader_gid"):
        DocketSink(paths[0], paths[1], WRITERS, {UID}, segment_bytes=1, retention=retention(receipt_dir, 2))


def test_retained_bytes_must_hold_two_segments(paths, receipt_dir):
    with pytest.raises(ValueError, match="twice segment_bytes"):
        DocketSink(
            paths[0], paths[1], WRITERS, {UID}, reader_gid=GID, segment_bytes=2, retention=retention(receipt_dir, 3)
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"receipt_dir": Path("receipts")}, "absolute"),
        ({"archiver_uid": -1}, "archiver_uid"),
        ({"retained_bytes": 0}, "retained_bytes"),
        ({"max_receipt_age": MIN_RECEIPT_AGE - 1}, "max_receipt_age"),
        ({"max_receipt_age": MAX_RECEIPT_AGE + 1}, "max_receipt_age"),
    ],
)
def test_retention_settings_are_checked(changes, message):
    fields = {"receipt_dir": Path("/receipts"), "archiver_uid": 0, "retained_bytes": 1, "max_receipt_age": 3600}
    with pytest.raises(ValueError, match=message):
        Retention(**{**fields, **changes})


def test_retention_accepts_its_age_bounds():
    for age in (MIN_RECEIPT_AGE, MAX_RECEIPT_AGE):
        assert Retention(Path("/receipts"), 0, 1, age).max_receipt_age == age
