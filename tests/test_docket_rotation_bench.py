import asyncio
import json
import os
import platform
import statistics
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_docket import WRITERS, paths, run_in_sink, token_of, workdir  # noqa: F401
from test_docket_removal import fill, run, settle, sink_of, write_receipts

from agent_bailiff.docket import sink as sink_module
from agent_bailiff.docket.archiver import DocketArchiver
from agent_bailiff.docket.manifest import manifest_path, read_docket_manifest
from agent_bailiff.docket.sink import MAX_REMOVALS, build_kid_index

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_DOCKET_BENCH") != "1",
    reason="set AGENT_BAILIFF_TEST_DOCKET_BENCH=1 to record the docket cut cost",
)

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CUTS = 200
RECORDS = 20_000
SEGMENT_BYTES = 1 << 20
REMOVAL_RETAINED = (1, 2000)


def test_docket_cut_cost(paths):  # noqa: F811
    latencies = []

    async def scenario(sink):
        previous = None
        for number in range(1, CUTS + 1):
            record = token_of(number, previous)
            assert sink._append(record.token.encode())["ok"]
            started = time.perf_counter_ns()
            sink._cut()
            latencies.append((time.perf_counter_ns() - started) / 1e6)
            assert not sink._failed
            previous = record.hash
            await asyncio.sleep(0)

    run_in_sink(paths, scenario, segment_bytes=1)
    assert len(read_docket_manifest(paths[0]).segments) == CUTS
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": host(),
        "cuts": CUTS,
        "records_per_segment": 1,
        "cut_ms": {
            "p50": round(statistics.median(latencies), 3),
            "p99": round(statistics.quantiles(latencies, n=100)[98], 3),
            "max": round(max(latencies), 3),
        },
    }
    BENCHMARKS.mkdir(exist_ok=True)
    (BENCHMARKS / f"docket-rotation-{now:%Y-%m-%d}.json").write_text(json.dumps(baseline, indent=2) + "\n")


def host():
    return {"machine": platform.machine(), "system": platform.system(), "python": platform.python_version()}


def test_archiver_throughput_against_appends(paths):  # noqa: F811
    root = paths[0].parent
    for name, mode in (("archive", 0o750), ("receipts", 0o750), ("archiver", 0o700)):
        (root / name).mkdir()
        os.chown(root / name, -1, os.getegid())
        os.chmod(root / name, mode)

    async def scenario(sink):
        previous = None
        started = time.perf_counter()
        for number in range(1, RECORDS + 1):
            record = token_of(number, previous)
            assert sink._append(record.token.encode())["ok"]
            previous = record.hash
            while sink._cut_pending:
                await asyncio.sleep(0)
        return time.perf_counter() - started

    append_seconds = run_in_sink(paths, scenario, segment_bytes=SEGMENT_BYTES, reader_gid=os.getegid())
    manifest = read_docket_manifest(paths[0])
    sealed = sum(entry.entries for entry in manifest.segments)
    archiver = DocketArchiver(
        paths[0],
        build_kid_index(WRITERS),
        root / "archive",
        root / "receipts",
        root / "archiver" / "checkpoint.json",
        device_of=lambda path: -1,
    )
    started = time.perf_counter()
    assert archiver.run(threading.Event(), follow=False) == len(manifest.segments)
    archive_seconds = time.perf_counter() - started
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": host(),
        "records": RECORDS,
        "segment_bytes": SEGMENT_BYTES,
        "sealed_segments": len(manifest.segments),
        "sealed_records": sealed,
        "append_records_per_second": round(RECORDS / append_seconds),
        "archive_records_per_second": round(sealed / archive_seconds),
    }
    BENCHMARKS.mkdir(exist_ok=True)
    (BENCHMARKS / f"docket-archiver-{now:%Y-%m-%d}.json").write_text(json.dumps(baseline, indent=2) + "\n")


def test_removal_pass_loop_stall(workdir, monkeypatch):  # noqa: F811
    writes = []
    original = sink_module.write_manifest

    def timed_write(*args, **options):
        started = time.perf_counter_ns()
        try:
            return original(*args, **options)
        finally:
            writes.append((time.perf_counter_ns() - started) / 1e6)

    monkeypatch.setattr(sink_module, "write_manifest", timed_write)
    passes = []
    for retained in REMOVAL_RETAINED:
        directory = workdir / f"retained-{retained}"
        directory.mkdir()
        os.chmod(directory, 0o700)
        passes.append(removal_pass(directory, retained, writes))
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": host(),
        "removals_per_pass": MAX_REMOVALS,
        "passes": passes,
    }
    BENCHMARKS.mkdir(exist_ok=True)
    (BENCHMARKS / f"docket-removal-{now:%Y-%m-%d}.json").write_text(json.dumps(baseline, indent=2) + "\n")


def removal_pass(directory, retained, writes):
    docket_paths = directory / "docket.log", directory / "s" / "docket.sock"
    receipt_dir = directory / "receipts"
    receipt_dir.mkdir()
    os.chown(receipt_dir, -1, os.getegid())
    os.chmod(receipt_dir, 0o750)

    async def fill_all(sink):
        await fill(sink, MAX_REMOVALS + retained)
        await settle(sink)

    run(sink_of(docket_paths, receipt_dir, 1 << 40), fill_all)
    manifest = read_docket_manifest(docket_paths[0])
    removed = {entry.segment for entry in manifest.segments[:MAX_REMOVALS]}
    write_receipts(docket_paths, receipt_dir, segments=removed)
    cap = sum(entry.size for entry in manifest.segments[MAX_REMOVALS:])
    manifest_bytes = manifest_path(docket_paths[0]).stat().st_size
    writes.clear()
    gaps = []

    async def scenario(sink):
        done = asyncio.Event()

        async def tick():
            while not done.is_set():
                started = time.perf_counter_ns()
                await asyncio.sleep(0)
                gaps.append((time.perf_counter_ns() - started) / 1e6)

        ticker = asyncio.create_task(tick())
        started = time.perf_counter()
        await sink._removal
        seconds = time.perf_counter() - started
        done.set()
        await ticker
        return seconds

    seconds = run(sink_of(docket_paths, receipt_dir, cap), scenario)
    assert len(read_docket_manifest(docket_paths[0]).segments) == retained
    assert len(writes) == MAX_REMOVALS
    return {
        "retained_segments": retained,
        "manifest_bytes_before": manifest_bytes,
        "pass_seconds": round(seconds, 3),
        "write_manifest_ms": quantiles(writes),
        "loop_stall_ms": quantiles(gaps),
    }


def quantiles(samples):
    return {
        "p50": round(statistics.median(samples), 3),
        "p99": round(statistics.quantiles(samples, n=100, method="inclusive")[98], 3),
        "max": round(max(samples), 3),
    }
