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

from agent_bailiff.docket.archiver import DocketArchiver
from agent_bailiff.docket.manifest import read_docket_manifest
from agent_bailiff.docket.sink import build_kid_index

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_DOCKET_BENCH") != "1",
    reason="set AGENT_BAILIFF_TEST_DOCKET_BENCH=1 to record the docket cut cost",
)

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CUTS = 200
RECORDS = 20_000
SEGMENT_BYTES = 1 << 20


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
