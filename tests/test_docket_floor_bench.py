import json
import os
import platform
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_docket import decide_client, make_entry, paths, start_sink, workdir  # noqa: F401

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_DOCKET_BENCH") != "1",
    reason="set AGENT_BAILIFF_TEST_DOCKET_BENCH=1 to record the docket free-space check cost",
)

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
STATVFS_CALLS = 100_000
APPENDS = 1_000


def statvfs_ns(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        started = time.perf_counter_ns()
        for _ in range(STATVFS_CALLS):
            os.fstatvfs(fd)
        return (time.perf_counter_ns() - started) / STATVFS_CALLS
    finally:
        os.close(fd)


def append_latencies(paths, start_sink, statvfs, first):  # noqa: F811
    handle = start_sink(statvfs=statvfs)
    client = decide_client(paths)
    latencies = []
    for number in range(first, first + APPENDS):
        started = time.perf_counter_ns()
        client.append(make_entry(number))
        latencies.append((time.perf_counter_ns() - started) / 1e6)
    client.close()
    handle.stop()
    return {
        "p50_ms": round(statistics.median(latencies), 3),
        "p99_ms": round(statistics.quantiles(latencies, n=100)[98], 3),
    }


def test_docket_floor_cost(paths, start_sink, workdir):  # noqa: F811
    probe = workdir / "probe"
    probe.write_bytes(b"")
    fixed = os.statvfs(probe)
    with_check = append_latencies(paths, start_sink, os.fstatvfs, 1)
    without_check = append_latencies(paths, start_sink, lambda fd: fixed, APPENDS + 1)
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": {"machine": platform.machine(), "system": platform.system(), "python": platform.python_version()},
        "fstatvfs_ns_per_call": round(statvfs_ns(probe)),
        "fstatvfs_calls": STATVFS_CALLS,
        "appends": APPENDS,
        "append_with_fstatvfs": with_check,
        "append_with_constant_statvfs": without_check,
    }
    BENCHMARKS.mkdir(exist_ok=True)
    (BENCHMARKS / f"docket-floor-{now:%Y-%m-%d}.json").write_text(json.dumps(baseline, indent=2) + "\n")
