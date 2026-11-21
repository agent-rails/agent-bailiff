import asyncio
import json
import os
import platform
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_docket import paths, run_in_sink, token_of, workdir  # noqa: F401

from agent_bailiff.docket.manifest import read_docket_manifest

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_DOCKET_BENCH") != "1",
    reason="set AGENT_BAILIFF_TEST_DOCKET_BENCH=1 to record the docket cut cost",
)

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CUTS = 200


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
        "host": {"machine": platform.machine(), "system": platform.system(), "python": platform.python_version()},
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
