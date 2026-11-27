import json
import os
import statistics
import threading
import time
from datetime import UTC, datetime

import pytest
from test_custodian import NOW
from test_redactor_load_bench import BENCHMARKS, host, percentile

from agent_bailiff.custodian.config import (
    DEFAULT_INFLIGHT_MAX,
    DEFAULT_INFLIGHT_MAX_BYTES,
    DEFAULT_INFLIGHT_PER_TENANT,
    DEFAULT_INFLIGHT_TTL,
)
from agent_bailiff.custodian.inflight import InflightFull, InflightReleases
from agent_bailiff.docket.entry import Entry

bench = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_REDACTOR_BENCH") != "1",
    reason="set AGENT_BAILIFF_TEST_REDACTOR_BENCH=1 to load the in-flight release map",
)

HEADER_VALUE = "Bearer " + "t" * 40
TTL_NS = DEFAULT_INFLIGHT_TTL * 1_000_000_000
THREADS = (1, 4, 16, 64)
OCCUPANCY = (0, DEFAULT_INFLIGHT_MAX // 2)
RUN_SECONDS = 1.0
SWEEP_SIZES = (64, 512, DEFAULT_INFLIGHT_MAX)
SWEEP_REPEATS = 5
ENTRY = Entry(
    entry_id="release",
    trace_id="trace",
    hop="custodian",
    component="custodian-1",
    decision="release",
    at=NOW,
    op_id="op",
)


class Clock:
    def __init__(self):
        self.offset = 0

    def __call__(self):
        return time.monotonic_ns() + self.offset


def default_map(clock, max_entries=DEFAULT_INFLIGHT_MAX):
    return InflightReleases(
        max_entries=max_entries,
        max_bytes=DEFAULT_INFLIGHT_MAX_BYTES,
        per_tenant=max_entries,
        ttl_ns=TTL_NS,
        monotonic_ns=clock,
    )


def fill(releases, prefix, count, tenants=1):
    for number in range(count):
        reservation = releases.reserve(f"{prefix}-{number}", f"tenant-{number % tenants}", HEADER_VALUE)
        releases.commit(reservation, "release", ENTRY)


def contend(threads, occupancy):
    releases = default_map(Clock(), DEFAULT_INFLIGHT_MAX + threads)
    fill(releases, "held", occupancy, tenants=8)
    reserve_us, take_us = [], []
    lock = threading.Lock()
    start = threading.Barrier(threads + 1)
    stop = threading.Event()

    def worker(index):
        local_reserve, local_take = [], []
        start.wait()
        number = 0
        while not stop.is_set():
            key = f"w{index}-{number}"
            began = time.perf_counter_ns()
            reservation = releases.reserve(key, f"tenant-{index % 8}", HEADER_VALUE)
            reserved = time.perf_counter_ns()
            releases.commit(reservation, "release", ENTRY)
            committed = time.perf_counter_ns()
            assert releases.take(key) is not None
            local_reserve.append((reserved - began) / 1e3)
            local_take.append((time.perf_counter_ns() - committed) / 1e3)
            number += 1
        with lock:
            reserve_us.extend(local_reserve)
            take_us.extend(local_take)

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(threads)]
    for item in workers:
        item.start()
    start.wait()
    began = time.perf_counter()
    time.sleep(RUN_SECONDS)
    stop.set()
    for item in workers:
        item.join()
    wall = time.perf_counter() - began
    return {
        "threads": threads,
        "occupancy": occupancy,
        "cycles_per_s": round(len(reserve_us) / wall),
        "reserve_p50_us": percentile(reserve_us, 50),
        "reserve_p99_us": percentile(reserve_us, 99),
        "reserve_max_us": round(max(reserve_us)),
        "take_p50_us": percentile(take_us, 50),
        "take_p99_us": percentile(take_us, 99),
        "take_max_us": round(max(take_us)),
    }


def sweep_burst(size):
    timings = []
    for repeat in range(SWEEP_REPEATS):
        clock = Clock()
        releases = default_map(clock, size + 1)
        fill(releases, f"r{repeat}", size)
        clock.offset += TTL_NS + 1
        began = time.perf_counter_ns()
        releases.reserve("after", "tenant-0", HEADER_VALUE)
        timings.append((time.perf_counter_ns() - began) / 1e6)
        assert len(releases._slots) == 1
    return {
        "expired": size,
        "reserve_median_ms": round(statistics.median(timings), 2),
        "reserve_max_ms": round(max(timings), 2),
    }


def tenants_until_full():
    releases = InflightReleases(
        max_entries=DEFAULT_INFLIGHT_MAX,
        max_bytes=DEFAULT_INFLIGHT_MAX_BYTES,
        per_tenant=DEFAULT_INFLIGHT_PER_TENANT,
        ttl_ns=TTL_NS,
        monotonic_ns=Clock(),
    )
    accepted = []
    for tenant in range(DEFAULT_INFLIGHT_MAX // DEFAULT_INFLIGHT_PER_TENANT + 2):
        count = 0
        try:
            while True:
                reservation = releases.reserve(f"{tenant}-{count}", f"tenant-{tenant}", HEADER_VALUE)
                releases.commit(reservation, "release", ENTRY)
                count += 1
        except InflightFull as full:
            accepted.append({"tenant": tenant, "accepted": count, "refusal": str(full)})
    return accepted


def bytes_cap_entries(value_bytes):
    releases = InflightReleases(
        max_entries=DEFAULT_INFLIGHT_MAX,
        max_bytes=DEFAULT_INFLIGHT_MAX_BYTES,
        per_tenant=DEFAULT_INFLIGHT_MAX,
        ttl_ns=TTL_NS,
        monotonic_ns=Clock(),
    )
    value = "x" * value_bytes
    count = 0
    try:
        while True:
            reservation = releases.reserve(str(count), "tenant-0", value)
            releases.commit(reservation, "release", ENTRY)
            count += 1
    except InflightFull as full:
        return {"value_bytes": value_bytes, "accepted": count, "refusal": str(full)}


@bench
def test_inflight_map_load():
    recorded = host()
    contention = [contend(threads, occupancy) for occupancy in OCCUPANCY for threads in THREADS]
    sweeps = [sweep_burst(size) for size in SWEEP_SIZES]
    tenants = tenants_until_full()
    value_sizes = [bytes_cap_entries(size) for size in (len(HEADER_VALUE), 2048, 4096, 16384)]
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": recorded,
        "measured_at": "InflightReleases in one process, no gRPC; header values of 47 bytes unless stated",
        "defaults": {
            "inflight_max": DEFAULT_INFLIGHT_MAX,
            "inflight_max_bytes": DEFAULT_INFLIGHT_MAX_BYTES,
            "inflight_per_tenant": DEFAULT_INFLIGHT_PER_TENANT,
            "inflight_ttl_s": DEFAULT_INFLIGHT_TTL,
        },
        "contention": (
            f"threads each looping reserve, commit, take for {RUN_SECONDS} s over a map holding `occupancy` "
            "committed entries; times include lock and GIL wait"
        ),
        "contention_results": contention,
        "sweep": "one reserve that sweeps `expired` entries that all expired at once, under the map lock",
        "sweep_results": sweeps,
        "tenants": "tenants filling their quota in turn with the default bounds",
        "tenant_results": tenants,
        "value_bytes": "entries one tenant can hold before the byte bound, by header value size",
        "value_bytes_results": value_sizes,
    }
    assert [item["accepted"] for item in tenants[:-2]] == [DEFAULT_INFLIGHT_PER_TENANT] * (len(tenants) - 2)
    BENCHMARKS.mkdir(exist_ok=True)
    path = BENCHMARKS / f"inflight-load-{now:%Y-%m-%d}.local.json"
    path.write_text(json.dumps(baseline, indent=2) + "\n")
