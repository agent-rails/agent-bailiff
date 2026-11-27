import json
import math
import multiprocessing
import os
import platform
import resource
import statistics
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import grpc
import pytest
import test_custodian
from google.protobuf import __version__ as protobuf_version
from test_custodian import DEPLOY_SECRET, NOW, Released

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.processors import CLEARANCE_KEY, RedactorProcessor
from agent_bailiff.adapters.agentgateway.server import (
    RESPONSE_GRPC_THREADS,
    RESPONSE_MAX_CONCURRENT_RPCS,
    response_server,
)
from agent_bailiff.custodian.echo import MARKER, MAX_RESULT_BYTES
from agent_bailiff.signing import token_hash

make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
issue = test_custodian.issue
open_docket = test_custodian.open_docket
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer
ledger_path = test_custodian.ledger_path

bench = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_REDACTOR_BENCH") != "1",
    reason="set AGENT_BAILIFF_TEST_REDACTOR_BENCH=1 to load the response redactor to failure",
)

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CHECK_RESPONSE = "/agentgateway.dev.ext_mcp.ExtMcp/CheckResponse"
SECRET = DEPLOY_SECRET.decode()
GATEWAY_TIMEOUT_SECONDS = 10
ENVELOPE_HEADROOM = 1024
SIZES = {"64KiB": 64 * 1024, "1MiB": 1024 * 1024, "2MiB": 2 * 1024 * 1024, "4MiB": MAX_RESULT_BYTES - ENVELOPE_HEADROOM}
SHAPES = ("text", "records")
CONCURRENCY = (1, 4, 16, 32, 64, 128)
CALLS_PER_SETTING = 32
MIN_CALLS_PER_CLIENT = 2
PROBE_INTERVAL_SECONDS = 0.01
DRAIN_SECONDS = 30
DRIVER_REPLY_SECONDS = 120
DRIVER_POLL_SECONDS = 0.5
DRIVER_EXIT_SECONDS = 30


def calls_per_client(concurrency):
    return max(MIN_CALLS_PER_CLIENT, math.ceil(CALLS_PER_SETTING / concurrency))


def make_result(shape, size, match):
    if shape == "text":
        document = {"content": [{"type": "text", "text": ""}]}
        filler = size - len(json.dumps(document, separators=(",", ":")))
        text = "x" * filler
        if match:
            middle = filler // 2
            text = text[:middle] + SECRET + text[middle + len(SECRET) :]
        document["content"][0]["text"] = text
    else:
        record = {"id": 0, "title": "issue title", "state": "open", "labels": ["bug", "p2"], "body": "y" * 40}
        count = size // (len(json.dumps(record, separators=(",", ":"))) + 8)
        items = [dict(record, id=number) for number in range(count)]
        if match:
            items[count // 2]["body"] = SECRET + "y" * 20
        document = {"content": [{"type": "text", "text": "items"}], "structuredContent": {"items": items}, "pad": ""}
        document["pad"] = "z" * (size - len(json.dumps(document, separators=(",", ":"))))
    raw = json.dumps(document, separators=(",", ":")).encode()
    assert len(raw) == size
    return raw


def drive(connection):
    while (setting := connection.recv()) is not None:
        connection.send(_drive(setting))


def _drive(setting):
    result = make_result(setting["shape"], setting["size"], setting["match"])
    per_client = setting["calls_per_client"]
    options = [("grpc.max_receive_message_length", -1), ("grpc.max_send_message_length", -1)]
    with grpc.insecure_channel(f"unix:{setting['socket']}", options=options) as channel:
        stub = channel.unary_unary(
            CHECK_RESPONSE,
            request_serializer=ext_mcp_pb2.McpResponse.SerializeToString,
            response_deserializer=ext_mcp_pb2.McpResponseResult.FromString,
        )

        def client(index):
            outcomes = []
            for number in range(per_client):
                message = ext_mcp_pb2.McpResponse(method="tools/call", mcp_response=result)
                message.metadata_context.update({CLEARANCE_KEY: setting["clearances"][index * per_client + number]})
                started = time.perf_counter_ns()
                try:
                    answer = stub(message, timeout=GATEWAY_TIMEOUT_SECONDS)
                except grpc.RpcError as error:
                    outcomes.append((error.code().name, (time.perf_counter_ns() - started) / 1e6))
                    continue
                elapsed = (time.perf_counter_ns() - started) / 1e6
                outcomes.append((_verdict(answer, setting["match"]), elapsed))
            return outcomes

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=setting["concurrency"]) as pool:
            outcomes = [item for batch in pool.map(client, range(setting["concurrency"])) for item in batch]
        return {"wall_s": time.perf_counter() - started, "outcomes": outcomes}


def _verdict(answer, match):
    kind = answer.WhichOneof("result")
    if match:
        good = kind == "mutated" and MARKER.encode() in answer.mutated and DEPLOY_SECRET not in answer.mutated
    else:
        good = kind == "pass"
    return "OK" if good else f"WRONG_{kind}"


class CountingRedactor:
    def __init__(self, inner):
        self.inner = inner
        self.active = 0
        self.lock = threading.Lock()

    def check_response(self, message):
        with self.lock:
            self.active += 1
        try:
            return self.inner.check_response(message)
        finally:
            with self.lock:
                self.active -= 1


class Probe:
    def __init__(self):
        self.samples = []
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while True:
            started = time.perf_counter_ns()
            if self.stopping.wait(PROBE_INTERVAL_SECONDS):
                return
            self.samples.append((time.perf_counter_ns() - started) / 1e6 - PROBE_INTERVAL_SECONDS * 1000)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopping.set()
        self.thread.join()


def percentile(values, rank):
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 2)
    return round(statistics.quantiles(values, n=100, method="inclusive")[rank - 1], 2)


def peak_rss_mib():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (1024 * 1024 if platform.system() == "Darwin" else 1024), 1)


def summarize(setting, measured, probe):
    latencies = [elapsed for verdict, elapsed in measured["outcomes"] if verdict == "OK"]
    counts = {}
    for verdict, _elapsed in measured["outcomes"]:
        counts[verdict] = counts.get(verdict, 0) + 1
    calls = len(measured["outcomes"])
    return {
        "shape": setting["shape"],
        "size": setting["label"],
        "result_bytes": setting["size"],
        "match": setting["match"],
        "concurrency": setting["concurrency"],
        "calls": calls,
        "outcomes": dict(sorted(counts.items())),
        "wall_s": round(measured["wall_s"], 2),
        "throughput_per_s": round(len(latencies) / measured["wall_s"], 1),
        "p50_ms": percentile(latencies, 50),
        "p99_ms": percentile(latencies, 99),
        "shed_rate": round(counts.get("RESOURCE_EXHAUSTED", 0) / calls, 3),
        "probe_lag_p50_ms": percentile(probe.samples, 50),
        "probe_lag_p99_ms": percentile(probe.samples, 99),
        "peak_rss_mib": peak_rss_mib(),
    }


def host():
    def sysctl(name):
        return subprocess.run(["sysctl", "-n", name], capture_output=True, text=True).stdout.strip() or None

    return {
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "cpu": sysctl("machdep.cpu.brand_string"),
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
        "grpcio": grpc.__version__,
        "protobuf": protobuf_version,
        "load_average_at_start": [round(value, 2) for value in os.getloadavg()],
    }


def seed(custodian, held, names):
    for name in names:
        reservation = custodian._inflight.reserve(token_hash(name), held.tenant, held.header_value)
        custodian._inflight.commit(reservation, held.release_entry_id, held.entry)


def unseed(custodian, names):
    for name in names:
        custodian._inflight.take(token_hash(name))


def wait_drained(redactor):
    deadline = time.monotonic() + DRAIN_SECONDS
    while redactor.active and time.monotonic() < deadline:
        time.sleep(0.05)
    assert redactor.active == 0


def start_driver(target):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    driver = context.Process(target=target, args=(child,), daemon=True)
    try:
        driver.start()
    except BaseException:
        parent.close()
        raise
    finally:
        child.close()
    return parent, driver


def receive(connection, driver, timeout):
    deadline = time.monotonic() + timeout
    while not connection.poll(DRIVER_POLL_SECONDS):
        if not driver.is_alive():
            raise AssertionError(f"the load driver exited with code {driver.exitcode} before it replied")
        if time.monotonic() > deadline:
            raise AssertionError(f"the load driver sent no result within {timeout} s")
    try:
        return connection.recv()
    except EOFError:
        driver.join(DRIVER_EXIT_SECONDS)
        raise AssertionError(f"the load driver exited with code {driver.exitcode} before it replied") from None


def stop_driver(connection, driver):
    if driver.is_alive():
        driver.kill()
    driver.join()
    connection.close()


def grid(socket_path):
    index = 0
    for shape in SHAPES:
        for label, size in SIZES.items():
            for match in (False, True):
                for concurrency in CONCURRENCY:
                    per_client = calls_per_client(concurrency)
                    yield {
                        "shape": shape,
                        "label": label,
                        "size": size,
                        "match": match,
                        "concurrency": concurrency,
                        "calls_per_client": per_client,
                        "socket": str(socket_path),
                        "clearances": [f"bench-{index}-{number}" for number in range(concurrency * per_client)],
                    }
                    index += 1


def fail_before_replying(connection):
    connection.recv()
    raise RuntimeError("the load driver failed before it replied")


def test_a_load_driver_that_dies_before_replying_fails_the_run():
    parent, driver = start_driver(fail_before_replying)
    try:
        parent.send({})
        started = time.monotonic()
        with pytest.raises(AssertionError, match="exited with code 1 before it replied"):
            receive(parent, driver, DRIVER_REPLY_SECONDS)
        assert time.monotonic() - started < DRIVER_REPLY_SECONDS
    finally:
        stop_driver(parent, driver)


@bench
@pytest.mark.parametrize("workers", [1, 2])
def test_redactor_load(make_custodian, issue, workdir, private, workers):
    custodian = make_custodian(inflight_max=4096, inflight_per_tenant=4096)
    request, token = issue()
    assert isinstance(custodian.release(token, request, NOW + 1), Released)
    held = custodian._inflight.take(token_hash(token))
    redactor = CountingRedactor(RedactorProcessor(custodian, clock=lambda: NOW + 2))
    socket_path = workdir / "s" / "redactor.sock"
    server = response_server(redactor, socket_path, private("redactor-grpc"), gateway_uid=os.geteuid(), workers=workers)
    connection = driver = None
    settings = []
    try:
        server.start()
        recorded = host()
        started_rss = peak_rss_mib()
        with Probe() as idle:
            time.sleep(1)
        connection, driver = start_driver(drive)
        for setting in grid(socket_path):
            seed(custodian, held, setting["clearances"])
            with Probe() as probe:
                connection.send(setting)
                measured = receive(connection, driver, DRIVER_REPLY_SECONDS)
                wait_drained(redactor)
            unseed(custodian, setting["clearances"])
            settings.append(summarize(setting, measured, probe))
        connection.send(None)
        driver.join(DRIVER_EXIT_SECONDS)
        assert driver.exitcode == 0
    finally:
        if driver is not None:
            stop_driver(connection, driver)
        server.close()
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": recorded,
        "measured_at": (
            "a gRPC client in a separate process calling CheckResponse on the redactor socket through the relay, "
            "without agentgateway; RedactorProcessor over a real Custodian, in-flight map and docket sink thread"
        ),
        "workers": workers,
        "admission_limit": RESPONSE_MAX_CONCURRENT_RPCS,
        "grpc_threads": RESPONSE_GRPC_THREADS,
        "deadline_s": GATEWAY_TIMEOUT_SECONDS,
        "calls_per_client": {str(concurrency): calls_per_client(concurrency) for concurrency in CONCURRENCY},
        "probe": (
            f"wake lag past a {PROBE_INTERVAL_SECONDS * 1000:.0f} ms sleep by another thread in the redactor process, "
            "a proxy for how long the scan holds the GIL from the request processor that shares the process"
        ),
        "peak_rss": "the redactor process's high-water resident set size after the setting (ru_maxrss)",
        "peak_rss_before_grid_mib": started_rss,
        "idle_probe_lag_p50_ms": percentile(idle.samples, 50),
        "idle_probe_lag_p99_ms": percentile(idle.samples, 99),
        "settings": settings,
    }
    assert not [item for item in settings if any(key.startswith("WRONG") for key in item["outcomes"])]
    BENCHMARKS.mkdir(exist_ok=True)
    path = BENCHMARKS / f"redactor-load-{workers}-worker-{now:%Y-%m-%d}.local.json"
    path.write_text(json.dumps(baseline, indent=2) + "\n")
