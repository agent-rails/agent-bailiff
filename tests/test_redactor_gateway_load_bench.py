import json
import os
import subprocess
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import test_agentgateway_e2e
from test_agentgateway_config import gateway_config
from test_agentgateway_e2e import CREDENTIAL_HEADERS, Gateway, free_ports
from test_custodian import NOW
from test_decide import AGENT_KEY, DECIDER_ID, make_root
from test_redactor_load_bench import (
    BENCHMARKS,
    SECRET,
    CountingRedactor,
    calls_per_client,
    host,
    peak_rss_mib,
    percentile,
    receive,
    start_driver,
    stop_driver,
    wait_drained,
)
from test_redactor_load_bench import make_result as make_document

from agent_bailiff.adapters.agentgateway.calls import TOOLS_CALL
from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor, RedactorProcessor
from agent_bailiff.adapters.agentgateway.server import (
    RESPONSE_GRPC_THREADS,
    RESPONSE_MAX_CONCURRENT_RPCS,
    ProcessorServer,
    request_handlers,
    response_server,
)
from agent_bailiff.client import BailiffClient, GatewayError, Holder, NeedsApproval, OutcomeUnknown, Refused, Result
from agent_bailiff.custodian.config import DEFAULT_INFLIGHT_TTL
from agent_bailiff.custodian.echo import MARKER, MAX_RESULT_BYTES
from agent_bailiff.routes import ToolRoute, ToolRoutes

binary = test_agentgateway_e2e.binary
ledger_path = test_agentgateway_e2e.ledger_path
make_custodian = test_agentgateway_e2e.make_custodian
make_decider = test_agentgateway_e2e.make_decider
open_docket = test_agentgateway_e2e.open_docket
private = test_agentgateway_e2e.private
reader = test_agentgateway_e2e.reader
sink = test_agentgateway_e2e.sink
state = test_agentgateway_e2e.state
workdir = test_agentgateway_e2e.workdir
writer = test_agentgateway_e2e.writer

bench = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_REDACTOR_BENCH") != "1" or test_agentgateway_e2e.BINARY is None,
    reason="set AGENT_BAILIFF_TEST_REDACTOR_BENCH=1 and cache agentgateway v1.7.0 to load the redactor through it",
)

ROUTES = ToolRoutes([ToolRoute("deploy", "create_ticket", "deploy.service", "env/staging/api")])
GATEWAY_BODY_HEADROOM = 4096
GATEWAY_BODY_LIMIT = 2 * 1024 * 1024
SIZES = {
    "64KiB": 64 * 1024,
    "1MiB": 1024 * 1024,
    "2MiB": GATEWAY_BODY_LIMIT - GATEWAY_BODY_HEADROOM,
    "4MiB": MAX_RESULT_BYTES - 1024,
}
SHAPES = ("text", "records")
CONCURRENCY = (1, 4, 16, 32, 64)
CLIENT_TIMEOUT_SECONDS = 60
BUDGET = 100
DRIVER_REPLY_SECONDS = 300
DRIVER_EXIT_SECONDS = 30
UPSTREAM_BACKLOG = 256
TTL_NS = (DEFAULT_INFLIGHT_TTL + 1) * 1_000_000_000


class TicketUpstream(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = UPSTREAM_BACKLOG

    def __init__(self):
        super().__init__(("127.0.0.1", 0), TicketHandler)
        self.lock = threading.Lock()
        self.executions = Counter()
        self.result = b"{}"
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"

    def reset(self, result):
        with self.lock:
            self.executions = Counter()
            self.result = result

    def take(self):
        with self.lock:
            return dict(self.executions)

    def stop(self):
        self.shutdown()
        self.server_close()


class TicketHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if "id" not in body:
            self.send_response(202)
            self.end_headers()
            return
        envelope = b'{"jsonrpc":"2.0","id":' + json.dumps(body["id"]).encode() + b',"result":'
        if body["method"] == "tools/call":
            with self.server.lock:
                self.server.executions[body["params"]["arguments"]["ticket"]] += 1
                result = self.server.result
        else:
            result = json.dumps(self.session_result(body)).encode()
        data = envelope + result + b"}"
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def session_result(self, body):
        if body["method"] == "initialize":
            return {
                "protocolVersion": body.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "tickets", "version": "1"},
            }
        if body["method"] == "tools/list":
            return {"tools": [{"name": "create_ticket", "inputSchema": {"type": "object"}}]}
        return {}

    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()


def drive(connection):
    upstream = TicketUpstream()
    connection.send(upstream.url)
    try:
        while (setting := connection.recv()) is not None:
            connection.send(_drive(upstream, setting))
    finally:
        upstream.stop()


def _drive(upstream, setting):
    upstream.reset(make_document(setting["shape"], setting["size"], setting["match"]))
    concurrency = setting["concurrency"]
    per_client = setting["calls_per_client"]
    started = []
    ready = threading.Barrier(concurrency + 1, action=lambda: started.append(time.perf_counter()))
    outcomes = [None] * concurrency

    def client(index):
        root = make_root(budget=BUDGET, task_id=f"{setting['tag']}-{index}")
        instance = BailiffClient(
            setting["url"],
            Holder(root.encode(), (), AGENT_KEY, DECIDER_ID),
            ROUTES,
            timeout=CLIENT_TIMEOUT_SECONDS,
            clock=lambda: NOW,
        )
        try:
            try:
                instance.list_tools()
            except BaseException:
                ready.abort()
                raise
            ready.wait()
            outcomes[index] = [_call(instance, setting, f"{index}-{number}") for number in range(per_client)]
        finally:
            instance.close()

    threads = [threading.Thread(target=client, args=(index,)) for index in range(concurrency)]
    for thread in threads:
        thread.start()
    ready.wait()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - started[0]
    return {"wall_s": wall, "calls": [item for batch in outcomes for item in batch], "executions": upstream.take()}


def _call(instance, setting, ticket):
    began = time.perf_counter_ns()
    try:
        outcome = instance.call("deploy", "create_ticket", {"ticket": ticket})
    except GatewayError:
        return ticket, "gateway_error", (time.perf_counter_ns() - began) / 1e6
    elapsed = (time.perf_counter_ns() - began) / 1e6
    return ticket, _label(outcome, setting["match"]), elapsed


def _label(outcome, match):
    if isinstance(outcome, Result):
        text = json.dumps(outcome.result)
        if SECRET in text or (match and MARKER not in text):
            return "result_wrong"
        return "result"
    if isinstance(outcome, Refused):
        return f"refused:{outcome.reason}"
    if isinstance(outcome, NeedsApproval):
        return "needs_approval"
    if isinstance(outcome, OutcomeUnknown):
        return f"unknown:{outcome.detail}"
    raise AssertionError(f"unexpected outcome {outcome!r}")


class TimedProcessor:
    def __init__(self, inner):
        self.inner = inner
        self.samples = []
        self.lock = threading.Lock()

    def check_request(self, message):
        if message.method != TOOLS_CALL:
            return self.inner.check_request(message)
        began = time.perf_counter_ns()
        try:
            return self.inner.check_request(message)
        finally:
            with self.lock:
                self.samples.append((time.perf_counter_ns() - began) / 1e6)

    def take(self):
        with self.lock:
            samples, self.samples = self.samples, []
        return samples


def summarize(setting, measured, releases, inflight_left, gateway_rss_mib):
    calls = measured["calls"]
    executions = measured["executions"]
    labels = Counter(label for _ticket, label, _elapsed in calls)
    latencies = [elapsed for _ticket, label, elapsed in calls if label == "result"]
    refused_after_acting = [
        ticket for ticket, label, _elapsed in calls if label.startswith("refused:") and ticket in executions
    ]
    unknown = [(ticket, label) for ticket, label, _elapsed in calls if label.startswith("unknown:")]
    return {
        "shape": setting["shape"],
        "size": setting["label"],
        "result_bytes": setting["size"],
        "match": setting["match"],
        "concurrency": setting["concurrency"],
        "calls": len(calls),
        "outcomes": dict(sorted(labels.items())),
        "upstream_executions": sum(executions.values()),
        "duplicate_executions": sum(count - 1 for count in executions.values()),
        "refused_after_acting": len(refused_after_acting),
        "unknown_after_acting": sum(1 for ticket, _label in unknown if ticket in executions),
        "unknown_without_acting": sum(1 for ticket, _label in unknown if ticket not in executions),
        "wall_s": round(measured["wall_s"], 2),
        "throughput_per_s": round(len(latencies) / measured["wall_s"], 1),
        "p50_ms": percentile(latencies, 50),
        "p99_ms": percentile(latencies, 99),
        "release_p50_ms": percentile(releases, 50),
        "release_p99_ms": percentile(releases, 99),
        "inflight_left": inflight_left,
        "peak_rss_mib": peak_rss_mib(),
        "gateway_rss_mib": gateway_rss_mib,
    }


def rss_mib(pid):
    kib = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, check=True).stdout
    return round(int(kib.strip()) / 1024, 1)


def grid(url):
    index = 0
    for shape in SHAPES:
        for label, size in SIZES.items():
            for match in (False, True):
                for concurrency in CONCURRENCY:
                    yield {
                        "shape": shape,
                        "label": label,
                        "size": size,
                        "match": match,
                        "concurrency": concurrency,
                        "calls_per_client": calls_per_client(concurrency),
                        "url": url,
                        "tag": f"bench-{index}",
                    }
                    index += 1


@bench
@pytest.mark.parametrize("workers", [1, 2])
def test_redactor_load_through_agentgateway(binary, workdir, private, make_decider, make_custodian, workers):
    offset = [0]
    custodian = make_custodian(rate_limit=100_000, monotonic_ns=lambda: time.monotonic_ns() + offset[0])
    decide = DecideProcessor(make_decider(), ROUTES, clock=lambda: NOW)
    releases = TimedProcessor(CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW + 1))
    redactor = CountingRedactor(RedactorProcessor(custodian, clock=lambda: NOW + 2))
    sockets = {name: workdir / name[0] / f"{name}.sock" for name in ("decide", "custodian", "redactor")}
    servers = [
        ProcessorServer(request_handlers(decide), sockets["decide"], private("decide-grpc"), gateway_uid=os.geteuid()),
        ProcessorServer(
            request_handlers(releases), sockets["custodian"], private("custodian-grpc"), gateway_uid=os.geteuid()
        ),
        response_server(
            redactor, sockets["redactor"], private("redactor-grpc"), gateway_uid=os.geteuid(), workers=workers
        ),
    ]
    connection = driver = gateway = None
    settings = []
    try:
        for server in servers:
            server.start()
        recorded = host()
        connection, driver = start_driver(drive)
        upstream_url = receive(connection, driver, DRIVER_REPLY_SECONDS)
        config = gateway_config(
            sockets["decide"], sockets["custodian"], upstream_url, sorted(CREDENTIAL_HEADERS), sockets["redactor"]
        )
        admin, stats, readiness, config["mcp"]["port"] = free_ports(4)
        config["config"] = {
            "adminAddr": f"127.0.0.1:{admin}",
            "statsAddr": f"127.0.0.1:{stats}",
            "readinessAddr": f"127.0.0.1:{readiness}",
        }
        expected = GatewayExpectations(
            sockets["decide"], sockets["custodian"], sockets["redactor"], ROUTES.services, frozenset({"Authorization"})
        )
        assert validate_gateway_config(config, expected) == ()
        gateway = Gateway(binary, config, workdir)
        url = f"http://127.0.0.1:{gateway.port}/mcp"
        for setting in grid(url):
            releases.take()
            connection.send(setting)
            measured = receive(connection, driver, DRIVER_REPLY_SECONDS)
            wait_drained(redactor)
            inflight_left = len(custodian._inflight._slots)
            offset[0] += TTL_NS
            custodian._inflight.sweep()
            settings.append(summarize(setting, measured, releases.take(), inflight_left, rss_mib(gateway.process.pid)))
        connection.send(None)
        driver.join(DRIVER_EXIT_SECONDS)
        assert driver.exitcode == 0
    finally:
        if driver is not None:
            stop_driver(connection, driver)
        if gateway is not None:
            gateway.stop()
        for server in servers:
            server.close()
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": recorded,
        "measured_at": (
            "BailiffClient threads in a separate process calling a non-idempotent create_ticket tool through "
            "agentgateway v1.7.0 with decide, custodian and redactor processors; the upstream runs in the client "
            "process and counts each execution by ticket; decide, custodian, redactor and the docket sink share "
            "the test process"
        ),
        "workers": workers,
        "admission_limit": RESPONSE_MAX_CONCURRENT_RPCS,
        "grpc_threads": RESPONSE_GRPC_THREADS,
        "client_timeout_s": CLIENT_TIMEOUT_SECONDS,
        "calls_per_client": {str(concurrency): calls_per_client(concurrency) for concurrency in CONCURRENCY},
        "release": "custodian request processor time per tools/call release (check_request)",
        "inflight_left": "in-flight entries left after the setting drained, swept before the next one",
        "peak_rss": "the processor process's high-water resident set size after the setting (ru_maxrss)",
        "gateway_rss": "agentgateway resident set size after the setting drained (ps rss), not its peak",
        "settings": settings,
    }
    assert not [item for item in settings if item["duplicate_executions"] or item["refused_after_acting"]]
    assert not [item for item in settings if "result_wrong" in item["outcomes"]]
    BENCHMARKS.mkdir(exist_ok=True)
    path = BENCHMARKS / f"redactor-gateway-load-{workers}-worker-{now:%Y-%m-%d}.local.json"
    path.write_text(json.dumps(baseline, indent=2) + "\n")
