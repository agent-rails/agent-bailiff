import base64
import copy
import hashlib
import http.client
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import test_custodian
from test_agentgateway_config import CUSTODIAN, DECIDE, REDACTOR, gateway_config
from test_control import RESOLVER, TRUST_POLICY, MemoryDocket
from test_control_suspension import shared_suspension
from test_custodian import CUSTODIAN_BINDINGS, DEPLOY_SECRET, NOW, docket_entries
from test_custodian_echo import Clock
from test_decide import make_request

from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.agentgateway.processors import (
    CustodianProcessor,
    DecideProcessor,
    RedactorProcessor,
    passed,
)
from agent_bailiff.adapters.agentgateway.server import ProcessorServer, request_handlers, response_server
from agent_bailiff.control import Control, Suspension
from agent_bailiff.custodian.config import DEFAULT_INFLIGHT_TTL
from agent_bailiff.custodian.echo import MARKER
from agent_bailiff.docket import decode_record
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.effector.catalog import Argument
from agent_bailiff.routes import ToolRoute, ToolRoutes

ROOT = Path(__file__).resolve().parent.parent
VERSION = "v1.7.0"
PLATFORMS = {("darwin", "arm64"): "darwin-arm64", ("linux", "x86_64"): "linux-amd64"}
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
AGENT_TOKEN = "Bearer agent-token"
ROUTES = ToolRoutes(
    [
        ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api"),
        ToolRoute("deploy", "deploy_production", "deploy.service", "env/prod/api"),
        ToolRoute("deploy", "deploy_canary", "deploy.canary", "env/staging/api"),
        ToolRoute(
            "deploy",
            "deploy_named",
            "deploy.service",
            "env/{stage}/{service}",
            (Argument("stage", "identifier"), Argument("service", "identifier")),
            strict=False,
        ),
    ]
)
STARTUP_SECONDS = 15
CREDENTIAL_HEADERS = frozenset(binding.header_name for binding in CUSTODIAN_BINDINGS)


def gateway_binary():
    name = PLATFORMS.get((sys.platform, platform.machine()))
    if name is None:
        return None
    cache = os.environ.get("AGENT_BAILIFF_CACHE") or str(
        Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "agent-bailiff"
    )
    path = Path(cache) / "agentgateway" / VERSION / f"agentgateway-{name}"
    return path if path.exists() else None


def pinned_sha256(path):
    pins = dict(
        reversed(line.split("  "))
        for line in (ROOT / "adapters" / "agentgateway" / f"agentgateway-{VERSION}.sha256").read_text().splitlines()
    )
    return pins[path.name]


BINARY = gateway_binary()
pytestmark = pytest.mark.skipif(
    BINARY is None,
    reason="agentgateway v1.7.0 binary not cached; run adapters/agentgateway/scripts/fetch_gateway.sh",
)

ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
open_docket = test_custodian.open_docket
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer


@pytest.fixture(scope="module")
def binary():
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    assert digest == pinned_sha256(BINARY), f"{BINARY} does not match its pinned sha256; refusing to run it"
    return BINARY


class Upstream(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), UpstreamHandler)
        self.requests = []
        self.call_result = {"content": [{"type": "text", "text": "deployed"}]}
        self.call_reply = None
        self.call_stream = None
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"

    def calls(self, method="tools/call"):
        return [dict(headers) for headers in self.raw_calls(method)]

    def raw_calls(self, method="tools/call"):
        with self.lock:
            return [headers for seen, headers in self.requests if seen == method]

    def stop(self):
        self.shutdown()
        self.server_close()


class UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        with self.server.lock:
            headers = [(key.lower(), value) for key, value in self.headers.items()]
            self.server.requests.append((body.get("method"), headers))
        if "id" not in body:
            self.send_response(202)
            self.end_headers()
            return
        if body["method"] == "tools/call" and self.server.call_stream:
            self.stream(self.server.call_stream(body["id"], self.headers["authorization"]))
            return
        if body["method"] == "tools/call" and self.server.call_reply:
            content_type, data = self.server.call_reply(body["id"], self.headers["authorization"])
        else:
            content_type, data = "application/json", self.result(body)
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def stream(self, messages):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        try:
            for message in messages:
                self.wfile.write(f"event: message\ndata: {json.dumps(message)}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def result(self, body):
        results = {
            "initialize": {
                "protocolVersion": body.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-deploy", "version": "1"},
            },
            "tools/list": {"tools": [{"name": "deploy_service", "inputSchema": {"type": "object"}}]},
            "tools/call": self.server.call_result,
        }
        return json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": results.get(body["method"], {})}).encode()

    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()


def free_ports(count):
    probes = [socket.socket() for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


class Gateway:
    def __init__(self, binary, config, directory):
        self.port = config["mcp"]["port"]
        self.config_path = directory / "gateway.json"
        self.config_path.write_text(json.dumps(config))
        self.log_path = directory / "gateway.log"
        with open(self.log_path, "wb") as log:
            self.process = subprocess.Popen([str(binary), "-f", str(self.config_path)], stdout=log, stderr=log)
        deadline = time.monotonic() + STARTUP_SECONDS
        while time.monotonic() < deadline:
            assert self.process.poll() is None, self.log()
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise AssertionError(f"gateway did not listen within {STARTUP_SECONDS}s\n{self.log()}")

    def log(self):
        return self.log_path.read_text(errors="replace")

    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(10)


class Agent:
    def __init__(self, port):
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.session = None
        self.next_id = 1
        status, body = self.post(
            {
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "agent", "version": "1"},
                },
            }
        )
        assert status == 200 and "result" in body, body
        self.post({"method": "notifications/initialized"}, notify=True)

    def call(self, name, arguments, headers):
        return self.post({"method": "tools/call", "params": {"name": name, "arguments": arguments}}, headers)

    def post(self, message, headers=None, notify=False):
        message = {"jsonrpc": "2.0", **message}
        if not notify:
            message["id"] = self.next_id
            self.next_id += 1
        return self.send(message, headers)

    def send(self, message, headers=None):
        status, text = self.exchange(message, headers)
        return status, _json_rpc(text)

    def exchange(self, message, headers=None):
        request_headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-06-18",
            **(headers or {}),
        }
        if self.session:
            request_headers["mcp-session-id"] = self.session
        request = urllib.request.Request(self.url, json.dumps(message).encode(), request_headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                self.session = response.headers.get("mcp-session-id") or self.session
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()


def _json_rpc(text):
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    if not text.strip():
        return {}
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


def agent_headers(request):
    headers = {
        "x-bailiff-task-root": request.task_root,
        "x-bailiff-leaf-proof": request.leaf_proof,
        "x-bailiff-nonce": request.nonce,
        "traceparent": f"00-{TRACE}-00f067aa0ba902b7-01",
        "authorization": AGENT_TOKEN,
        "proxy-authorization": AGENT_TOKEN,
        "cookie": "session=agent",
    }
    if request.links:
        headers["x-bailiff-links"] = ",".join(request.links)
    return headers


@pytest.fixture
def stack_options():
    return {}


@pytest.fixture
def stack(binary, workdir, private, make_decider, make_custodian, stack_options):
    upstream = Upstream()
    custodian = make_custodian(monotonic_ns=stack_options.get("monotonic_ns"))
    sockets = {
        "decide": workdir / "d" / "decide.sock",
        "custodian": workdir / "c" / "custodian.sock",
        "redactor": workdir / "c" / "redactor.sock",
    }
    servers = {
        "decide": ProcessorServer(
            request_handlers(DecideProcessor(make_decider(), ROUTES, clock=lambda: NOW)),
            sockets["decide"],
            private("decide-grpc"),
            gateway_uid=os.geteuid(),
        ),
        "custodian": ProcessorServer(
            request_handlers(CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW + 1)),
            sockets["custodian"],
            private("custodian-grpc"),
            gateway_uid=os.geteuid(),
        ),
        "redactor": response_server(
            RedactorProcessor(custodian, clock=lambda: NOW + 2),
            sockets["redactor"],
            private("redactor-grpc"),
            gateway_uid=os.geteuid(),
        ),
    }
    for server in servers.values():
        server.start()
    config = gateway_config(
        sockets["decide"], sockets["custodian"], upstream.url, sorted(CREDENTIAL_HEADERS), sockets["redactor"]
    )
    if "timeout" in stack_options:
        config["mcp"]["policies"]["timeout"] = stack_options["timeout"]
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
    try:
        yield {
            "agent": Agent(gateway.port),
            "upstream": upstream,
            "servers": servers,
            "gateway": gateway,
            "config": config,
            "expected": expected,
        }
    finally:
        gateway.stop()
        for server in servers.values():
            server.close()
        upstream.stop()


def refused(body, reason):
    return body.get("result") == {"content": [{"type": "text", "text": reason}], "isError": True}


def test_an_allowed_call_gets_the_credential_header_and_a_joined_docket_trace(stack, workdir):
    request = make_request()
    status, body = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    assert status == 200 and body.get("result", {}).get("content") == [{"type": "text", "text": "deployed"}], body
    [headers] = stack["upstream"].calls()
    assert headers["authorization"] == DEPLOY_SECRET.decode()
    assert not [name for name in headers if name.startswith("x-bailiff-")]
    assert "proxy-authorization" not in headers and "cookie" not in headers
    assert AGENT_TOKEN not in headers.values()
    entries = docket_entries(workdir)
    [allow] = [entry for entry in entries if entry.hop == "decide" and entry.decision == "allow"]
    [release] = [entry for entry in entries if entry.hop == "custodian" and entry.decision == "release"]
    assert release.parent_entry == allow.entry_id
    assert (allow.trace_id, allow.op_id) == (TRACE, release.op_id)
    assert release.trace_id == TRACE
    assert release.credential_tier == "gateway-bound"
    assert DEPLOY_SECRET.decode() not in stack["gateway"].log()


def test_an_echoed_credential_is_redacted_before_the_agent_sees_it(stack, workdir):
    echo = f"token {DEPLOY_SECRET.decode()} and {base64.b64encode(DEPLOY_SECRET).decode()}"
    stack["upstream"].call_result = {"content": [{"type": "text", "text": echo}]}
    request = make_request()
    status, body = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    assert status == 200, body
    [content] = body["result"]["content"]
    assert content["text"].startswith(f"token {MARKER} and {MARKER}"), body
    assert DEPLOY_SECRET.decode() not in json.dumps(body)
    assert base64.b64encode(DEPLOY_SECRET).decode() not in json.dumps(body)
    entries = docket_entries(workdir)
    [release] = [entry for entry in entries if entry.hop == "custodian" and entry.decision == "release"]
    [alert] = [entry for entry in entries if entry.decision == "alert"]
    assert (alert.reason, alert.parent_entry, alert.op_id) == ("credential_echo", release.entry_id, release.op_id)


def test_a_result_without_an_echo_reaches_the_agent_unchanged(stack):
    request = make_request()
    status, body = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    assert status == 200 and body["result"] == {"content": [{"type": "text", "text": "deployed"}]}, body


def stream_events(text):
    return [json.loads(line[len("data: ") :]) for line in text.splitlines() if line.startswith("data: ")]


def event_stream(*messages):
    return "text/event-stream", "".join(
        f"event: message\ndata: {json.dumps(message)}\n\n" for message in messages
    ).encode()


def deployed(call_id):
    return {"jsonrpc": "2.0", "id": call_id, "result": {"content": [{"type": "text", "text": "deployed"}]}}


def error_echoing(call_id, credential):
    error = {"code": -32000, "message": f"upstream rejected {credential}"}
    return "application/json", json.dumps({"jsonrpc": "2.0", "id": call_id, "error": error}).encode()


SIDE_MESSAGES = {
    "notification": lambda credential: {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"level": "info", "data": f"using {credential}"},
    },
    "server_request": lambda credential: {
        "jsonrpc": "2.0",
        "id": "s-1",
        "method": "elicitation/create",
        "params": {"message": f"confirm {credential}", "requestedSchema": {"type": "object", "properties": {}}},
    },
}


def alerts(workdir):
    return [entry for entry in docket_entries(workdir) if entry.decision == "alert"]


def call_access_line(gateway):
    deadline = time.monotonic() + 5
    while True:
        lines = [
            line
            for line in gateway.log().splitlines()
            if f"trace.id={TRACE} " in line and " mcp.method.name=tools/call " in line
        ]
        if lines or time.monotonic() > deadline:
            assert len(lines) == 1, gateway.log()
            return lines[0]
        time.sleep(0.05)


def record_redactor_calls(monkeypatch):
    seen = []
    check_response = RedactorProcessor.check_response

    def recording(processor, message):
        seen.append(message.method)
        return check_response(processor, message)

    monkeypatch.setattr(RedactorProcessor, "check_response", recording)
    return seen


def test_an_echo_in_a_json_rpc_error_reaches_a_direct_client_but_not_the_access_log(stack, workdir, monkeypatch):
    redacted = record_redactor_calls(monkeypatch)
    stack["upstream"].call_reply = error_echoing
    request = make_request()
    status, body = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    echo = f"upstream rejected {DEPLOY_SECRET.decode()}"
    assert status == 200 and body["error"] == {"code": -32000, "message": echo}, body
    assert redacted == []
    line = call_access_line(stack["gateway"])
    assert "mcp.error.message" not in line and DEPLOY_SECRET.decode() not in line, line
    assert alerts(workdir) == []


def gateway_log_after_error_echo(stack, binary, directory, config):
    admin, stats, readiness, config["mcp"]["port"] = free_ports(4)
    config["config"].update(
        {
            "adminAddr": f"127.0.0.1:{admin}",
            "statsAddr": f"127.0.0.1:{stats}",
            "readinessAddr": f"127.0.0.1:{readiness}",
        }
    )
    directory.mkdir()
    gateway = Gateway(binary, config, directory)
    try:
        stack["upstream"].call_reply = error_echoing
        request = make_request()
        _, body = Agent(gateway.port).call("deploy_service", request.args, agent_headers(request))
        assert body.get("error", {}).get("message") == f"upstream rejected {DEPLOY_SECRET.decode()}", body
        deadline = time.monotonic() + 5
        while TRACE not in gateway.log() and time.monotonic() < deadline:
            time.sleep(0.05)
        return gateway.log()
    finally:
        gateway.stop()


def test_without_the_access_log_removal_the_gateway_logs_the_error_echo(stack, binary, workdir):
    config = copy.deepcopy(stack["config"])
    del config["frontendPolicies"]
    assert any("frontendPolicies" in problem for problem in validate_gateway_config(config, stack["expected"]))
    log = gateway_log_after_error_echo(stack, binary, workdir / "unfiltered", config)
    field = f'mcp.error.message="upstream rejected {DEPLOY_SECRET.decode()}"'
    assert log.count(DEPLOY_SECRET.decode()) == 1 and field in log, log


def test_a_json_access_log_also_drops_the_error_echo(stack, binary, workdir):
    config = copy.deepcopy(stack["config"])
    config["config"]["logging"] = {"format": "json"}
    assert validate_gateway_config(config, stack["expected"]) == ()
    log = gateway_log_after_error_echo(stack, binary, workdir / "json", config)
    calls = [line for line in log.splitlines() if TRACE in line and "tools/call" in line]
    assert len(calls) == 1 and calls[0].lstrip().startswith("{"), log
    assert "mcp.error.message" not in log and DEPLOY_SECRET.decode() not in log, log


@pytest.mark.parametrize("kind", sorted(SIDE_MESSAGES))
def test_an_echo_in_an_event_stream_side_message_reaches_a_direct_client(stack, workdir, monkeypatch, kind):
    redacted = record_redactor_calls(monkeypatch)
    stack["upstream"].call_reply = lambda call_id, credential: event_stream(
        SIDE_MESSAGES[kind](credential), deployed(call_id)
    )
    request = make_request()
    call = {"method": "tools/call", "params": {"name": "deploy_service", "arguments": request.args}}
    status, text = stack["agent"].exchange({"jsonrpc": "2.0", "id": 7, **call}, agent_headers(request))
    side, result = stream_events(text)
    expected = SIDE_MESSAGES[kind](DEPLOY_SECRET.decode())
    assert status == 200 and DEPLOY_SECRET.decode() in json.dumps(side), text
    assert redacted == ["tools/call"]
    assert side["method"] == expected["method"], text
    assert {key: side["params"][key] for key in expected["params"]} == expected["params"], text
    assert result == deployed(7)
    assert DEPLOY_SECRET.decode() not in call_access_line(stack["gateway"])
    assert alerts(workdir) == []


SHORT_TIMEOUTS = {"requestTimeout": "1s", "backendRequestTimeout": "1s"}
IDLE_TIMEOUTS = {**SHORT_TIMEOUTS, "responseIdleTimeout": "1s"}
SILENCE_SECONDS = 2.5


def progress(step):
    return {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "p-1", "progress": step}}


def stream_call(stack, messages):
    stack["upstream"].call_stream = messages
    request = make_request()
    params = {"name": "deploy_service", "arguments": request.args, "_meta": {"progressToken": "p-1"}}
    return stack["agent"].exchange(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}, agent_headers(request)
    )


def silent_then_deployed(call_id, credential):
    time.sleep(SILENCE_SECONDS)
    yield deployed(call_id)


def progress_then_silent(call_id, credential):
    yield progress(1)
    time.sleep(SILENCE_SECONDS)
    yield deployed(call_id)


@pytest.mark.parametrize("stack_options", [{"timeout": SHORT_TIMEOUTS}])
def test_upstream_timeouts_do_not_bound_an_event_stream_body_after_its_headers(stack):
    status, text = stream_call(stack, silent_then_deployed)
    assert status == 200 and stream_events(text) == [deployed(7)], text


@pytest.mark.parametrize("stack_options", [{"timeout": IDLE_TIMEOUTS}])
def test_a_response_idle_timeout_cuts_a_silent_event_stream_after_the_upstream_acted(stack):
    started = time.monotonic()
    with pytest.raises(http.client.IncompleteRead) as cut:
        stream_call(stack, progress_then_silent)
    assert 1 <= time.monotonic() - started < SILENCE_SECONDS
    assert stream_events(cut.value.partial.decode()) == [progress(1.0)]
    assert len(stack["upstream"].calls()) == 1


@pytest.mark.parametrize("stack_options", [{"timeout": IDLE_TIMEOUTS}])
def test_a_response_idle_timeout_does_not_bound_an_event_stream_that_keeps_sending(stack):
    steps = 8

    def chatty_then_deployed(call_id, credential):
        for step in range(steps):
            yield progress(step)
            time.sleep(0.4)
        yield deployed(call_id)

    started = time.monotonic()
    status, text = stream_call(stack, chatty_then_deployed)
    assert time.monotonic() - started >= 3
    assert status == 200 and stream_events(text) == [*map(progress, map(float, range(steps))), deployed(7)], text


CUSTODIAN_CLOCK = Clock()


@pytest.mark.parametrize("stack_options", [{"monotonic_ns": CUSTODIAN_CLOCK}])
def test_a_stream_result_after_inflight_ttl_fails_as_unmatched_after_the_upstream_acted(stack, workdir):
    def deployed_after_ttl(call_id, credential):
        yield progress(1)
        CUSTODIAN_CLOCK.now += (DEFAULT_INFLIGHT_TTL + 1) * 1_000_000_000
        yield deployed(call_id)

    status, text = stream_call(stack, deployed_after_ttl)
    unmatched = {"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "response_unmatched"}}
    assert status == 200 and stream_events(text) == [progress(1.0), unmatched], text
    assert len(stack["upstream"].calls()) == 1
    assert [(entry.hop, entry.decision) for entry in docket_entries(workdir)] == [
        ("decide", "allow"),
        ("custodian", "release"),
    ]


@pytest.mark.parametrize("meta", [{"progressToken": 2}, {"progressToken": "p-1"}])
def test_a_call_with_spec_meta_is_released(stack, meta):
    request = make_request()
    params = {"name": "deploy_service", "arguments": request.args, "_meta": meta}
    status, body = stack["agent"].post({"method": "tools/call", "params": params}, agent_headers(request))
    assert body.get("result", {}).get("content") == [{"type": "text", "text": "deployed"}], body
    [headers] = stack["upstream"].calls()
    assert headers["authorization"] == DEPLOY_SECRET.decode()


def test_a_call_with_unknown_meta_is_refused_and_reaches_no_upstream(stack):
    request = make_request()
    params = {"name": "deploy_service", "arguments": request.args, "_meta": {"dangerousMode": "yes"}}
    status, body = stack["agent"].post({"method": "tools/call", "params": params}, agent_headers(request))
    assert refused(body, "malformed_request"), body
    assert stack["upstream"].calls() == []


def test_an_out_of_scope_call_is_refused_and_reaches_no_upstream(stack):
    request = make_request(resource="env/prod/api")
    status, body = stack["agent"].call("deploy_production", request.args, agent_headers(request))
    assert refused(body, "out_of_scope"), body
    assert stack["upstream"].calls() == []


def test_a_templated_route_takes_its_resource_from_the_arguments(stack):
    arguments = {"stage": "staging", "service": "api", "replicas": 2}
    request = make_request(resource="env/staging/api", args=arguments)
    status, body = stack["agent"].call("deploy_named", arguments, agent_headers(request))
    assert body.get("result", {}).get("content") == [{"type": "text", "text": "deployed"}], body
    assert len(stack["upstream"].calls()) == 1


def test_a_templated_route_naming_another_resource_is_refused_and_reaches_no_upstream(stack):
    arguments = {"stage": "prod", "service": "api", "replicas": 2}
    request = make_request(resource="env/prod/api", args=arguments)
    status, body = stack["agent"].call("deploy_named", arguments, agent_headers(request))
    assert refused(body, "out_of_scope"), body
    assert stack["upstream"].calls() == []


def test_a_templated_route_with_a_bad_argument_is_malformed_and_reaches_no_upstream(stack):
    arguments = {"stage": "..", "service": "api", "replicas": 2}
    request = make_request(resource="env/staging/api", args=arguments)
    status, body = stack["agent"].call("deploy_named", arguments, agent_headers(request))
    assert refused(body, "malformed_request"), body
    assert stack["upstream"].calls() == []


def test_a_replayed_call_is_refused_and_reaches_the_upstream_once(stack):
    request = make_request()
    first = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    second = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    assert "result" in first[1] and not first[1]["result"].get("isError"), first
    assert refused(second[1], "already_issued"), second
    assert len(stack["upstream"].calls()) == 1


def test_a_custodian_refusal_after_decide_allows_reaches_no_upstream(stack, workdir):
    request = make_request(tool="deploy.canary")
    status, body = stack["agent"].call("deploy_canary", request.args, agent_headers(request))
    assert refused(body, "release_refused"), body
    assert stack["upstream"].calls() == []
    entries = docket_entries(workdir)
    assert [entry.decision for entry in entries if entry.hop == "decide"] == ["allow"]
    assert [entry.reason for entry in entries if entry.hop == "custodian"] == ["canary", "canary"]


BLOCKED = {
    "prompts/get": ({"name": "p"}, -32001, "method_refused"),
    "resources/read": ({"uri": "file:///r"}, -32001, "method_refused"),
    "prompts/list": ({}, -32001, "method_refused"),
    "resources/list": ({}, -32001, "method_refused"),
    "logging/setLevel": ({"level": "info"}, -32001, "method_refused"),
    "resources/subscribe": ({"uri": "file:///r"}, -32602, "unknown resource"),
    "completion/complete": (
        {"ref": {"type": "ref/prompt", "name": "p"}, "argument": {"name": "a", "value": "b"}},
        -32602,
        "unknown resource",
    ),
    "tasks/get": ({"taskId": "deploy/t1"}, -32602, "unknown resource"),
}


@pytest.mark.parametrize("method", sorted(BLOCKED))
def test_methods_outside_the_allowlist_never_reach_the_upstream(stack, method):
    params, code, message = BLOCKED[method]
    status, body = stack["agent"].post({"method": method, "params": params}, {"authorization": AGENT_TOKEN})
    assert body.get("error") == {"code": code, "message": message}, body
    assert stack["upstream"].calls(method) == []


def test_tools_list_reaches_the_upstream(stack):
    status, body = stack["agent"].post({"method": "tools/list"})
    assert body["result"]["tools"][0]["name"] == "deploy_service", body
    assert len(stack["upstream"].calls("tools/list")) == 1


EXTRA_AGENT_HEADERS = {"sudo": "root", "x-forwarded-user": "admin", "x-bailiff-extra": "1"}
UPSTREAM_VISIBLE = {"accept", "content-type", "mcp-protocol-version", "traceparent", "tracestate"}
GATEWAY_SET = {"host", "content-length", "accept-encoding", "mcp-method", "mcp-name"}


HOSTILE_HEADERS = [
    ("Sudo", b"root"),
    ("sudo", b"again"),
    ("x-forwarded-user", b"admin"),
    ("X-Dup", b"1"),
    ("x-dup", b"2"),
    ("x-bin", b"\xff\xfe"),
    ("tracestate", b"vendor=1"),
    ("tracestate", b"vendor=2"),
    ("content-type", b"text/evil"),
]


def send_raw(agent, message, pairs):
    url = urllib.parse.urlsplit(agent.url)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=15)
    try:
        connection.putrequest("POST", url.path, skip_accept_encoding=True)
        body = json.dumps({"jsonrpc": "2.0", "id": 99, **message}).encode()
        base = [
            ("content-type", b"application/json"),
            ("accept", b"application/json, text/event-stream"),
            ("mcp-protocol-version", b"2025-06-18"),
            ("content-length", str(len(body)).encode()),
        ]
        for key, value in base + pairs:
            connection.putheader(key, value)
        connection.endheaders(body)
        return connection.getresponse().status
    finally:
        connection.close()


@pytest.mark.parametrize("method", ["tools/call", "tools/list"])
def test_only_allowlisted_agent_headers_reach_the_upstream(stack, method):
    request = make_request()
    chain = [(key, value.encode()) for key, value in agent_headers(request).items()]
    if method == "tools/call":
        message = {"method": method, "params": {"name": "deploy_service", "arguments": request.args}}
    else:
        message = {"method": method}
    assert send_raw(stack["agent"], message, chain + HOSTILE_HEADERS) == 200
    [seen] = stack["upstream"].raw_calls(method)
    released = {"authorization"} if method == "tools/call" else set()
    assert {key for key, _ in seen} <= UPSTREAM_VISIBLE | GATEWAY_SET | released, seen
    assert dict(seen)["content-type"] == "application/json"


def test_check_config_refuses_a_stateful_gateway_the_gateway_itself_accepts(stack, binary, workdir):
    config = copy.deepcopy(stack["config"])
    config["mcp"]["statefulMode"] = "stateful"
    path = workdir / "stateful.json"
    path.write_text(json.dumps(config))
    accepted = subprocess.run([str(binary), "--validate-only", "-f", str(path)], capture_output=True, text=True)
    assert accepted.returncode == 0 and "valid" in accepted.stdout, accepted
    assert any("statefulMode" in problem for problem in validate_gateway_config(config, stack["expected"]))


def test_a_notification_reaches_the_upstream_without_agent_credentials(stack):
    request = make_request()
    status, body = stack["agent"].post(
        {"method": "notifications/roots/list_changed"}, agent_headers(request), notify=True
    )
    assert status == 202
    [headers] = stack["upstream"].calls("notifications/roots/list_changed")
    assert not {"authorization", "proxy-authorization", "cookie"} & set(headers)
    assert headers["x-bailiff-nonce"] == request.nonce


def batch_of(*messages):
    return [{"jsonrpc": "2.0", "id": 100 + index, **message} for index, message in enumerate(messages)]


@pytest.mark.parametrize("name", ["read_and_list", "call_without_proof_and_list", "call_with_proof_and_list"])
def test_the_gateway_rejects_json_rpc_batches_before_any_upstream_call(stack, workdir, name):
    request = make_request()
    call = {"method": "tools/call", "params": {"name": "deploy_service", "arguments": request.args}}
    batches = {
        "read_and_list": (
            batch_of({"method": "resources/read", "params": {"uri": "file:///r"}}, {"method": "tools/list"}),
            {},
        ),
        "call_without_proof_and_list": (batch_of(call, {"method": "tools/list"}), {"authorization": AGENT_TOKEN}),
        "call_with_proof_and_list": (batch_of(call, {"method": "tools/list"}), agent_headers(request)),
    }
    payload, headers = batches[name]
    status, body = stack["agent"].send(payload, headers)
    assert (status, body) == (400, {"text": "fail to deserialize request body: unrecognized JSON-RPC message"})
    with stack["upstream"].lock:
        methods = [method for method, _ in stack["upstream"].requests]
    assert set(methods) <= {"initialize", "notifications/initialized"}, methods
    assert [entry for entry in docket_entries(workdir) if entry.decision in ("allow", "release")] == []


def test_an_unreachable_custodian_fails_closed(stack):
    stack["servers"]["custodian"].close()
    request = make_request()
    status, body = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    assert body.get("error") == {"code": -32603, "message": "guardrail check failed"}, body
    assert stack["upstream"].calls() == []


def test_a_call_without_chain_headers_is_refused(stack):
    status, body = stack["agent"].call("deploy_service", {"service": "api"}, {"authorization": AGENT_TOKEN})
    assert refused(body, "malformed_request"), body
    assert stack["upstream"].calls() == []


UNSAFE = {
    "fail_open": lambda policies, processors: processors[CUSTODIAN].update(failureMode="failOpen"),
    "no_header_allowlist": lambda policies, processors: processors[DECIDE].pop("requestHeaders"),
    "custodian_header_filter": lambda policies, processors: processors[CUSTODIAN].update(
        requestHeaders={"allowed": ["x-bailiff-nonce"]}
    ),
    "custodian_before_decide": lambda policies, processors: processors.insert(DECIDE, processors.pop(CUSTODIAN)),
    "custodian_over_tcp": lambda policies, processors: processors[CUSTODIAN].update(host="127.0.0.1:9"),
    "tools_call_only": lambda policies, processors: processors[DECIDE].update(methods={"tools/call": "request"}),
    "redactor_after_guard": lambda policies, processors: processors.append(processors.pop(REDACTOR)),
    "redactor_fail_open": lambda policies, processors: processors[REDACTOR].update(failureMode="failOpen"),
    "redactor_on_every_method": lambda policies, processors: processors[REDACTOR].update(methods={"*": "response"}),
    "no_upstream_timeout": lambda policies, processors: policies.pop("timeout"),
    "no_method_rule": lambda policies, processors: policies.pop("mcpAuthorization"),
    "header_modifier_sets": lambda policies, processors: policies["requestHeaderModifier"].update(set={"x-a": "1"}),
    "chain_headers_stripped": lambda policies, processors: policies["requestHeaderModifier"]["remove"].append(
        "x-bailiff-leaf-proof"
    ),
}


@pytest.mark.parametrize("name", sorted(UNSAFE))
def test_check_config_refuses_unsafe_configs_the_gateway_itself_accepts(stack, binary, workdir, name):
    config = copy.deepcopy(stack["config"])
    policies = config["mcp"]["policies"]
    UNSAFE[name](policies, policies["mcpGuardrails"]["processors"])
    path = workdir / f"{name}.json"
    path.write_text(json.dumps(config))
    accepted = subprocess.run([str(binary), "--validate-only", "-f", str(path)], capture_output=True, text=True)
    assert accepted.returncode == 0 and "valid" in accepted.stdout, accepted
    assert validate_gateway_config(config, stack["expected"])


def allow_record_line(workdir):
    index = build_kid_index(test_custodian.WRITERS)
    for line in (workdir / "docket.log").read_text().splitlines():
        entry = decode_record(line, index).entry
        if (entry.hop, entry.decision) == ("decide", "allow"):
            return line
    raise AssertionError("no decide allow record")


@pytest.mark.parametrize("level", ["task", "tenant", "root"])
def test_a_revoke_through_control_stops_the_next_call(stack, workdir, writer, private, level):
    request = make_request()
    status, body = stack["agent"].call("deploy_service", request.args, agent_headers(request))
    assert body.get("result", {}).get("content") == [{"type": "text", "text": "deployed"}], body
    control = Control(
        "control",
        test_custodian.WRITERS,
        writer,
        Suspension(shared_suspension(private("shared")), os.getegid()),
        MemoryDocket(),
        "control",
        resolver=RESOLVER,
        trust_policy=TRUST_POLICY,
    )
    control.revoke(allow_record_line(workdir), level, "ops", NOW)
    later = make_request(nonce="n-2")
    status, body = stack["agent"].call("deploy_service", later.args, agent_headers(later))
    assert refused(body, "chain_invalid"), body
    assert len(stack["upstream"].calls()) == 1


OTHER_USER = os.environ.get("AGENT_BAILIFF_TEST_OTHER_USER")
PROBE = """
import socket, sys
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(3)
connection.connect(sys.argv[1])
try:
    connection.sendall(b"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n")
    print("closed" if connection.recv(1) == b"" else "served")
except (ConnectionResetError, BrokenPipeError):
    print("closed")
except socket.timeout:
    print("served")
"""


@pytest.mark.skipif(sys.platform != "linux", reason="cross-uid peer check runs in Linux CI only")
@pytest.mark.skipif(not OTHER_USER, reason="set AGENT_BAILIFF_TEST_OTHER_USER to a user in this user's group")
def test_a_direct_custodian_call_from_a_non_gateway_uid_is_refused(stack, workdir):
    for directory in (workdir, workdir / "c"):
        os.chmod(directory, 0o750)
    socket_path = workdir / "c" / "custodian.sock"
    python = shutil.which("python3") or "/usr/bin/python3"
    result = subprocess.run(
        ["sudo", "-n", "-u", OTHER_USER, python, "-I", "-c", PROBE, str(socket_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.stdout.strip() == "closed", result


def test_the_custodian_sees_agent_headers_without_agent_credentials(stack, monkeypatch):
    seen = []
    check_request = CustodianProcessor.check_request

    def recording(processor, message):
        seen.append({header.key for header in message.headers})
        return check_request(processor, message)

    monkeypatch.setattr(CustodianProcessor, "check_request", recording)
    request = make_request()
    stack["agent"].call("deploy_service", request.args, {**agent_headers(request), **EXTRA_AGENT_HEADERS})
    [names] = seen
    assert set(EXTRA_AGENT_HEADERS) <= names
    assert not {"authorization", "proxy-authorization", "cookie"} & names


FORGED_CLEARANCE_HEADERS = {
    "clearance": "forged",
    "extmcp": "forged",
    "mcpguardrails": "forged",
    "mcpguardrails.clearance": "forged",
    "x-bailiff-clearance": "forged",
}


def metadata_values(struct):
    return {key: value.string_value for key, value in struct.fields.items()}


def record_custodian_metadata(monkeypatch):
    seen = []
    check_request = CustodianProcessor.check_request

    def recording(processor, message):
        seen.append(metadata_values(message.metadata_context))
        return check_request(processor, message)

    monkeypatch.setattr(CustodianProcessor, "check_request", recording)
    return seen


def test_agent_input_does_not_change_the_clearance_the_custodian_reads(stack, monkeypatch):
    issued = []
    check_request = DecideProcessor.check_request

    def issuing(processor, message):
        result = check_request(processor, message)
        issued.append(metadata_values(result.metadata))
        return result

    monkeypatch.setattr(DecideProcessor, "check_request", issuing)
    read = record_custodian_metadata(monkeypatch)
    request = make_request()
    params = {"name": "deploy_service", "arguments": request.args, "clearance": "forged"}
    status, body = stack["agent"].post(
        {"method": "tools/call", "params": params, "mcpGuardrails": {"clearance": "forged"}},
        {**agent_headers(request), **FORGED_CLEARANCE_HEADERS},
    )
    assert body.get("result", {}).get("content") == [{"type": "text", "text": "deployed"}], body
    [clearance] = issued
    assert read == [clearance] and clearance["clearance"]
    assert clearance["clearance"] not in call_access_line(stack["gateway"])


def test_a_clearance_in_meta_is_refused_before_the_custodian_runs(stack, monkeypatch):
    read = record_custodian_metadata(monkeypatch)
    request = make_request()
    params = {"name": "deploy_service", "arguments": request.args, "_meta": {"clearance": "forged"}}
    status, body = stack["agent"].post({"method": "tools/call", "params": params}, agent_headers(request))
    assert refused(body, "malformed_request"), body
    assert read == []
    assert stack["upstream"].calls() == []


def test_agent_input_does_not_supply_a_clearance_decide_did_not_set(stack, monkeypatch):
    monkeypatch.setattr(DecideProcessor, "_check", lambda processor, message: passed())
    read = record_custodian_metadata(monkeypatch)
    request = make_request()
    params = {
        "name": "deploy_service",
        "arguments": request.args,
        "clearance": "forged",
        "_meta": {"clearance": "forged"},
    }
    status, body = stack["agent"].post(
        {"method": "tools/call", "params": params, "mcpGuardrails": {"clearance": "forged"}},
        {**agent_headers(request), **FORGED_CLEARANCE_HEADERS},
    )
    assert refused(body, "clearance_missing"), body
    assert read == [{}]
    assert stack["upstream"].calls() == []


def test_free_ports_are_distinct_within_one_call():
    ports = free_ports(64)
    assert len(set(ports)) == len(ports)
