import copy
import hashlib
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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import test_custodian
from agent_warrant.ledger import TaskLedger
from test_agentgateway_config import gateway_config
from test_custodian import CUSTODIAN_BINDINGS, DEPLOY_SECRET, NOW, docket_entries
from test_decide import make_request

from agent_bailiff.adapters.agentgateway.calls import ToolRoute, ToolRoutes
from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor
from agent_bailiff.adapters.agentgateway.server import ProcessorServer

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
pytestmark = [
    pytest.mark.skipif(
        BINARY is None,
        reason="agentgateway v1.7.0 binary not cached; run adapters/agentgateway/scripts/fetch_gateway.sh",
    ),
    pytest.mark.skipif(
        not hasattr(TaskLedger, "open_read_only"),
        reason="needs agent-warrant with TaskLedger.open_read_only (unreleased PR #15); move the pin after its release",
    ),
]

ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
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
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"

    def calls(self):
        with self.lock:
            return [headers for method, headers in self.requests if method == "tools/call"]

    def stop(self):
        self.shutdown()
        self.server_close()


class UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        with self.server.lock:
            headers = {key.lower(): value for key, value in self.headers.items()}
            self.server.requests.append((body.get("method"), headers))
        if "id" not in body:
            self.send_response(202)
            self.end_headers()
            return
        results = {
            "initialize": {
                "protocolVersion": body.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-deploy", "version": "1"},
            },
            "tools/list": {"tools": [{"name": "deploy_service", "inputSchema": {"type": "object"}}]},
            "tools/call": {"content": [{"type": "text", "text": "deployed"}]},
        }
        data = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": results.get(body["method"], {})}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


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
                return response.status, _json_rpc(response.read().decode())
        except urllib.error.HTTPError as error:
            return error.code, _json_rpc(error.read().decode())


def _json_rpc(text):
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    return json.loads(text) if text.strip() else {}


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
def stack(binary, workdir, private, make_decider, make_custodian):
    upstream = Upstream()
    sockets = {"decide": workdir / "d" / "decide.sock", "custodian": workdir / "c" / "custodian.sock"}
    servers = {
        "decide": ProcessorServer(
            DecideProcessor(make_decider(), ROUTES, clock=lambda: NOW),
            sockets["decide"],
            private("decide-grpc"),
            gateway_uid=os.geteuid(),
        ),
        "custodian": ProcessorServer(
            CustodianProcessor(make_custodian(), ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW + 1),
            sockets["custodian"],
            private("custodian-grpc"),
            gateway_uid=os.geteuid(),
        ),
    }
    for server in servers.values():
        server.start()
    config = gateway_config(sockets["decide"], sockets["custodian"], upstream.url)
    config["config"] = {
        "adminAddr": f"127.0.0.1:{free_port()}",
        "statsAddr": f"127.0.0.1:{free_port()}",
        "readinessAddr": f"127.0.0.1:{free_port()}",
    }
    config["mcp"]["port"] = free_port()
    expected = GatewayExpectations(
        sockets["decide"], sockets["custodian"], ROUTES.services, frozenset({"Authorization"})
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


def test_an_out_of_scope_call_is_refused_and_reaches_no_upstream(stack):
    request = make_request(resource="env/prod/api")
    status, body = stack["agent"].call("deploy_production", request.args, agent_headers(request))
    assert refused(body, "out_of_scope"), body
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
    "fail_open": lambda processors: processors[2].update(failureMode="failOpen"),
    "no_header_allowlist": lambda processors: processors[1].pop("requestHeaders"),
    "custodian_before_decide": lambda processors: processors.insert(1, processors.pop(2)),
    "custodian_over_tcp": lambda processors: processors[2].update(host="127.0.0.1:9"),
}


@pytest.mark.parametrize("name", sorted(UNSAFE))
def test_check_config_refuses_unsafe_configs_the_gateway_itself_accepts(stack, binary, workdir, name):
    config = copy.deepcopy(stack["config"])
    UNSAFE[name](config["mcp"]["policies"]["mcpGuardrails"]["processors"])
    path = workdir / f"{name}.json"
    path.write_text(json.dumps(config))
    accepted = subprocess.run([str(binary), "--validate-only", "-f", str(path)], capture_output=True, text=True)
    assert accepted.returncode == 0 and "valid" in accepted.stdout, accepted
    assert validate_gateway_config(config, stack["expected"])


@pytest.mark.skip(reason="revoke and suspend through control land in Phase 6")
def test_a_revoke_through_control_stops_the_next_call():
    pass


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
