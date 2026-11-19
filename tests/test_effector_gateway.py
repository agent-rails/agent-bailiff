import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import test_agentgateway_e2e
import test_custodian
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_agentgateway_config import gateway_config
from test_agentgateway_e2e import TRACE, Agent, Gateway, free_port, refused
from test_custodian import docket_entries
from test_decide import CUSTODIAN_ID, DECIDE_KEY, NOW, TENANT, make_request, make_root
from test_effector import EFFECTOR_TOKEN, FakeTransport, RecordingDocket, Suspended, Verified

from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor
from agent_bailiff.adapters.agentgateway.server import ProcessorServer
from agent_bailiff.custodian.bindings import EffectorBinding
from agent_bailiff.custodian.release import RELEASE_HEADER, ReleaseSigner
from agent_bailiff.decide.config import TargetBinding
from agent_bailiff.decide.costs import CostTable
from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.kubernetes import KubernetesClient
from agent_bailiff.effector.release import ReleaseCheck, ReleaseCheckConfig
from agent_bailiff.effector.server import Effector, EffectorConfig, EffectorServer, _Handler
from agent_bailiff.routes import routes_from_catalog
from agent_bailiff.service.init import DEFAULT_CATALOG

pytestmark = test_agentgateway_e2e.pytestmark
binary = test_agentgateway_e2e.binary
ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer

SERVICE = "k8s"
EFFECTOR_ID = "effector.homelab"
TARGET = "cluster.homelab"
CATALOG = OperationCatalog.load(DEFAULT_CATALOG)
ROUTES = routes_from_catalog(SERVICE, CATALOG)
RELEASE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
TOOLS = sorted({operation.tool for operation in CATALOG.operations})
DECIDE_BINDINGS = tuple(
    TargetBinding(TENANT, tool, "k8s/staging/*", EFFECTOR_ID, TARGET, CUSTODIAN_ID) for tool in TOOLS
)
EFFECTOR_BINDINGS = tuple(
    EffectorBinding(TENANT, tool, "k8s/staging/*", EFFECTOR_ID, TARGET, CATALOG.digest) for tool in TOOLS
)
COSTS = CostTable(1, dict.fromkeys(TOOLS, 1))
SCOPE = {"tools": ["k8s.*"], "resources": ["k8s/staging/*"], "max_cost_per_call": 5}
SCALE = {"namespace": "staging", "name": "api", "replicas": 3}
RETRY_WINDOW_SECONDS = 3


class RecordingHandler(_Handler):
    def do_POST(self):
        self.server.releases.append(self.headers.get_all(RELEASE_HEADER) or [])
        super().do_POST()


def effector_server(transport, docket):
    check = ReleaseCheck(
        ReleaseCheckConfig(
            effector_id=EFFECTOR_ID,
            custodian_id=CUSTODIAN_ID,
            decider_id=test_custodian.DECIDER_ID,
            custodian_keys={"release-1": RELEASE_KEY.public_key()},
            decide_keys={"decide-1": DECIDE_KEY.public_key()},
            skew_seconds=5,
            max_clearance_lifetime=test_custodian.MAX_PROOF_AGE,
        ),
        CATALOG,
        NOW,
    )
    effector = Effector(
        EffectorConfig(EFFECTOR_ID, EFFECTOR_ID),
        CATALOG,
        check,
        KubernetesClient(transport, transport.token_file),
        Suspended(False),
        docket,
        Verified(True),
    )
    server = EffectorServer(effector, 0, clock=lambda: NOW + 2)
    server.RequestHandlerClass = RecordingHandler
    server.releases = []
    server.start()
    return server


class FailingUpstream(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), FailingHandler)
        self.calls = 0
        self.lock = threading.Lock()
        threading.Thread(target=self.serve_forever, daemon=True).start()


class FailingHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if body.get("method") != "tools/call":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "failing", "version": "1"},
            }
            data = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
            self.send_response(200 if "id" in body else 202)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        with self.server.lock:
            self.server.calls += 1
        self.send_response(503)
        self.send_header("content-length", "0")
        self.end_headers()


def build_stack(binary, workdir, private, make_decider, make_custodian, upstream_url):
    sockets = {"decide": workdir / "d" / "decide.sock", "custodian": workdir / "c" / "custodian.sock"}
    servers = {
        "decide": ProcessorServer(
            DecideProcessor(make_decider(DECIDE_BINDINGS, costs=COSTS), ROUTES, clock=lambda: NOW),
            sockets["decide"],
            private("decide-grpc"),
            gateway_uid=os.geteuid(),
        ),
        "custodian": ProcessorServer(
            CustodianProcessor(
                make_custodian(
                    bindings=EFFECTOR_BINDINGS, release_signer=ReleaseSigner(CUSTODIAN_ID, RELEASE_KEY, "release-1")
                ),
                ROUTES,
                frozenset(),
                clock=lambda: NOW + 1,
            ),
            sockets["custodian"],
            private("custodian-grpc"),
            gateway_uid=os.geteuid(),
        ),
    }
    for server in servers.values():
        server.start()
    config = gateway_config(sockets["decide"], sockets["custodian"], upstream_url, [RELEASE_HEADER])
    config["mcp"]["targets"][0]["name"] = SERVICE
    config["config"] = {
        "adminAddr": f"127.0.0.1:{free_port()}",
        "statsAddr": f"127.0.0.1:{free_port()}",
        "readinessAddr": f"127.0.0.1:{free_port()}",
    }
    config["mcp"]["port"] = free_port()
    expected = GatewayExpectations(sockets["decide"], sockets["custodian"], ROUTES.services, frozenset())
    assert validate_gateway_config(config, expected) == ()
    return servers, Gateway(binary, config, workdir)


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "token"
    path.write_text(EFFECTOR_TOKEN + "\n")
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def stack(binary, workdir, private, make_decider, make_custodian, token_file):
    transport = FakeTransport()
    transport.token_file = token_file
    effector_docket = RecordingDocket()
    effector = effector_server(transport, effector_docket)
    url = f"http://127.0.0.1:{effector.server_address[1]}/mcp"
    servers, gateway = build_stack(binary, workdir, private, make_decider, make_custodian, url)
    try:
        yield {
            "agent": Agent(gateway.port),
            "effector": effector,
            "transport": transport,
            "docket": effector_docket,
            "gateway": gateway,
        }
    finally:
        gateway.stop()
        for server in servers.values():
            server.close()
        effector.close()


def request_for(name, arguments, nonce="n-1"):
    operation = CATALOG.operation(name)
    resource = operation.resource.format(**{key: arguments[key] for key in ("namespace", "name") if key in arguments})
    return make_request(make_root(scope=SCOPE), tool=operation.tool, resource=resource, args=arguments, nonce=nonce)


def headers_for(request, **extra):
    headers = {
        "x-bailiff-task-root": request.task_root,
        "x-bailiff-leaf-proof": request.leaf_proof,
        "x-bailiff-nonce": request.nonce,
        "traceparent": f"00-{TRACE}-00f067aa0ba902b7-01",
    }
    return headers | extra


def test_a_released_scale_reaches_kubernetes_once_with_only_the_custodian_release(stack, workdir):
    request = request_for("scale_deployment", SCALE)
    forged = {RELEASE_HEADER: "forged-by-the-agent"}
    status, body = stack["agent"].call("scale_deployment", SCALE, headers_for(request, **forged))
    assert body.get("result", {}).get("isError") is False, body
    assert json.loads(body["result"]["content"][0]["text"])["spec.replicas"] == 3
    [(method, path, headers, _)] = stack["transport"].requests
    assert (method, path) == ("PATCH", "/apis/apps/v1/namespaces/staging/deployments/api/scale")
    assert headers["Impersonate-User"] == f"bailiff:{TENANT}:scale"
    calls = [release for release in stack["effector"].releases if release]
    assert len(calls) == 1 and len(calls[0]) == 1 and calls[0][0] != "forged-by-the-agent"
    [release] = [entry for entry in docket_entries(workdir) if entry.hop == "custodian" and entry.decision == "release"]
    assert release.credential_tier == "effector"
    attempt, outcome = stack["docket"].entries
    assert (attempt.op_id, attempt.parent_entry) == (release.op_id, release.entry_id)
    assert (outcome.outcome, outcome.trace_id) == ("done", TRACE)


def test_session_methods_list_the_catalog_through_the_gateway(stack):
    status, body = stack["agent"].post({"method": "tools/list"})
    assert sorted(tool["name"] for tool in body["result"]["tools"]) == sorted(item.name for item in CATALOG.operations)
    assert stack["transport"].requests == []


def test_another_namespace_is_refused_before_the_effector(stack):
    arguments = {**SCALE, "namespace": "prod"}
    request = request_for("scale_deployment", arguments)
    status, body = stack["agent"].call("scale_deployment", arguments, headers_for(request))
    assert refused(body, "out_of_scope"), body
    assert stack["transport"].requests == [] and not any(stack["effector"].releases)


def test_replicas_outside_the_catalog_range_are_refused_before_decide(stack, workdir):
    arguments = {**SCALE, "replicas": 11}
    request = request_for("scale_deployment", arguments)
    status, body = stack["agent"].call("scale_deployment", arguments, headers_for(request))
    assert refused(body, "malformed_request"), body
    assert stack["transport"].requests == []
    assert [entry for entry in docket_entries(workdir) if entry.decision in ("allow", "release")] == []


def test_a_replayed_call_is_refused_and_kubernetes_is_called_once(stack):
    request = request_for("scale_deployment", SCALE)
    first = stack["agent"].call("scale_deployment", SCALE, headers_for(request))
    second = stack["agent"].call("scale_deployment", SCALE, headers_for(request))
    assert first[1]["result"]["isError"] is False, first
    assert refused(second[1], "already_issued"), second
    assert len(stack["transport"].requests) == 1


def test_a_release_replayed_directly_at_the_effector_is_refused(stack, monkeypatch):
    captured = []
    original = RecordingHandler.do_POST

    def capture(self):
        captured.extend(self.headers.get_all(RELEASE_HEADER) or [])
        original(self)

    monkeypatch.setattr(RecordingHandler, "do_POST", capture)
    request = request_for("scale_deployment", SCALE)
    stack["agent"].call("scale_deployment", SCALE, headers_for(request))
    [release] = captured
    message = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "scale_deployment", "arguments": SCALE},
    }
    direct = urllib.request.Request(
        f"http://127.0.0.1:{stack['effector'].server_address[1]}/mcp",
        json.dumps(message).encode(),
        {"content-type": "application/json", RELEASE_HEADER: release},
        method="POST",
    )
    with urllib.request.urlopen(direct, timeout=5) as response:
        body = json.loads(response.read())
    assert body["result"]["content"][0]["text"] == "release_replayed"
    assert len(stack["transport"].requests) == 1


def test_the_gateway_does_not_retry_a_failed_effector_call(binary, workdir, private, make_decider, make_custodian):
    upstream = FailingUpstream()
    servers, gateway = build_stack(
        binary, workdir, private, make_decider, make_custodian, f"http://127.0.0.1:{upstream.server_address[1]}/mcp"
    )
    try:
        agent = Agent(gateway.port)
        request = request_for("scale_deployment", SCALE)
        status, body = agent.call("scale_deployment", SCALE, headers_for(request))
        assert "error" in body or body.get("result", {}).get("isError") is True or status >= 500, (status, body)
        time.sleep(RETRY_WINDOW_SECONDS)
        assert upstream.calls == 1
    finally:
        gateway.stop()
        for server in servers.values():
            server.close()
        upstream.shutdown()
        upstream.server_close()


def test_the_effector_token_reaches_neither_the_agent_nor_the_gateway_log(stack):
    request = request_for("list_pods", {"namespace": "staging", "limit": 5})
    status, body = stack["agent"].call("list_pods", {"namespace": "staging", "limit": 5}, headers_for(request))
    assert body["result"]["isError"] is False, body
    assert EFFECTOR_TOKEN not in json.dumps(body) and EFFECTOR_TOKEN not in stack["gateway"].log()
