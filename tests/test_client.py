import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import test_agentgateway_e2e
import test_custodian
from agent_warrant.chain import ChainLink, LeafProof
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_agentgateway_e2e import BINARY
from test_control import MemoryDocket
from test_control_suspension import shared_suspension
from test_custodian import NOW, docket_entries
from test_decide import AGENT_KEY, CHILD_KEY, DECIDER_ID, make_root

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.calls import read_call
from agent_bailiff.client import (
    EFFECTOR_ERROR_ACTIONS,
    REFUSAL_REASONS,
    BailiffClient,
    GatewayError,
    Holder,
    NeedsApproval,
    OutcomeUnknown,
    Refused,
    Result,
    effector_error_action,
    refusal_action,
)
from agent_bailiff.client import client as client_module
from agent_bailiff.client.contract import new_traceparent, prepare_call
from agent_bailiff.control import Control, Suspension
from agent_bailiff.effector.catalog import Argument
from agent_bailiff.routes import ToolRoute, ToolRoutes

ROOT = Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "tests" / "vectors" / "client-v1.json").read_text())
ROUTES = ToolRoutes([ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api")])
ARGS = {"service": "api", "replicas": 2}
DEPLOYED = {"content": [{"type": "text", "text": "deployed"}]}

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
stack = test_agentgateway_e2e.stack


def holder(key=AGENT_KEY, links=()):
    return Holder(make_root().encode(), links, key, DECIDER_ID)


def counting_bytes():
    counter = iter(range(1, 1_000_000))
    return lambda size: bytes([next(counter) % 256 or 1]) * size


def reply(result=None, *, status=200, headers=None, error=None, request_id=None):
    def respond(message):
        if result is None and error is None:
            return status, headers or {}, b""
        body = {"jsonrpc": "2.0", "id": message.get("id") if request_id is None else request_id}
        body.update({"error": error} if error is not None else {"result": result})
        return status, headers or {}, json.dumps(body).encode()

    return respond


def initialized(version="2025-11-25", session="s-1"):
    headers = {"mcp-session-id": session} if session else {}
    return reply(
        {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {"name": "stub"}}, headers=headers
    )


class Stub:
    def __init__(self):
        self.requests = []
        self.responders = {
            "initialize": [initialized()],
            "notifications/initialized": [lambda message: (202, {}, b"")],
            "tools/list": [reply({"tools": [{"name": "deploy_service"}]})],
            "tools/call": [reply(DEPLOYED)],
        }
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                message = json.loads(body)
                stub.requests.append(({key.lower(): value for key, value in self.headers.items()}, message))
                queue = stub.responders[message["method"]]
                responder = queue.pop(0) if len(queue) > 1 else queue[0]
                outcome = responder(message)
                if outcome is None:
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                status, headers, payload = outcome
                self.send_response(status)
                headers = {"content-type": "application/json", **headers}
                for key, value in headers.items():
                    self.send_header(key, value)
                if callable(payload):
                    self.send_header("connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    payload(self.wfile)
                    return
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"

    def methods(self):
        return [message["method"] for _, message in self.requests]

    def calls(self):
        return [(headers, message) for headers, message in self.requests if message["method"] == "tools/call"]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    server = Stub()
    yield server
    server.stop()


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(stub, sleeps):
    instance = BailiffClient(
        stub.url,
        holder(),
        ROUTES,
        timeout=2,
        clock=lambda: NOW,
        token_bytes=counting_bytes(),
        sleep=sleeps.append,
        jitter=lambda: 0.5,
    )
    yield instance
    instance.close()


def vector_call(vector):
    item = vector["input"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(item["holder_key_seed"]))
    nonce_bytes = bytes.fromhex(item["nonce_bytes"])
    return prepare_call(
        Holder(item["task_root"], tuple(item["links"]), key, item["audience"]),
        ToolRoutes([ToolRoute(**item["route"])]),
        item["route"]["service"],
        item["route"]["name"],
        item["arguments"],
        request_id=item["request_id"],
        now=item["now"],
        token_bytes=lambda size: nonce_bytes[:size],
        traceparent=item["traceparent"],
    )


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda vector: vector["name"])
def test_the_client_produces_the_golden_vector(vector):
    call = vector_call(vector)
    assert dict(call.headers) == vector["expected"]["headers"]
    assert call.body.decode() == vector["expected"]["body"]


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda vector: vector["name"])
def test_the_gateway_adapter_reads_the_golden_vector_back(vector):
    item, expected = vector["input"], vector["expected"]
    message = ext_mcp_pb2.McpRequest(
        service_names=[item["route"]["service"]],
        method="tools/call",
        headers=[ext_mcp_pb2.McpHeader(key=key, value=value.encode()) for key, value in expected["headers"].items()],
        mcp_request=json.dumps(json.loads(expected["body"])["params"]).encode(),
    )
    request = read_call(message, ToolRoutes([ToolRoute(**item["route"])]))
    assert (request.tool, request.resource, request.args) == (
        item["route"]["tool"],
        item["route"]["resource"],
        item["arguments"],
    )
    assert request.links == tuple(item["links"])
    assert request.trace_id == item["traceparent"].split("-")[1]
    assert request.digest() == expected["request_digest"]
    proof = LeafProof.decode(request.leaf_proof)
    assert (proof.audience, proof.request_digest, proof.iat) == (
        item["audience"],
        expected["request_digest"],
        item["now"],
    )


def test_the_contract_version_is_one():
    assert VECTORS["contract_version"] == 1
    assert client_module.PROTOCOL_VERSION == "2025-11-25"


def test_a_generated_traceparent_is_w3c_with_random_ids(client):
    call = client.prepare("deploy", "deploy_service", ARGS)
    assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", call.headers["traceparent"])
    assert call.headers["traceparent"] != client.prepare("deploy", "deploy_service", ARGS).headers["traceparent"]


@pytest.mark.parametrize(
    "traceparent",
    ["", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "00-" + "0" * 32 + "-00f067aa0ba902b7-01"],
)
def test_an_invalid_traceparent_is_rejected_before_signing(client, traceparent):
    with pytest.raises(ValueError, match="traceparent"):
        client.prepare("deploy", "deploy_service", ARGS, traceparent)


def test_an_all_zero_random_trace_id_is_rejected():
    with pytest.raises(ValueError, match="all-zero"):
        new_traceparent(lambda size: bytes(size))


def test_each_prepared_call_gets_a_fresh_nonce(client):
    first = client.prepare("deploy", "deploy_service", ARGS)
    second = client.prepare("deploy", "deploy_service", ARGS)
    assert first.nonce != second.nonce and first.request_id != second.request_id


@pytest.mark.parametrize(("service", "name"), [("deploy", "delete_service"), ("other", "deploy_service")])
def test_an_unrouted_tool_is_rejected(client, service, name):
    with pytest.raises(ValueError, match="no route"):
        client.prepare(service, name, ARGS)


def test_arguments_outside_a_route_schema_are_rejected(stub):
    template = ToolRoutes(
        [ToolRoute("deploy", "scale", "deploy.service", "env/staging/{name}", (Argument("name", "label"),))]
    )
    instance = BailiffClient(stub.url, holder(), template, clock=lambda: NOW)
    with pytest.raises(ValueError, match="argument schema"):
        instance.prepare("deploy", "scale", {"name": "API!"})


def test_a_holder_key_that_is_not_the_leaf_subject_is_rejected():
    with pytest.raises(ValueError, match="holder key"):
        holder(CHILD_KEY)


CHILD_SCOPE = {"tools": ["deploy.service"], "resources": ["env/staging/*"], "max_cost_per_call": 2}


def test_a_delegated_holder_extends_the_chain_to_the_child_key():
    parent = holder()
    links = parent.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600, now=NOW)
    child = Holder(parent.task_root, links, CHILD_KEY, DECIDER_ID)
    [link] = (ChainLink.decode(token) for token in links)
    assert link.subject == encode_public_key(CHILD_KEY.public_key())
    assert link.issuer == encode_public_key(AGENT_KEY.public_key())
    assert (link.scope, link.budget, link.depth) == (CHILD_SCOPE, 10, 1)
    assert child.leaf == link


def test_a_delegate_of_a_delegate_appends_to_the_chain():
    parent = holder()
    links = parent.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600, now=NOW)
    grandchild_key = Ed25519PrivateKey.generate()
    child = Holder(parent.task_root, links, CHILD_KEY, DECIDER_ID)
    chain = child.delegate(grandchild_key.public_key(), scope=CHILD_SCOPE, budget=5, ttl=60, now=NOW)
    assert chain[:1] == links and ChainLink.decode(chain[1]).depth == 2
    assert Holder(parent.task_root, chain, grandchild_key, DECIDER_ID).leaf.budget == 5


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"scope": {**CHILD_SCOPE, "resources": ["env/*"]}}, "does not narrow"),
        ({"scope": {**CHILD_SCOPE, "tools": ["deploy.*", "admin.*"]}}, "does not narrow"),
        ({"scope": {**CHILD_SCOPE, "max_cost_per_call": 6}}, "does not narrow"),
        ({"budget": 101}, "budget"),
        ({"ttl": 0}, "ttl"),
    ],
)
def test_a_delegation_that_widens_the_parent_is_refused(options, message):
    request = {"scope": CHILD_SCOPE, "budget": 10, "ttl": 600, **options}
    with pytest.raises(ValueError, match=message):
        holder().delegate(CHILD_KEY.public_key(), now=NOW, **request)


def test_a_delegation_past_the_root_max_depth_is_refused():
    current = holder()
    for _ in range(4):
        child_key = Ed25519PrivateKey.generate()
        links = current.delegate(child_key.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600, now=NOW)
        current = Holder(current.task_root, links, child_key, DECIDER_ID)
    with pytest.raises(ValueError, match="max_depth"):
        current.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600, now=NOW)


@pytest.mark.parametrize("now", [NOW - 1, NOW + 3600])
def test_a_delegation_outside_the_holder_record_window_is_refused(now):
    with pytest.raises(ValueError, match="not valid at now"):
        holder().delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600, now=now)


def test_a_client_delegates_only_on_its_thread(client):
    errors: list[BaseException] = []

    def delegate():
        client.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600)

    thread = threading.Thread(target=lambda: _capture(errors, delegate))
    thread.start()
    thread.join()
    assert len(errors) == 1 and "one per thread" in str(errors[0])


def test_the_client_delegates_at_its_clock(stub):
    instance = BailiffClient(stub.url, holder(), ROUTES, clock=lambda: NOW + 5)
    [token] = instance.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600)
    instance.close()
    link = ChainLink.decode(token)
    assert (link.issued_at, link.expires_at) == (NOW + 5, NOW + 605)


def test_an_allowed_call_returns_the_result(client, stub):
    outcome = client.call("deploy", "deploy_service", ARGS)
    assert outcome == Result(DEPLOYED) and not outcome.is_error


def test_the_session_is_initialized_once_and_its_headers_sent(client, stub):
    client.call("deploy", "deploy_service", ARGS)
    client.call("deploy", "deploy_service", ARGS)
    assert stub.methods() == ["initialize", "notifications/initialized", "tools/call", "tools/call"]
    init_headers = stub.requests[0][0]
    assert "mcp-session-id" not in init_headers and "mcp-protocol-version" not in init_headers
    for headers, _ in stub.requests[1:]:
        assert headers["mcp-session-id"] == "s-1"
        assert headers["mcp-protocol-version"] == "2025-11-25"
    assert client.session_id == "s-1"


def test_a_stateless_gateway_without_a_session_id_works(client, stub):
    stub.responders["initialize"] = [initialized(session=None)]
    assert client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
    assert all("mcp-session-id" not in headers for headers, _ in stub.requests)


def test_the_negotiated_protocol_version_is_used(client, stub):
    stub.responders["initialize"] = [initialized("2025-06-18")]
    client.call("deploy", "deploy_service", ARGS)
    assert stub.calls()[0][0]["mcp-protocol-version"] == "2025-06-18"


def test_an_unsupported_protocol_version_fails(client, stub):
    stub.responders["initialize"] = [initialized("2024-11-05")]
    with pytest.raises(GatewayError, match="unsupported MCP protocol version"):
        client.call("deploy", "deploy_service", ARGS)
    assert stub.calls() == []


def test_the_chain_headers_reach_the_gateway(client, stub):
    call = client.prepare("deploy", "deploy_service", ARGS)
    client.send(call)
    [(headers, message)] = stub.calls()
    assert {key: headers[key] for key in call.headers} == dict(call.headers)
    assert message == json.loads(call.body)


def test_a_prepared_call_is_sent_at_most_once(client, stub):
    call = client.prepare("deploy", "deploy_service", ARGS)
    client.send(call)
    with pytest.raises(RuntimeError, match="at most once"):
        client.send(call)
    assert len(stub.calls()) == 1


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_a_failed_tool_call_is_never_retried(client, stub, status):
    stub.responders["tools/call"] = [reply(status=status)]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown(f"http_{status}")
    assert len(stub.calls()) == 1


def test_a_dropped_connection_during_a_call_is_outcome_unknown(client, stub):
    stub.responders["tools/call"] = [lambda message: None]
    outcome = client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, OutcomeUnknown) and outcome.detail.startswith("transport:")
    assert len(stub.calls()) == 1


def test_a_call_that_times_out_is_outcome_unknown(stub):
    def slow(message):
        time.sleep(1)
        return reply(DEPLOYED)(message)

    stub.responders["tools/call"] = [slow]
    instance = BailiffClient(stub.url, holder(), ROUTES, timeout=0.2, clock=lambda: NOW)
    outcome = instance.call("deploy", "deploy_service", ARGS)
    assert outcome == OutcomeUnknown("transport: TimeoutError")
    assert len(stub.calls()) == 1
    instance.close()


def test_a_released_call_rejected_upstream_is_outcome_unknown(client, stub):
    stub.responders["tools/call"] = [reply(status=401, headers={"content-type": "text/plain"})]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("http_401")


def test_a_json_rpc_error_is_outcome_unknown(client, stub):
    stub.responders["tools/call"] = [reply(error={"code": -32603, "message": "boom"})]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("jsonrpc_error_-32603")


def test_an_expired_session_reinitializes_with_jitter_and_does_not_resend(client, stub, sleeps):
    client.call("deploy", "deploy_service", ARGS)
    stub.responders["tools/call"] = [reply(status=404), reply(DEPLOYED)]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("session_expired")
    stub.responders["initialize"] = [initialized(session="s-2")]
    assert client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
    assert stub.methods().count("initialize") == 2
    assert sleeps == [0.5 * client_module.BACKOFF_BASE_SECONDS]
    calls = stub.calls()
    assert len(calls) == 3
    assert calls[2][0]["mcp-session-id"] == "s-2"
    assert len({headers["x-bailiff-nonce"] for headers, _ in calls}) == 3


def test_tools_list_reinitializes_once_on_an_expired_session(client, stub):
    client.list_tools()
    stub.responders["tools/list"] = [reply(status=404), reply({"tools": [{"name": "deploy_service"}]})]
    assert client.list_tools() == [{"name": "deploy_service"}]
    assert stub.methods().count("initialize") == 2


def test_tools_list_expiring_twice_raises_gateway_error(client, stub):
    client.list_tools()
    stub.responders["tools/list"] = [reply(status=404)]
    with pytest.raises(GatewayError, match="tools/list returned HTTP 404"):
        client.list_tools()
    assert stub.methods().count("initialize") == 2


def test_initialize_retries_with_full_jitter_then_gives_up(client, stub, sleeps):
    stub.responders["initialize"] = [reply(status=503)]
    with pytest.raises(GatewayError, match="initialize returned HTTP 503"):
        client.call("deploy", "deploy_service", ARGS)
    assert stub.methods() == ["initialize"] * client_module.SETUP_ATTEMPTS
    assert sleeps == [0.5 * 0.2, 0.5 * 0.4]
    assert stub.calls() == []


def test_initialize_recovers_after_a_transient_failure(client, stub, sleeps):
    stub.responders["initialize"] = [reply(status=503), initialized()]
    assert client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
    assert stub.methods() == ["initialize", "initialize", "notifications/initialized", "tools/call"]


def test_tools_list_is_returned(client):
    assert client.list_tools() == [{"name": "deploy_service"}]


def tool_page(index, cursor):
    page = {"tools": [{"name": f"tool_{index}"}]}
    if cursor is not None:
        page["nextCursor"] = cursor
    return reply(page)


def test_tools_list_follows_cursors_and_merges_pages(client, stub):
    stub.responders["tools/list"] = [tool_page(0, "c1"), tool_page(1, "c2"), tool_page(2, None)]
    assert client.list_tools() == [{"name": "tool_0"}, {"name": "tool_1"}, {"name": "tool_2"}]
    params = [message["params"] for _, message in stub.requests if message["method"] == "tools/list"]
    assert params == [{}, {"cursor": "c1"}, {"cursor": "c2"}]


def test_tools_list_with_more_than_ten_pages_is_refused(client, stub):
    stub.responders["tools/list"] = [tool_page(index, f"c{index + 1}") for index in range(11)]
    with pytest.raises(GatewayError, match="more than 10 pages"):
        client.list_tools()
    assert stub.methods().count("tools/list") == 10


def test_tools_list_restarts_from_the_first_page_after_a_session_expires_mid_listing(client, stub):
    stub.responders["tools/list"] = [tool_page(0, "c1"), reply(status=404), tool_page(0, "c1"), tool_page(1, None)]
    assert client.list_tools() == [{"name": "tool_0"}, {"name": "tool_1"}]
    params = [message["params"] for _, message in stub.requests if message["method"] == "tools/list"]
    assert params == [{}, {"cursor": "c1"}, {}, {"cursor": "c1"}]
    assert stub.methods().count("initialize") == 2


def test_tools_list_refuses_a_repeated_cursor(client, stub):
    stub.responders["tools/list"] = [tool_page(0, "c1"), tool_page(1, "c1")]
    with pytest.raises(GatewayError, match="repeated a nextCursor"):
        client.list_tools()


def test_tools_list_refuses_a_tool_name_listed_twice(client, stub):
    stub.responders["tools/list"] = [tool_page(0, "c1"), tool_page(0, None)]
    with pytest.raises(GatewayError, match="listed tool 'tool_0' twice"):
        client.list_tools()


@pytest.mark.parametrize("name", [["list"], {"n": 1}, None, 7])
def test_tools_list_refuses_a_tool_without_a_string_name(client, stub, name):
    stub.responders["tools/list"] = [reply({"tools": [{"name": name}]})]
    with pytest.raises(GatewayError, match="a tool without a string name"):
        client.list_tools()


@pytest.mark.parametrize("cursor", ["", 7])
def test_a_malformed_cursor_is_refused(client, stub, cursor):
    stub.responders["tools/list"] = [reply({"tools": [], "nextCursor": cursor})]
    with pytest.raises(GatewayError, match="nextCursor"):
        client.list_tools()


def refusal(reason):
    return reply({"content": [{"type": "text", "text": reason}], "isError": True})


@pytest.mark.parametrize("reason", sorted(REFUSAL_REASONS - {"needs_approval"}))
def test_a_bailiff_refusal_is_typed(client, stub, reason):
    stub.responders["tools/call"] = [refusal(reason)]
    assert client.call("deploy", "deploy_service", ARGS) == Refused(reason)


def test_needs_approval_has_its_own_type(client, stub):
    stub.responders["tools/call"] = [refusal("needs_approval")]
    assert client.call("deploy", "deploy_service", ARGS) == NeedsApproval()


@pytest.mark.parametrize(
    ("reason", "action"),
    [
        ("out_of_scope", "stop"),
        ("unbounded_scope", "stop"),
        ("policy_denied", "stop"),
        ("chain_invalid", "stop"),
        ("already_issued", "stop"),
        ("reservation_refused", "stop"),
        ("release_refused", "stop"),
        ("suspended", "ask_user"),
        ("needs_approval", "ask_user"),
        ("docket_unavailable", "retry_later"),
        ("ledger_unavailable", "retry_later"),
        ("internal_error", "retry_later"),
    ],
)
def test_a_refusal_says_what_the_agent_should_do(client, stub, reason, action):
    stub.responders["tools/call"] = [refusal(reason)]
    outcome = client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, Refused | NeedsApproval)
    assert outcome.action == action
    assert outcome.retryable is (action == "retry_later")


def test_every_refusal_reason_has_an_action():
    assert {refusal_action(reason) for reason in REFUSAL_REASONS} == {"stop", "ask_user", "retry_later"}


def test_an_unknown_reason_has_no_action():
    with pytest.raises(ValueError, match="not a bailiff refusal reason"):
        refusal_action("repository not found")


@pytest.mark.parametrize(
    ("reason", "action"),
    [
        ("effector_suspended", "ask_user"),
        ("effector_busy", "retry_later"),
        ("effector_docket_unavailable", "retry_later"),
        ("effector_rbac_unverified", "retry_later"),
        ("effector_restart_unverified", "retry_later"),
        ("effector_webhook_unverified", "retry_later"),
        ("effector_kubernetes_429", "retry_later"),
        ("effector_kubernetes_403", "stop"),
        ("effector_kubernetes_404", "stop"),
        ("effector_release_replayed", "stop"),
        ("effector_release_expired", "stop"),
        ("effector_outcome_unknown", "stop"),
        ("effector_response_too_large", "stop"),
        ("effector_something_new", "stop"),
    ],
)
def test_an_effector_error_says_what_the_agent_should_do(client, stub, reason, action):
    stub.responders["tools/call"] = [refusal(reason)]
    outcome = client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, Result) and outcome.effector_error == reason
    assert effector_error_action(reason) == action


@pytest.mark.parametrize(
    "result",
    [
        {"content": [{"type": "text", "text": "effector_busy"}], "isError": False},
        {"content": [{"type": "text", "text": "repository not found"}], "isError": True},
        {"content": [{"type": "text", "text": "effector_busy"}, {"type": "text", "text": "x"}], "isError": True},
    ],
)
def test_only_a_lone_prefixed_tool_error_is_an_effector_error(result):
    assert Result(result).effector_error is None


def test_every_effector_retry_or_ask_reason_is_one_the_effector_emits():
    sources = [ROOT / "agent_bailiff" / "effector" / name for name in ("server.py", "release.py")]
    literals = set()
    for path in sources:
        literals |= set(re.findall(r'(?:_error|_refuse\(checked,|ReleaseRefused)\(?\s*"([a-z_]+)"', path.read_text()))
    emitted = {reason if reason.startswith("effector_") else f"effector_{reason}" for reason in literals}
    assert {"effector_suspended", "effector_rbac_unverified", "effector_busy"} <= emitted
    assert set(EFFECTOR_ERROR_ACTIONS) - {"effector_kubernetes_429"} <= emitted


def test_a_tool_error_with_other_text_is_a_result(client, stub):
    stub.responders["tools/call"] = [refusal("repository not found")]
    outcome = client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, Result) and outcome.is_error


def test_every_reason_the_server_emits_is_a_known_refusal():
    sources = [ROOT / "agent_bailiff" / "decide" / "decider.py", *(ROOT / "agent_bailiff" / "adapters").rglob("*.py")]
    literals = set()
    for path in sources:
        text = path.read_text()
        literals |= set(re.findall(r'(?:_Refusal|CallRefused|refuse)\("([a-z_]+)"', text))
        literals |= set(re.findall(r'^[A-Z_]+_REFUSED = "([a-z_]+)"', text, re.MULTILINE))
    assert {"chain_invalid", "unknown_tool", "release_refused", "clearance_missing"} <= literals
    assert literals <= REFUSAL_REASONS


def event_stream(*messages):
    def respond(message):
        events = [{"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}]
        events += [{"jsonrpc": "2.0", "id": message["id"], "result": item} for item in messages]
        payload = b": keep-alive\n\n" + b"".join(f"event: message\ndata: {json.dumps(e)}\n\n".encode() for e in events)
        return 200, {"content-type": "text/event-stream"}, payload

    return respond


def test_an_event_stream_response_is_read_by_request_id(client, stub):
    stub.responders["tools/call"] = [event_stream(DEPLOYED)]
    assert client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)


def test_an_event_stream_over_the_size_cap_is_outcome_unknown(client, stub, monkeypatch):
    client.list_tools()
    monkeypatch.setattr(client_module, "MAX_RESPONSE_BYTES", 64)
    stub.responders["tools/call"] = [event_stream({"content": [{"type": "text", "text": "x" * 200}]})]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("transport: _ResponseError")


def test_a_json_response_over_the_size_cap_is_outcome_unknown(client, stub, monkeypatch):
    client.list_tools()
    monkeypatch.setattr(client_module, "MAX_RESPONSE_BYTES", 64)
    stub.responders["tools/call"] = [reply({"content": [{"type": "text", "text": "x" * 200}]})]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("transport: _ResponseError")


def test_a_client_is_used_by_one_thread(client):
    errors = []
    thread = threading.Thread(target=lambda: _capture(errors, client.prepare, "deploy", "deploy_service", ARGS))
    thread.start()
    thread.join()
    assert len(errors) == 1 and "one per thread" in str(errors[0])


def _capture(errors, function, *args):
    try:
        function(*args)
    except RuntimeError as error:
        errors.append(error)


@pytest.mark.parametrize("url", ["ftp://gateway/mcp", "http:///mcp", "http://gateway/mcp?x=1"])
def test_a_bad_gateway_url_is_rejected(url):
    with pytest.raises(ValueError, match="url"):
        BailiffClient(url, holder(), ROUTES)


PROBE = """
import sys
from importlib.abc import MetaPathFinder


class Block(MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "google.protobuf" or name.startswith(("google.protobuf.", "agent_bailiff.adapters", "grpc")):
            raise ImportError(f"blocked {name}")
        return None


sys.meta_path.insert(0, Block())
import agent_bailiff.client
print(agent_bailiff.client.CONTRACT_VERSION)
"""


def test_the_client_imports_without_the_gateway_adapter_grpc_or_protobuf():
    result = subprocess.run(
        [sys.executable, "-c", PROBE],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT)},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"


live = pytest.mark.skipif(BINARY is None, reason="agentgateway v1.7.0 binary not cached; run fetch_gateway.sh")


@pytest.fixture
def gateway_client(stack):
    instance = BailiffClient(stack["agent"].url, holder(), test_agentgateway_e2e.ROUTES, clock=lambda: NOW)
    yield instance
    instance.close()


@live
def test_the_client_calls_through_agentgateway(gateway_client, stack):
    assert [tool["name"] for tool in gateway_client.list_tools()][0] == "deploy_service"
    assert gateway_client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
    assert gateway_client.protocol_version in client_module.SUPPORTED_PROTOCOL_VERSIONS
    assert len(stack["upstream"].calls()) == 1


@live
def test_a_replayed_client_call_is_refused_by_agentgateway(gateway_client, stack):
    call = gateway_client.prepare("deploy", "deploy_service", ARGS)
    assert gateway_client.send(call) == Result(DEPLOYED)
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": gateway_client.protocol_version,
        **dict(call.headers),
    }
    if gateway_client.session_id:
        headers["mcp-session-id"] = gateway_client.session_id
    request = urllib.request.Request(stack["agent"].url, call.body, headers, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        exchange = client_module._Exchange(
            response.status, {}, test_agentgateway_e2e._json_rpc(response.read().decode())
        )
    assert client_module.classify(exchange) == Refused("already_issued")
    assert len(stack["upstream"].calls()) == 1


@live
@pytest.mark.parametrize("reason", ["needs_approval", "out_of_scope", "already_issued"])
def test_an_upstream_answer_shaped_like_a_refusal_is_outcome_unknown(gateway_client, stack, reason):
    stack["upstream"].call_result = {"content": [{"type": "text", "text": reason}], "isError": True}
    outcome = gateway_client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, OutcomeUnknown), outcome
    assert len(stack["upstream"].calls()) == 1


@live
@pytest.mark.parametrize(
    "result",
    [
        {"content": [{"type": "text", "text": "boom"}], "isError": True},
        {"content": [{"type": "text", "text": "needs_approval"}, {"type": "text", "text": "more"}], "isError": True},
        {"content": [{"type": "text", "text": "needs_approval"}]},
        {"content": [{"type": "image", "data": "AA==", "mimeType": "image/png"}], "isError": True},
        {"content": []},
    ],
)
def test_other_upstream_answers_pass_the_refusal_guard(gateway_client, stack, result):
    stack["upstream"].call_result = result
    outcome = gateway_client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, Result) and outcome.result["content"] == result["content"], outcome


@live
@pytest.mark.parametrize("reason", ["effector_suspended", "effector_docket_unavailable", "effector_malformed_request"])
def test_an_effector_error_passes_the_refusal_guard(gateway_client, stack, reason):
    stack["upstream"].call_result = {"content": [{"type": "text", "text": reason}], "isError": True}
    outcome = gateway_client.call("deploy", "deploy_service", ARGS)
    assert isinstance(outcome, Result) and outcome.effector_error == reason, outcome


@live
def test_a_call_outside_the_scope_is_refused_by_agentgateway(gateway_client, stack):
    assert gateway_client.call("deploy", "deploy_production", ARGS) == Refused("out_of_scope")
    assert stack["upstream"].calls() == []


def test_an_empty_priming_event_is_skipped(client, stub):
    respond = event_stream(DEPLOYED)

    def primed(message):
        status, headers, payload = respond(message)
        return status, headers, b"id: 1\ndata:\n\n" + payload

    stub.responders["tools/call"] = [primed]
    assert client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)


def test_a_non_utf8_event_stream_is_outcome_unknown(client, stub):
    stub.responders["tools/call"] = [lambda message: (200, {"content-type": "text/event-stream"}, b"data: \xff\n\n")]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("transport: _ResponseError")


def test_a_json_response_for_another_request_id_is_outcome_unknown(client, stub):
    stub.responders["tools/call"] = [reply(DEPLOYED, request_id=999)]
    assert client.call("deploy", "deploy_service", ARGS) == OutcomeUnknown("transport: _ResponseError")


def test_a_failed_initialized_notification_leaves_no_session(client, stub):
    stub.responders["notifications/initialized"] = [lambda message: None] * 3 + [lambda message: (202, {}, b"")]
    with pytest.raises(GatewayError):
        client.call("deploy", "deploy_service", ARGS)
    assert client.protocol_version is None and client.session_id is None
    assert client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
    assert stub.methods().count("initialize") == 2
    assert len(stub.calls()) == 1


def test_a_trickling_event_stream_stops_at_the_deadline(stub):
    def trickle(wfile):
        for _ in range(20):
            wfile.write(b"x")
            wfile.flush()
            time.sleep(0.1)

    stub.responders["tools/call"] = [lambda message: (200, {"content-type": "text/event-stream"}, trickle)]
    instance = BailiffClient(stub.url, holder(), ROUTES, timeout=0.5, clock=lambda: NOW)
    instance.list_tools()
    started = time.monotonic()
    outcome = instance.call("deploy", "deploy_service", ARGS)
    elapsed = time.monotonic() - started
    instance.close()
    assert isinstance(outcome, OutcomeUnknown) and outcome.detail.startswith("transport:")
    assert elapsed < 1.0


@live
def test_a_sub_agent_calls_through_agentgateway_under_a_narrowed_link(gateway_client, stack, workdir):
    links = gateway_client.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600)
    child = Holder(make_root().encode(), links, CHILD_KEY, DECIDER_ID)
    sub_agent = BailiffClient(stack["agent"].url, child, test_agentgateway_e2e.ROUTES, clock=lambda: NOW)
    try:
        assert sub_agent.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
        assert sub_agent.call("deploy", "deploy_canary", ARGS) == Refused("out_of_scope")
    finally:
        sub_agent.close()
    assert len(stack["upstream"].calls()) == 1
    decided = [entry for entry in docket_entries(workdir) if entry.hop == "decide"]
    assert [entry.decision for entry in decided] == ["allow", "refuse"]
    child_key = encode_public_key(CHILD_KEY.public_key())
    assert all(entry.agent_key == child_key and entry.handles["link"] for entry in decided)


@live
def test_revoking_a_sub_agent_link_stops_the_sub_agent_but_not_its_parent(
    gateway_client, stack, workdir, writer, private
):
    links = gateway_client.delegate(CHILD_KEY.public_key(), scope=CHILD_SCOPE, budget=10, ttl=600)
    sub_agent = BailiffClient(
        stack["agent"].url,
        Holder(make_root().encode(), links, CHILD_KEY, DECIDER_ID),
        test_agentgateway_e2e.ROUTES,
        clock=lambda: NOW,
    )
    try:
        assert sub_agent.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
        control = Control(
            "control",
            test_custodian.WRITERS,
            writer,
            Suspension(shared_suspension(private("shared")), os.getegid()),
            MemoryDocket(),
            "control",
        )
        control.revoke(test_agentgateway_e2e.allow_record_line(workdir), "link", "ops", NOW)
        assert sub_agent.call("deploy", "deploy_service", ARGS) == Refused("chain_invalid")
    finally:
        sub_agent.close()
    assert gateway_client.call("deploy", "deploy_service", ARGS) == Result(DEPLOYED)
    assert len(stack["upstream"].calls()) == 2
