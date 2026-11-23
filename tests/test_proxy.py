import io
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.client import GatewayError, OutcomeUnknown, Refused, Result
from agent_bailiff.proxy.agent_key import generate_agent_key
from agent_bailiff.proxy.guidance import GATEWAY_UNAVAILABLE, NO_TASK, OUTCOME_UNKNOWN, TASK_EXPIRED
from agent_bailiff.proxy.server import MAX_LINE_BYTES, StdioProxy, route_services
from agent_bailiff.routes import ToolRoute, ToolRoutes
from agent_bailiff.task.issue import TaskRequest, issue_task

NOW = 1_800_000_000
TTL = 600
SCOPE = {"tools": ["gitea.issues.list"], "resources": ["gitea/repos/demo/issues"], "max_cost_per_call": 1}
ISSUER_KEY = Ed25519PrivateKey.generate()
ROUTE_DOCUMENT = {
    "routes": [
        {"service": "gitea", "name": "list_issues", "tool": "gitea.issues.list", "resource": "gitea/repos/demo/issues"}
    ]
}
ROUTES = ToolRoutes.from_document(ROUTE_DOCUMENT)
LIST_ISSUES = {
    "name": "list_issues",
    "description": "List issues.",
    "inputSchema": {"type": "object"},
    "annotations": {"readOnlyHint": True},
}
UNROUTED = {"name": "create_issue", "description": "Create an issue.", "inputSchema": {"type": "object"}}
RESULT = Result({"content": [{"type": "text", "text": "[]"}], "isError": False})
SIGNAL_EXIT_SECONDS = 2


class FakeClient:
    def __init__(self, gateway, holder):
        self.gateway = gateway
        self.holder = holder
        self.closed = False

    def list_tools(self):
        self.gateway.listed += 1
        if isinstance(self.gateway.tools, Exception):
            raise self.gateway.tools
        return self.gateway.tools

    def prepare(self, service, name, arguments):
        if arguments.get("bad"):
            raise ValueError("arguments for 'list_issues' do not match the route's argument schema")
        return (service, name, arguments)

    def send(self, call):
        self.gateway.sent.append(call)
        if isinstance(self.gateway.outcome, Exception):
            raise self.gateway.outcome
        return self.gateway.outcome

    def close(self):
        self.closed = True


class FakeGateway:
    def __init__(self):
        self.tools = [LIST_ISSUES, UNROUTED]
        self.outcome = RESULT
        self.sent = []
        self.listed = 0
        self.clients = []

    def factory(self, url, holder, routes):
        client = FakeClient(self, holder)
        self.clients.append(client)
        return client


@pytest.fixture
def key_dir(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


@pytest.fixture
def task_file(tmp_path):
    return tmp_path / "task.json"


@pytest.fixture
def gateway():
    return FakeGateway()


@pytest.fixture
def clock():
    return [NOW]


@pytest.fixture
def proxy(task_file, key_dir, gateway, clock):
    return StdioProxy(
        task_file, key_dir, "http://127.0.0.1:1/mcp", ROUTES, clock=lambda: clock[0], client_factory=gateway.factory
    )


def nested(levels):
    schema = {"type": "object"}
    for _ in range(levels):
        schema = {"type": "object", "properties": {"inner": schema}}
    return schema


def issue(task_file, key_dir, now=NOW):
    subject = generate_agent_key(key_dir)
    request = TaskRequest(purpose="triage", scope=SCOPE, budget=10, subject=subject, ttl=TTL)
    task = issue_task(ISSUER_KEY, "issuer.quickstart", "decide.quickstart", request, now)
    task_file.write_bytes(task.encode())
    return task


def serve(proxy, *lines):
    stdout = io.BytesIO()
    proxy.run(io.BytesIO(b"".join(lines)), stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def request(method, request_id=1, **params):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode() + b"\n"


def call(name="list_issues", request_id=1, **arguments):
    return request("tools/call", request_id, name=name, arguments=arguments)


def ask(proxy, line):
    (reply,) = serve(proxy, line)
    return reply


def result_text(reply):
    assert reply["result"]["isError"] is True
    return reply["result"]["content"][0]["text"]


@pytest.mark.parametrize("line", [b"\xff\xfe\n", b"{not json\n", b'{"id": 1, "id": 2}\n', b'{"x": NaN}\n'])
def test_unparseable_input_is_a_parse_error_and_the_loop_continues(proxy, line):
    first, second = serve(proxy, line, request("ping", 2))
    assert first == {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": first["error"]["message"]}}
    assert second == {"jsonrpc": "2.0", "id": 2, "result": {}}


@pytest.mark.parametrize(
    "line",
    [
        b"[]\n",
        b"7\n",
        b'{"jsonrpc": "1.0", "id": 1, "method": "ping"}\n',
        b'{"jsonrpc": "2.0", "id": true, "method": "ping"}\n',
        b'{"jsonrpc": "2.0", "id": 1}\n',
    ],
)
def test_a_non_request_is_an_invalid_request(proxy, line):
    first, second = serve(proxy, line, request("ping", 2))
    assert (first["id"], first["error"]["code"]) == (None, -32600)
    assert second["result"] == {}


def test_an_oversized_line_is_refused_and_the_next_line_is_served(proxy):
    first, second = serve(proxy, b"x" * (MAX_LINE_BYTES + 1) + b"y" * 10 + b"\n", request("ping", 2))
    assert first["error"]["code"] == -32600
    assert second == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_a_notification_and_a_blank_line_get_no_reply(proxy):
    replies = serve(proxy, b'{"jsonrpc": "2.0", "method": "notifications/initialized"}\n', b"\n", request("ping"))
    assert replies == [{"jsonrpc": "2.0", "id": 1, "result": {}}]


def test_an_unknown_method_is_not_found(proxy):
    assert ask(proxy, request("resources/list"))["error"]["code"] == -32601


@pytest.mark.parametrize(("requested", "answered"), [("2025-06-18", "2025-06-18"), ("1999-01-01", "2025-11-25")])
def test_initialize_echoes_a_supported_version_or_answers_the_latest(proxy, requested, answered):
    result = ask(proxy, request("initialize", protocolVersion=requested))["result"]
    assert result == {
        "protocolVersion": answered,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "agent-bailiff-proxy", "version": "1"},
    }


def test_tools_list_is_the_routed_upstream_tools_without_annotations(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    first, second = serve(proxy, request("tools/list"), request("tools/list", 2))
    expected = {key: value for key, value in LIST_ISSUES.items() if key != "annotations"}
    assert first["result"] == second["result"] == {"tools": [expected]}
    assert gateway.listed == 1


@pytest.mark.parametrize(
    "oversized",
    [
        {"description": "d" * 4097},
        {"description": 5},
        {"title": "t" * 4097},
        {"title": 5},
        {"inputSchema": {"type": "object", "description": "s" * 16385}},
        {"inputSchema": "object"},
        {"inputSchema": nested(16)},
    ],
)
def test_an_oversized_tool_is_dropped_and_logged(proxy, task_file, key_dir, gateway, oversized, caplog):
    issue(task_file, key_dir)
    gateway.tools = [LIST_ISSUES | oversized]
    with caplog.at_level(logging.WARNING):
        assert ask(proxy, request("tools/list"))["result"] == {"tools": []}
    assert "dropped tool 'list_issues'" in caplog.text


def test_tools_list_without_a_task_is_an_error(proxy, gateway):
    reply = ask(proxy, request("tools/list"))
    assert reply["error"] == {"code": -32000, "message": "no task issued; ask the user to issue one"}
    assert gateway.listed == 0


def test_tools_list_when_the_gateway_fails_is_an_error(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    gateway.tools = GatewayError("tools/list returned more than 10 pages")
    reply = ask(proxy, request("tools/list"))
    assert reply["error"]["code"] == -32000
    assert "more than 10 pages" in reply["error"]["message"]


def test_a_routed_call_is_sent_with_the_task_holder(proxy, task_file, key_dir, gateway):
    task = issue(task_file, key_dir)
    reply = ask(proxy, call(owner="demo"))
    assert reply["result"] == RESULT.result
    assert gateway.sent == [("gitea", "list_issues", {"owner": "demo"})]
    assert gateway.clients[0].holder.task_root == task.root.encode()


@pytest.mark.parametrize(
    "line",
    [
        call("create_issue"),
        request("tools/call", arguments={}),
        request("tools/call", name="list_issues", arguments=[]),
        b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []}\n',
    ],
)
def test_an_unrouted_or_malformed_call_is_invalid_params(proxy, task_file, key_dir, gateway, line):
    issue(task_file, key_dir)
    assert ask(proxy, line)["error"]["code"] == -32602
    assert gateway.sent == []


def test_a_call_without_a_task_says_so(proxy, gateway):
    assert result_text(ask(proxy, call())) == NO_TASK
    assert gateway.clients == []


def test_a_call_with_an_invalid_task_file_says_why(proxy, task_file, gateway):
    task_file.write_text("{}")
    assert result_text(ask(proxy, call())).startswith("the task file is invalid")
    assert gateway.clients == []


@pytest.mark.parametrize("now", [NOW + TTL, NOW + TTL + 1])
def test_an_expired_task_sends_nothing(proxy, task_file, key_dir, gateway, clock, now):
    issue(task_file, key_dir)
    clock[0] = now
    assert result_text(ask(proxy, call())) == TASK_EXPIRED
    assert gateway.sent == []


def test_a_new_task_reloads_closes_the_old_client_and_prunes_the_old_key(proxy, task_file, key_dir, gateway):
    first = issue(task_file, key_dir)
    before = proxy.handle(json.loads(call()))
    second = issue(task_file, key_dir)
    after = proxy.handle(json.loads(call(request_id=2)))
    assert before["result"] == after["result"] == RESULT.result
    assert [client.holder.task_root for client in gateway.clients] == [first.root.encode(), second.root.encode()]
    assert [client.closed for client in gateway.clients] == [True, False]
    assert sorted(os.listdir(key_dir)) == [f"{second.root.subject}.key"]


def test_an_unchanged_task_reuses_the_client(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    serve(proxy, call(), call(request_id=2))
    assert len(gateway.clients) == 1
    assert len(gateway.sent) == 2


def test_a_refusal_carries_guidance(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    gateway.outcome = Refused("out_of_scope")
    assert result_text(ask(proxy, call())).startswith("out_of_scope: agent-bailiff refused this call")


def test_an_unknown_outcome_is_sent_once_and_never_retried(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    gateway.outcome = OutcomeUnknown("transport: TimeoutError")
    assert result_text(ask(proxy, call())) == f"outcome_unknown: transport: TimeoutError; {OUTCOME_UNKNOWN}"
    assert len(gateway.sent) == 1


def test_an_unreachable_gateway_is_gateway_unavailable(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    gateway.outcome = GatewayError("the gateway did not answer after 3 attempts")
    assert result_text(ask(proxy, call())) == GATEWAY_UNAVAILABLE


def test_arguments_the_route_refuses_are_a_tool_error(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    assert "do not match" in result_text(ask(proxy, call(bad=True)))
    assert gateway.sent == []


def test_eof_closes_the_client(proxy, task_file, key_dir, gateway):
    issue(task_file, key_dir)
    serve(proxy, call())
    assert gateway.clients[0].closed


def test_a_name_routed_on_two_services_is_refused():
    routes = ToolRoutes(
        [ToolRoute("a", "list", "a.items.list", "a/items"), ToolRoute("b", "list", "b.items.list", "b/items")]
    )
    with pytest.raises(ValueError, match="more than one service"):
        route_services(routes)


class SlowGateway(BaseHTTPRequestHandler):
    called = threading.Event()

    def do_POST(self):
        message = json.loads(self.rfile.read(int(self.headers["content-length"])))
        method = message.get("method")
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "g", "version": "1"}}
        else:
            self.called.set()
            time.sleep(1)
            result = RESULT.result
        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def slow_gateway():
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowGateway)
    SlowGateway.called = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    server.shutdown()
    server.server_close()


def start_proxy(tmp_path, task_file, key_dir, gateway_url):
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps(ROUTE_DOCUMENT))
    arguments = ["--task-file", str(task_file), "--key-dir", str(key_dir), "--gateway-url", gateway_url]
    process = subprocess.Popen(
        [sys.executable, "-m", "agent_bailiff.cli", "proxy", "run", *arguments, "--routes", str(routes)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert b"proxy routes sha256" in process.stderr.readline()
    return process


def test_sigint_while_idle_exits_cleanly(tmp_path, task_file, key_dir):
    process = start_proxy(tmp_path, task_file, key_dir, "http://127.0.0.1:1/mcp")
    began = time.monotonic()
    process.send_signal(signal.SIGINT)
    assert process.wait(timeout=SIGNAL_EXIT_SECONDS) == 0
    assert time.monotonic() - began < SIGNAL_EXIT_SECONDS
    assert process.stdout.read() == b""
    process.stdin.close()


def test_sigterm_mid_call_replies_then_exits(tmp_path, task_file, key_dir, slow_gateway):
    issue(task_file, key_dir, now=int(time.time()))
    process = start_proxy(tmp_path, task_file, key_dir, slow_gateway)
    process.stdin.write(call(owner="demo"))
    process.stdin.flush()
    assert SlowGateway.called.wait(timeout=5)
    process.send_signal(signal.SIGTERM)
    reply = json.loads(process.stdout.readline())
    assert process.wait(timeout=5) == 0
    process.stdin.close()
    assert reply == {"jsonrpc": "2.0", "id": 1, "result": RESULT.result}
