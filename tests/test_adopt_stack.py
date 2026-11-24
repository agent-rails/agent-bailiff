import hashlib
import json
import os
import secrets
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest
import test_quickstart
import test_quickstart_stack
from test_quickstart_stack import IMAGE, RUN_TIMEOUT_SECONDS, b

from agent_bailiff.proxy.guidance import GUIDANCE, TASK_EXPIRED

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
UPSTREAM = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json")
ROUTES = b.QUICKSTART_UPSTREAMS / json.loads((b.QUICKSTART_UPSTREAMS / "stub.json").read_text())["routes_file"]
ISSUER_UID = b.ISSUER_UID
ALLOWED = "stub/notes/allowed"
SCOPE = {"tools": ["stub.read_note", "stub.write_note"], "resources": [ALLOWED], "max_cost_per_call": 1}
REPLY_TIMEOUT_SECONDS = 30
EXPIRY_DEADLINE_SECONDS = 10


def cli(*arguments, check=True):
    return subprocess.run(
        [sys.executable, "-m", "agent_bailiff.cli", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=check,
    )


def own_directory(path, uid):
    script = (
        "import os, sys\n"
        "for root, dirs, files in os.walk('/out'):\n"
        "    for name in [root, *(os.path.join(root, f) for f in files)]:\n"
        "        os.chown(name, int(sys.argv[1]), int(sys.argv[1]))\n"
    )
    command = [
        "docker", "run", "--rm", "--network", "none", "--user", "0:0", "--read-only", "--cap-drop", "ALL",
        "--cap-add", "CHOWN", "--volume", f"{path}:/out", IMAGE, "-c", script, str(uid),
    ]  # fmt: skip
    subprocess.run(command, capture_output=True, timeout=RUN_TIMEOUT_SECONDS, check=True)


class Proxy:
    def __init__(self, adopter, routes):
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agent_bailiff.cli",
                "proxy",
                "run",
                "--task-file",
                str(adopter.task_file),
                "--key-dir",
                str(adopter.key_dir),
                "--gateway-url",
                adopter.gateway_url,
                "--routes",
                str(routes),
            ],  # fmt: skip
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self.next_id = 0

    def request(self, method, params=None):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        ready, _, _ = select.select([self.process.stdout], [], [], REPLY_TIMEOUT_SECONDS)
        assert ready, f"no reply to {method} within {REPLY_TIMEOUT_SECONDS} s"
        reply = json.loads(self.process.stdout.readline())
        assert reply["id"] == self.next_id, reply
        return reply

    def call(self, name, **arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})["result"]

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=RUN_TIMEOUT_SECONDS)


class Adopter:
    def __init__(self, stack, root):
        self.stack = stack
        self.key_dir = root / "keys"
        self.task_dir = root / "tasks"
        self.task_file = self.task_dir / "task.json"
        self.gateway_url = f"http://127.0.0.1:{stack.gateway_port}/mcp"
        self.key_dir.mkdir(mode=0o700)
        self.task_dir.mkdir(mode=0o755)
        os.chmod(self.task_dir, 0o755)
        stack.env["BAILIFF_TASK_DIR"] = str(self.task_dir)

    def keygen(self):
        return cli("proxy", "keygen", "--key-dir", self.key_dir).stdout.strip()

    def issue(self, *, scope=SCOPE, budget=20, ttl=3600):
        subject = self.keygen()
        output = self.stack.compose(
            "--profile", "operator", "run", "--rm", "--no-deps", "-T", "task-issuer",
            "--purpose", "adopt-the-stack", "--scope", json.dumps(scope), "--budget", str(budget),
            "--ttl", str(ttl), f"--subject={subject}",
        )  # fmt: skip
        return output.strip().splitlines()[-1], subject

    def upstream_calls(self):
        output = self.stack.compose("logs", "--no-log-prefix", "stub-upstream")
        lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        return [line for line in lines if line["method"] == "tools/call"]


@pytest.fixture(scope="module")
def secret(stack):
    value = secrets.token_hex(16)
    stack.compose(
        "run", "--rm", "--no-deps", "-T", "custodian", "-m", "agent_bailiff.cli", "custodian", "put-credential",
        "--config", "/var/lib/bailiff/custodian/config.json", "--tenant", b.TENANT,
        "--credential-id", UPSTREAM.credential_id, "--target", UPSTREAM.target,
        stdin=value,
    )  # fmt: skip
    return value


@pytest.fixture(scope="module")
def adopter(stack, secret, tmp_path_factory):
    adopter = Adopter(stack, tmp_path_factory.mktemp("adopt"))
    own_directory(adopter.task_dir, ISSUER_UID)
    try:
        yield adopter
    finally:
        own_directory(adopter.task_dir, os.getuid())


@pytest.fixture(scope="module")
def proxy(adopter):
    adopter.issue()
    proxy = Proxy(adopter, ROUTES)
    try:
        yield proxy
    finally:
        proxy.close()


def refusal(result, reason):
    assert result["isError"] is True, result
    return result["content"][0]["text"].startswith(f"{reason}: ")


def test_routes_generate_drafts_every_upstream_tool(adopter, proxy, tmp_path):
    tools = tmp_path / "tools.json"
    output = cli("proxy", "tools", "--task-file", adopter.task_file, "--key-dir", adopter.key_dir,
                 "--gateway-url", adopter.gateway_url).stdout  # fmt: skip
    tools.write_text(output)
    draft = tmp_path / "routes.json"
    cli("routes", "generate", "--tools", tools, "--service", UPSTREAM.service, "--out", draft)
    routes = json.loads(draft.read_text())["routes"]
    assert [(route["name"], route["tool"], route["resource"]) for route in routes] == [
        ("delete_all_notes", "stub.delete_all_notes", ""),
        ("read_note", "stub.read_note", ""),
        ("write_note", "stub.write_note", ""),
    ]


def test_the_proxy_lists_only_routed_tools(proxy):
    assert proxy.request("initialize", {"protocolVersion": "2025-06-18"})["result"]["serverInfo"]["name"]
    tools = proxy.request("tools/list")["result"]["tools"]
    assert sorted(tool["name"] for tool in tools) == ["read_note", "write_note"]


def test_an_in_scope_call_reaches_the_upstream_with_the_stored_credential(adopter, proxy, secret):
    before = len(adopter.upstream_calls())
    assert proxy.call("write_note", note="allowed", text="hello") == {
        "content": [{"type": "text", "text": "wrote allowed"}],
        "isError": False,
    }
    assert proxy.call("read_note", note="allowed")["content"][0]["text"] == "hello"
    calls = adopter.upstream_calls()[before:]
    assert [call["tool"] for call in calls] == ["write_note", "read_note"]
    assert {call["credential_sha256"] for call in calls} == {hashlib.sha256(secret.encode()).hexdigest()}


def test_an_out_of_scope_call_is_refused_with_guidance(adopter, proxy):
    before = len(adopter.upstream_calls())
    result = proxy.call("read_note", note="payroll")
    assert refusal(result, "out_of_scope")
    assert result["content"][0]["text"].endswith(GUIDANCE["stop"])
    assert len(adopter.upstream_calls()) == before


def test_an_exhausted_budget_is_refused_with_guidance(adopter, proxy):
    adopter.issue(budget=2)
    assert [proxy.call("read_note", note="allowed")["isError"] for _ in range(2)] == [False, False]
    result = proxy.call("read_note", note="allowed")
    assert refusal(result, "reservation_refused")
    assert result["content"][0]["text"].endswith(GUIDANCE["stop"]), result


def test_an_expired_task_sends_nothing(adopter, proxy):
    adopter.issue(ttl=3)
    expires_at = json.loads(adopter.task_file.read_text())["expires_at"]
    deadline = time.monotonic() + EXPIRY_DEADLINE_SECONDS
    while time.time() < expires_at:
        assert time.monotonic() < deadline, "the task did not expire in time"
        time.sleep(0.2)
    before = len(adopter.upstream_calls())
    assert proxy.call("read_note", note="allowed") == {
        "content": [{"type": "text", "text": TASK_EXPIRED}],
        "isError": True,
    }
    assert len(adopter.upstream_calls()) == before


def test_a_renewed_task_succeeds_and_prunes_the_old_key(adopter, proxy):
    _, old = adopter.issue()
    assert proxy.call("read_note", note="allowed")["isError"] is False
    _, new = adopter.issue()
    assert sorted(path.stem for path in adopter.key_dir.glob("*.key")) == sorted([old, new])
    assert proxy.call("read_note", note="allowed")["isError"] is False
    assert [path.stem for path in adopter.key_dir.glob("*.key")] == [new]


def test_a_revoked_task_is_refused(adopter, proxy):
    task_id, _ = adopter.issue()
    assert proxy.call("read_note", note="allowed")["isError"] is False
    revoked = test_quickstart.revoke_task(adopter.stack, task_id)
    assert revoked["handles"] == {"task": task_id, "tenant": b.TENANT}
    assert refusal(proxy.call("read_note", note="allowed"), "chain_invalid")


def test_a_route_the_gateway_lacks_is_refused(adopter, proxy, tmp_path):
    adopter.issue(scope={**SCOPE, "tools": [*SCOPE["tools"], "stub.delete_all_notes"], "resources": ["stub/notes"]})
    drifted = tmp_path / "routes.json"
    document = json.loads(ROUTES.read_text())
    document["routes"].append({"service": "stub", "name": "delete_all_notes", "tool": "stub.delete_all_notes",
                               "resource": "stub/notes"})  # fmt: skip
    drifted.write_text(json.dumps(document))
    drifting = Proxy(adopter, drifted)
    try:
        before = len(adopter.upstream_calls())
        result = drifting.call("delete_all_notes")
        assert refusal(result, "unknown_tool"), result
        assert len(adopter.upstream_calls()) == before
    finally:
        drifting.close()


def test_the_task_directory_is_not_created_for_the_operator(adopter, tmp_path):
    adopter.stack.env["BAILIFF_TASK_DIR"] = str(tmp_path / "missing")
    try:
        subject = adopter.keygen()
        adopter.stack.compose(
            "--profile", "operator", "run", "--rm", "--no-deps", "-T", "task-issuer", "--purpose", "missing",
            "--scope", json.dumps(SCOPE), "--budget", "1", f"--subject={subject}",
            expect=1,
        )  # fmt: skip
        assert not Path(tmp_path / "missing").exists()
    finally:
        adopter.stack.env["BAILIFF_TASK_DIR"] = str(adopter.task_dir)
