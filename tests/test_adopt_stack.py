import base64
import hashlib
import json
import os
import pwd
import secrets
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import test_quickstart
import test_quickstart_stack
from test_quickstart_stack import IMAGE, RUN_TIMEOUT_SECONDS, b

from agent_bailiff.custodian.echo import MARKER
from agent_bailiff.proxy.guidance import GUIDANCE, TASK_EXPIRED

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
UPSTREAM = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json")
ROUTES = b.QUICKSTART_UPSTREAMS / json.loads((b.QUICKSTART_UPSTREAMS / "stub.json").read_text())["routes_file"]
ISSUER_UID = b.ISSUER_UID
ALLOWED = "stub/notes/allowed"
SCOPE = {
    "permissions": [{"tools": ["stub.read_note", "stub.write_note"], "resources": [ALLOWED], "max_cost_per_call": 1}]
}
REPLY_TIMEOUT_SECONDS = 30
EXPIRY_DEADLINE_SECONDS = 10
AGENT_USER = os.environ.get("AGENT_BAILIFF_TEST_AGENT_USER")
AGENT_PYTHON = os.environ.get("AGENT_BAILIFF_TEST_AGENT_PYTHON", sys.executable)
AS_AGENT = ["sudo", "-n", "-u", AGENT_USER] if AGENT_USER else []
SHARED_USER_FLAG = [] if AGENT_USER else ["--allow-shared-user"]
DOCKER_SOCKET = "/var/run/docker.sock"
OPEN_PROBE = """
import socket, sys
try:
    open(sys.argv[2], "rb").close()
    key = "opened"
except PermissionError:
    key = "denied"
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    connection.connect(sys.argv[1])
    daemon = "connected"
except PermissionError:
    daemon = "denied"
print(daemon, key)
"""
ISSUER_KEY_MODE = """
import json, os, stat
info = os.stat("/v/issuer-data/issuer.key")
print(json.dumps([info.st_uid, stat.S_IMODE(info.st_mode)]))
"""


def agent_python(*arguments, check=True):
    return subprocess.run(
        [*AS_AGENT, AGENT_PYTHON, "-I", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=check,
    )


def cli(*arguments, check=True):
    return agent_python("-m", "agent_bailiff.cli", *arguments, check=check)


def operator_cli(*arguments):
    return subprocess.run(
        [sys.executable, "-m", "agent_bailiff.cli", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=True,
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
                *AS_AGENT,
                AGENT_PYTHON,
                "-I",
                "-m",
                "agent_bailiff.cli",
                "proxy",
                "run",
                *SHARED_USER_FLAG,
                "--task-file",
                str(adopter.task_file),
                "--key-dir",
                str(adopter.key_dir),
                "--gateway-url",
                adopter.gateway_url,
                "--gateway-ca",
                str(adopter.gateway_ca),
                "--routes",
                str(routes),
            ],  # fmt: skip
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.next_id = 0

    def stderr_text(self):
        os.set_blocking(self.process.stderr.fileno(), False)
        return (self.process.stderr.read() or b"").decode(errors="replace")

    def request(self, method, params=None):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        ready, _, _ = select.select([self.process.stdout], [], [], REPLY_TIMEOUT_SECONDS)
        assert ready, f"no reply to {method} within {REPLY_TIMEOUT_SECONDS} s; stderr: {self.stderr_text()}"
        line = self.process.stdout.readline()
        assert line, f"proxy closed stdout during {method}; stderr: {self.stderr_text()}"
        reply = json.loads(line)
        assert reply["id"] == self.next_id, (reply, self.stderr_text())
        return reply

    def call(self, name, **arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})["result"]

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=RUN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            raise AssertionError(f"proxy did not exit; stderr: {self.stderr_text()}") from None
        self.process.stderr.close()


class Adopter:
    def __init__(self, stack, root):
        self.stack = stack
        self.root = root
        self.key_dir = root / "keys"
        self.task_dir = root / "tasks"
        self.task_file = self.task_dir / "task.json"
        self.routes = root / "routes.json"
        self.gateway_url = stack.gateway_url
        self.gateway_ca = stack.gateway_ca
        os.chmod(root, 0o755)
        if AGENT_USER:
            subprocess.run(
                ["sudo", "-n", "install", "-d", "-o", AGENT_USER, "-m", "0700", str(self.key_dir)], check=True
            )
        else:
            self.key_dir.mkdir(mode=0o700)
        self.task_dir.mkdir(mode=0o755)
        os.chmod(self.task_dir, 0o755)
        shutil.copyfile(ROUTES, self.routes)
        stack.env["BAILIFF_TASK_DIR"] = str(self.task_dir)

    def remove(self):
        if AGENT_USER:
            subprocess.run(["sudo", "-n", "rm", "-rf", str(self.key_dir)], check=True)
        shutil.rmtree(self.root)

    def key_subjects(self):
        script = "import os, sys; print(' '.join(sorted(os.listdir(sys.argv[1]))))"
        names = agent_python("-c", script, self.key_dir).stdout.split()
        return sorted(name.removesuffix(".key") for name in names if name.endswith(".key"))

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
def adopter(stack, secret):
    adopter = Adopter(stack, Path(tempfile.mkdtemp(prefix="bailiff-adopt-")))
    own_directory(adopter.task_dir, ISSUER_UID)
    try:
        yield adopter
    finally:
        own_directory(adopter.task_dir, os.getuid())
        adopter.remove()


@pytest.fixture(scope="module")
def proxy(adopter):
    adopter.issue()
    proxy = Proxy(adopter, adopter.routes)
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
                 "--gateway-url", adopter.gateway_url, "--gateway-ca", adopter.gateway_ca).stdout  # fmt: skip
    tools.write_text(output)
    draft = tmp_path / "routes.json"
    operator_cli("routes", "generate", "--tools", tools, "--service", UPSTREAM.service, "--out", draft)
    routes = json.loads(draft.read_text())["routes"]
    assert [(route["name"], route["tool"], route["resource"]) for route in routes] == [
        ("delete_all_notes", "stub.delete_all_notes", ""),
        ("echo_auth", "stub.echo_auth", ""),
        ("read_note", "stub.read_note", ""),
        ("write_note", "stub.write_note", ""),
    ]


def test_the_proxy_lists_only_routed_tools(proxy):
    assert proxy.request("initialize", {"protocolVersion": "2025-06-18"})["result"]["serverInfo"]["name"]
    tools = proxy.request("tools/list")["result"]["tools"]
    assert sorted(tool["name"] for tool in tools) == ["echo_auth", "read_note", "write_note"]


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


def test_an_echoed_credential_is_redacted_and_alerted_against_its_release(adopter, proxy, secret):
    echo = {"tools": ["stub.echo_auth"], "resources": [ALLOWED], "max_cost_per_call": 1}
    task_id, _ = adopter.issue(scope={"permissions": [*SCOPE["permissions"], echo]})
    assert proxy.call("write_note", note="allowed", text="plain") == {
        "content": [{"type": "text", "text": "wrote allowed"}],
        "isError": False,
    }
    before = len(adopter.upstream_calls())
    echoed = proxy.call("echo_auth", note="allowed")
    assert echoed["isError"] is False, echoed
    [content] = echoed["content"]
    assert content["text"].count(MARKER) == 2, content
    assert secret not in content["text"]
    assert base64.b64encode(secret.encode()).decode() not in content["text"]
    [upstream_call] = adopter.upstream_calls()[before:]
    assert upstream_call["tool"] == "echo_auth"
    entries = [row["entry"] for row in test_quickstart.verified_rows(adopter.stack, task_id)]
    releases = {entry["entry_id"]: entry for entry in entries if entry["decision"] == "release"}
    alerts = [entry for entry in entries if entry["decision"] == "alert"]
    assert [(alert["reason"], alert["tool"], alert["op_id"]) for alert in alerts] == [
        ("credential_echo", "stub.echo_auth", releases[alerts[0]["parent_entry"]]["op_id"])
    ]
    assert releases[alerts[0]["parent_entry"]]["tool"] == "stub.echo_auth"


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
    assert adopter.key_subjects() == sorted([old, new])
    assert proxy.call("read_note", note="allowed")["isError"] is False
    assert adopter.key_subjects() == [new]


def test_a_revoked_task_is_refused(adopter, proxy):
    task_id, _ = adopter.issue()
    assert proxy.call("read_note", note="allowed")["isError"] is False
    revoked = test_quickstart.revoke_task(adopter.stack, task_id)
    assert revoked["handles"] == {"task": task_id, "tenant": b.TENANT}
    assert refusal(proxy.call("read_note", note="allowed"), "chain_invalid")


def test_a_route_the_gateway_lacks_is_refused(adopter, proxy):
    delete_all = {"tools": ["stub.delete_all_notes"], "resources": ["stub/notes"], "max_cost_per_call": 1}
    adopter.issue(scope={"permissions": [*SCOPE["permissions"], delete_all]})
    drifted = adopter.root / "drifted-routes.json"
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


@pytest.mark.skipif(not AGENT_USER, reason="set AGENT_BAILIFF_TEST_AGENT_USER to a user outside the docker group")
def test_the_agent_user_reaches_neither_the_docker_daemon_nor_the_issuer_key(adopter):
    volume = f"{adopter.stack.project}_issuer-data"
    mountpoint = subprocess.run(
        ["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", volume],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=True,
    ).stdout.strip()
    probe = agent_python("-c", OPEN_PROBE, DOCKER_SOCKET, f"{mountpoint}/issuer.key")
    assert probe.stdout.split() == ["denied", "denied"], probe
    assert pwd.getpwnam(AGENT_USER).pw_uid != b.ISSUER_UID
    assert adopter.stack.probe(ISSUER_KEY_MODE) == [b.ISSUER_UID, 0o600]


def test_the_proxy_run_by_a_user_who_reaches_docker_refuses_without_the_flag(adopter):
    environ = {key: value for key, value in os.environ.items() if key != "DOCKER_HOST"}
    done = subprocess.run(
        [
            sys.executable, "-m", "agent_bailiff.cli", "proxy", "run",
            "--task-file", str(adopter.task_file), "--key-dir", str(adopter.key_dir),
            "--gateway-url", adopter.gateway_url, "--gateway-ca", str(adopter.gateway_ca),
            "--routes", str(adopter.routes),
        ],
        input=b"",
        capture_output=True,
        env=environ,
        timeout=RUN_TIMEOUT_SECONDS,
        check=False,
    )  # fmt: skip
    assert done.returncode == 1, done.stderr
    assert b"proxy run refused" in done.stderr, done.stderr
    assert DOCKER_SOCKET.encode() in done.stderr, done.stderr
