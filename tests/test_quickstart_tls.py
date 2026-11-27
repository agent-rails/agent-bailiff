import hashlib
import json
import os
import shutil
import socket
import ssl
import tempfile
import time
import uuid
from pathlib import Path

import pytest
import test_adopt_stack
import test_quickstart_stack
from test_adopt_stack import ALLOWED, Proxy
from test_quickstart_bootstrap import issue_certificate, pem, private_pem
from test_quickstart_stack import RUN_TIMEOUT_SECONDS, Stack, b, started

pytestmark = test_quickstart_stack.pytestmark
secret = test_adopt_stack.secret
adopter = test_adopt_stack.adopter
proxy = test_adopt_stack.proxy
OVERRIDE = Path(__file__).resolve().parent / "fixtures" / "quickstart-tls.compose.yaml"
GATEWAY_START_SECONDS = 30
FATAL_DECODE_ERROR_ALERT = b"\x15\x03\x03\x00\x02\x02\x32"


def write_tls_files(root):
    certs, upstreams = root / "certs", root / "upstreams"
    for directory in (root, certs, upstreams):
        directory.mkdir(exist_ok=True)
        os.chmod(directory, 0o755)
    trusted = issue_certificate("quickstart tls test ca")
    untrusted = issue_certificate("quickstart untrusted test ca")
    for host, issuer in (("tls-upstream", trusted), ("tls-other", trusted), ("tls-stranger", untrusted)):
        leaf, key = issue_certificate(host, issuer=issuer, dns_name=host)
        (certs / f"{host}.pem").write_bytes(pem(leaf))
        (certs / f"{host}.key").write_bytes(private_pem(key))
        os.chmod(certs / f"{host}.key", 0o644)
    (upstreams / "ca.pem").write_bytes(pem(trusted[0]))
    shutil.copyfile(b.QUICKSTART_UPSTREAMS / "stub-routes.json", upstreams / "stub-routes.json")
    stub = json.loads((b.QUICKSTART_UPSTREAMS / "stub.json").read_text())
    for name, host in (("tls", "tls-upstream"), ("stranger", "tls-stranger")):
        document = {**stub, "url": f"https://{host}:8443/mcp", "ca_file": "ca.pem"}
        (upstreams / f"{name}.json").write_text(json.dumps(document))
    return certs, upstreams


@pytest.fixture(scope="module")
def stack():
    root = Path(tempfile.mkdtemp(prefix="bailiff-tls-"))
    try:
        certs, upstreams = write_tls_files(root)
        env = {"UPSTREAM": "tls", "BAILIFF_UPSTREAMS": str(upstreams), "BAILIFF_TEST_CERTS": str(certs)}
        with started(Stack(f"bailiff-qs-{uuid.uuid4().hex[:8]}", files=(OVERRIDE,), env=env)) as running:
            yield running
    finally:
        shutil.rmtree(root)


def calls(stack, host):
    output = stack.compose("logs", "--no-log-prefix", host)
    lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    return [line for line in lines if line["method"] == "tools/call"]


def point_gateway(stack, upstream):
    stack.env["UPSTREAM"] = upstream
    stack.compose("run", "--rm", "--no-deps", "-T", "gateway-init")
    stack.compose("run", "--rm", "--no-deps", "-T", "gateway-check")
    stack.compose("restart", "gateway", timeout=RUN_TIMEOUT_SECONDS)
    wait_for_gateway(stack)


def wait_for_gateway(stack):
    deadline = time.monotonic() + GATEWAY_START_SECONDS
    while True:
        try:
            socket.create_connection(("127.0.0.1", stack.gateway_port), timeout=1).close()
            return
        except OSError:
            assert time.monotonic() < deadline, "the gateway did not come back"
            time.sleep(0.5)


GATEWAY_FILES = """
import json, pathlib
root = pathlib.Path("/v/gateway-config")
print(json.dumps({"config": json.loads((root / "gateway.json").read_text()), "ca": (root / "ca.pem").read_text()}))
"""


def test_the_gateway_trusts_only_the_configured_ca(stack):
    files = stack.probe(GATEWAY_FILES)
    upstreams = Path(stack.env["BAILIFF_UPSTREAMS"])
    assert files["ca"] == (upstreams / "ca.pem").read_text()
    assert files["config"]["mcp"]["targets"] == [
        {
            "name": "stub",
            "mcp": {"host": "https://tls-upstream:8443/mcp"},
            "policies": {"backendTLS": {"root": "/var/lib/bailiff/gateway/ca.pem"}},
        }
    ]


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_the_gateway_serves_its_install_leaf_on_loopback(stack, host):
    context = ssl.create_default_context(cafile=stack.gateway_ca)
    with (
        socket.create_connection((host, stack.gateway_port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        assert tls.version() in ("TLSv1.2", "TLSv1.3")


def test_plain_http_to_the_gateway_gets_no_mcp_answer(stack):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    request = (
        "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\n"
        f"content-length: {len(body)}\r\nconnection: close\r\n\r\n{body}"
    )
    with socket.create_connection(("127.0.0.1", stack.gateway_port), timeout=5) as raw:
        raw.sendall(request.encode())
        answer = b""
        while chunk := raw.recv(4096):
            answer += chunk
    assert answer == FATAL_DECODE_ERROR_ALERT, answer


def test_a_client_pinning_the_install_ca_lists_the_tools(stack, adopter, proxy):
    result = test_adopt_stack.cli(
        "proxy", "tools", "--task-file", adopter.task_file, "--key-dir", adopter.key_dir,
        "--gateway-url", adopter.gateway_url, "--gateway-ca", adopter.gateway_ca, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert any(tool["name"].endswith("write_note") for tool in json.loads(result.stdout)["tools"]), result.stdout


@pytest.mark.parametrize("pinned", ["another", "system roots"])
def test_a_client_without_the_install_ca_is_refused_before_sending_a_proof(stack, adopter, proxy, pinned):
    pin = []
    if pinned == "another":
        other = adopter.root / "another-ca.pem"
        other.write_bytes(pem(issue_certificate("another quickstart ca")[0]))
        os.chmod(other, 0o644)
        pin = ["--gateway-ca", other]
    before = len(calls(stack, "tls-upstream"))
    result = test_adopt_stack.cli(
        "proxy", "tools", "--task-file", adopter.task_file, "--key-dir", adopter.key_dir,
        "--gateway-url", adopter.gateway_url, *pin, check=False,
    )  # fmt: skip
    assert result.returncode == 1, result.stderr
    assert "CERTIFICATE_VERIFY_FAILED" in result.stderr, result.stderr
    assert len(calls(stack, "tls-upstream")) == before


def test_a_call_reaches_the_https_upstream_with_the_stored_credential(stack, proxy, secret):
    assert proxy.call("write_note", note="allowed", text="over tls") == {
        "content": [{"type": "text", "text": "wrote allowed"}],
        "isError": False,
    }
    written = calls(stack, "tls-upstream")
    assert [call["tool"] for call in written] == ["write_note"]
    assert written[0]["credential_sha256"] == hashlib.sha256(secret.encode()).hexdigest()


def test_a_redirect_to_another_host_is_not_followed(stack, proxy):
    result = proxy.call("read_note", note=ALLOWED.rsplit("/", 1)[1])
    assert result["content"][0]["text"].startswith("outcome_unknown: http_307;"), result
    assert [call["tool"] for call in calls(stack, "tls-upstream")][-1] == "read_note"
    assert calls(stack, "tls-other") == []


def test_an_upstream_outside_the_configured_ca_is_refused(stack, adopter):
    point_gateway(stack, "stranger")
    try:
        adopter.issue()
        stranger = Proxy(adopter, adopter.routes)
        try:
            result = stranger.call("write_note", note="allowed", text="never")
            assert result["isError"] is True, result
            assert calls(stack, "tls-stranger") == []
            assert "invalid peer certificate: UnknownIssuer" in stack.compose("logs", "--no-log-prefix", "gateway")
        finally:
            stranger.close()
    finally:
        point_gateway(stack, "tls")
