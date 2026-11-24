import base64
import importlib.util
import json
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

SERVER = Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "stub-upstream" / "server.py"
_spec = importlib.util.spec_from_file_location("quickstart_stub_upstream", SERVER)
assert _spec is not None and _spec.loader is not None
stub = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = stub
_spec.loader.exec_module(stub)


@pytest.fixture
def server():
    upstream = stub.StubUpstream(0)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{upstream.server_address[1]}/mcp"
    finally:
        upstream.shutdown()
        upstream.server_close()


def post(url, body, authorization=None):
    headers = {"content-type": "application/json"}
    if authorization:
        headers["authorization"] = authorization
    request = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read() or b"null")


def call(url, name, arguments, authorization="Bearer stub"):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    return post(url, body, authorization)[1]["result"]


def test_it_lists_its_tools(server):
    status, reply = post(server, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert status == 200
    assert [tool["name"] for tool in reply["result"]["tools"]] == [
        "read_note",
        "write_note",
        "delete_all_notes",
        "echo_auth",
    ]


def test_initialize_echoes_the_protocol_version(server):
    params = {"protocolVersion": "2025-03-26"}
    reply = post(server, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})[1]
    assert reply["result"]["protocolVersion"] == "2025-03-26"


def test_a_notification_gets_202(server):
    assert post(server, {"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == 202


def test_a_call_without_a_credential_is_refused(server):
    assert call(server, "read_note", {"note": "a"}, authorization=None) == {
        "content": [{"type": "text", "text": "missing credential"}],
        "isError": True,
    }


def test_a_written_note_reads_back(server):
    assert call(server, "write_note", {"note": "plan", "text": "ship it"})["isError"] is False
    assert call(server, "read_note", {"note": "plan"})["content"][0]["text"] == "ship it"


def test_echo_auth_returns_the_credential_raw_and_in_base64(server):
    result = call(server, "echo_auth", {"note": "a"}, authorization="Bearer secret-value")
    encoded = base64.b64encode(b"Bearer secret-value").decode()
    assert result == {
        "content": [{"type": "text", "text": f"authorization: Bearer secret-value\nbase64: {encoded}"}],
        "isError": False,
    }


def test_echo_auth_without_a_credential_is_refused(server):
    assert call(server, "echo_auth", {"note": "a"}, authorization=None)["isError"] is True


def test_an_unknown_tool_is_an_error(server):
    assert call(server, "drop_tables", {})["isError"] is True


def test_the_log_holds_only_a_credential_digest(server, capsys):
    call(server, "read_note", {"note": "a"}, authorization="Bearer secret-value")
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["tool"] == "read_note"
    assert "secret-value" not in json.dumps(line)
    assert len(line["credential_sha256"]) == 64


@pytest.mark.parametrize("body", [b"", b"{", b"[]"])
def test_a_malformed_body_is_refused(server, body):
    request = urllib.request.Request(server, body, {"content-type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=5)
    assert error.value.code == 400


def test_an_oversized_body_is_refused(server):
    request = urllib.request.Request(server, b"x", {"content-length": str(stub.MAX_BODY_BYTES + 1)}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=5)
    assert error.value.code == 413


def test_a_stalled_connection_is_closed(server, monkeypatch):
    assert stub.Handler.timeout == stub.READ_TIMEOUT_SECONDS
    monkeypatch.setattr(stub.Handler, "timeout", 0.2)
    port = int(server.rsplit(":", 1)[1].split("/")[0])
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(b"POST /mcp HTTP/1.1\r\ncontent-length: 10\r\n\r\n{")
        assert connection.recv(1024) == b""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def start(upstream):
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    return upstream


def test_a_redirected_tool_answers_307_and_other_tools_still_work():
    upstream = start(stub.StubUpstream(0, {"delete_all_notes": "https://elsewhere.example/mcp"}))
    url = f"http://127.0.0.1:{upstream.server_address[1]}/mcp"
    try:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "delete_all_notes"}}
        request = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.build_opener(NoRedirect).open(request, timeout=5)
        assert (error.value.code, error.value.headers["location"]) == (307, "https://elsewhere.example/mcp")
        assert call(url, "read_note", {"note": "x"})["isError"] is False
    finally:
        upstream.shutdown()
        upstream.server_close()


def test_it_serves_tls_with_the_given_certificate(tmp_path):
    from test_quickstart_bootstrap import issue_certificate, pem, private_pem

    ca = issue_certificate("stub test ca")
    leaf, key = issue_certificate("localhost", issuer=ca, dns_name="localhost")
    (tmp_path / "server.pem").write_bytes(pem(leaf))
    (tmp_path / "server.key").write_bytes(private_pem(key))
    upstream = stub.StubUpstream(0)
    upstream.serve_tls(tmp_path / "server.pem", tmp_path / "server.key")
    start(upstream)
    try:
        context = ssl.create_default_context(cadata=pem(ca[0]).decode())
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        request = urllib.request.Request(
            f"https://localhost:{upstream.server_address[1]}/mcp",
            json.dumps(body).encode(),
            {"content-type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5, context=context) as response:
            assert response.status == 200
        with pytest.raises(urllib.error.URLError, match="CERTIFICATE_VERIFY_FAILED"):
            urllib.request.urlopen(request, timeout=5, context=ssl.create_default_context())
    finally:
        upstream.shutdown()
        upstream.server_close()
