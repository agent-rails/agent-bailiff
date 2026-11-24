import importlib.util
import json
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
    assert [tool["name"] for tool in reply["result"]["tools"]] == ["read_note", "write_note", "delete_all_notes"]


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
