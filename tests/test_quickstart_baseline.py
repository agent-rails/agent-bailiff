import importlib.util
import json
import ssl
import sys
import threading
from pathlib import Path

import pytest
from test_quickstart_bootstrap import issue_certificate, pem, private_pem
from test_quickstart_stub_upstream import stub

BASELINE = Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "baseline.py"
_spec = importlib.util.spec_from_file_location("quickstart_baseline", BASELINE)
assert _spec is not None and _spec.loader is not None
baseline = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = baseline
_spec.loader.exec_module(baseline)

READ = {"note": "a"}


@pytest.fixture
def authority(tmp_path):
    ca = issue_certificate("baseline test ca")
    leaf, key = issue_certificate("localhost", issuer=ca, dns_name="localhost")
    (tmp_path / "ca.pem").write_bytes(pem(ca[0]))
    (tmp_path / "server.pem").write_bytes(pem(leaf))
    (tmp_path / "server.key").write_bytes(private_pem(key))
    return tmp_path


@pytest.fixture
def served(authority):
    server = stub.StubUpstream(0)
    server.serve_tls(authority / "server.pem", authority / "server.key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def upstream(served, authority):
    return served, authority / "ca.pem"


def run(upstream, authorization, clients, calls, tool, arguments):
    url, ca_file = upstream
    return baseline.run_baseline(url, authorization, ca_file, clients, calls, tool, arguments)


def test_every_call_is_counted_and_reaches_the_upstream_with_the_credential(upstream, capsys):
    level = run(upstream, "token abc", 2, 5, "read_note", READ)
    assert (level["clients"], level["calls"], level["outcomes"]) == (2, 10, {"result": 10})
    logged = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    calls = [entry for entry in logged if entry["method"] == "tools/call"]
    assert len(calls) == 10
    assert all(entry["credential_sha256"] is not None for entry in calls)


def test_the_level_has_the_fields_of_the_gateway_load_level_that_the_comparison_reads(upstream):
    level = run(upstream, "token abc", 1, 4, "read_note", READ)
    assert set(level) == {"clients", "calls", "seconds", "calls_per_second", "p50_ms", "p99_ms", "outcomes"}
    assert 0 <= level["p50_ms"] <= level["p99_ms"]


def test_a_tool_error_is_counted_as_an_error_result(upstream):
    level = run(upstream, "token abc", 1, 3, "no_such_tool", {})
    assert level["outcomes"] == {"error result": 3}


def test_a_missing_credential_is_an_error_result_not_a_result(upstream):
    level = run(upstream, "", 1, 3, "read_note", READ)
    assert level["outcomes"] == {"error result": 3}


def test_an_unreachable_upstream_fails_the_run(authority):
    with pytest.raises(baseline.BaselineFailed, match="a baseline client failed"):
        run(("https://localhost:1/mcp", authority / "ca.pem"), "token abc", 2, 3, "read_note", READ)


def test_an_upstream_outside_the_configured_ca_fails_the_run(served):
    with pytest.raises(baseline.BaselineFailed, match="CERTIFICATE_VERIFY_FAILED"):
        run((served, None), "token abc", 1, 2, "read_note", READ)


@pytest.mark.parametrize("url", ["http://example.test/mcp", "https:///mcp"])
def test_a_non_https_url_is_refused(url):
    with pytest.raises(ValueError, match="https URL"):
        baseline.DirectClient(url, "token abc", ssl.create_default_context())


def test_an_event_stream_response_is_decoded():
    raw = b'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"content":[]}}\n\n'
    assert baseline.decode(raw, "text/event-stream") == {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}


def test_an_empty_response_decodes_to_nothing():
    assert baseline.decode(b"  ", "application/json") is None


def test_the_percentiles_follow_the_gateway_load_calculation():
    samples = [float(value) for value in range(1, 101)]
    assert baseline.percentile(samples, 0.50) == pytest.approx(50.5)
    assert baseline.percentile(samples, 0.99) == pytest.approx(99.01)
