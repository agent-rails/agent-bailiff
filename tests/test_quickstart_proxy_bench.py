import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.proxy.task_state import TaskState
from agent_bailiff.task.issue import TaskRequest, issue_task

BENCH = Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "proxy_bench.py"
_spec = importlib.util.spec_from_file_location("quickstart_proxy_bench", BENCH)
assert _spec is not None and _spec.loader is not None
bench = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bench
_spec.loader.exec_module(bench)

NOW = 1_800_000_000
SCOPE = {
    "permissions": [
        {"tools": ["gitea.issues.list"], "resources": ["gitea/repos/quickstart/demo/*"], "max_cost_per_call": 1}
    ]
}
FAKE_PROXY = """
import json, sys
retries = 3
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        continue
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18"}
    elif method == "tools/list":
        result = {"tools": [{"name": "list_issues"}]}
    elif message["params"]["arguments"]["repo"] == "payroll":
        text = "out_of_scope: agent-bailiff refused this call"
        result = {"content": [{"type": "text", "text": text}], "isError": True}
    else:
        result = {"content": [{"type": "text", "text": "[]"}], "isError": False}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\\n")
    sys.stdout.flush()
sys.stderr.write("INFO gateway client closed after %d setup retries\\n" % retries)
"""


@pytest.fixture
def fake_proxy(tmp_path):
    script = tmp_path / "fake_proxy.py"
    script.write_text(FAKE_PROXY)
    return [sys.executable, str(script)]


def test_the_scripted_out_of_scope_share_is_exact_and_never_starts_with_a_refusal():
    for percent in (1, 20, 25, 50, 90):
        scripted = bench.out_of_scope_calls(100, percent)
        assert sum(scripted) == percent
        assert not scripted[0]


def test_the_scripted_calls_spread_across_the_run():
    scripted = bench.out_of_scope_calls(10, 20)
    assert [index for index, out in enumerate(scripted) if out] == [4, 9]


def test_a_session_reports_each_measure_the_benchmark_promises(fake_proxy):
    report = bench.run_session(fake_proxy, 50, 20)
    assert report["calls"] == 50
    assert report["warm_calls"] == 49
    assert report["outcomes"] == {"refused: out_of_scope": 10, "result": 40}
    assert report["refusals_per_100_calls"] == 20.0
    assert report["setup_retries"] == 3
    assert report["retries_per_call"] == 0.06
    assert report["scripted_out_of_scope_percent"] == 20
    for field in (
        "initialize_ms",
        "tools_list_ms",
        "first_call_ms",
        "p50_ms",
        "p99_ms",
        "in_scope_p50_ms",
        "out_of_scope_p50_ms",
    ):
        assert report[field] >= 0
    assert report["p50_ms"] <= report["p99_ms"]


def test_a_missing_retry_log_fails_the_session(tmp_path):
    script = tmp_path / "silent.py"
    script.write_text(FAKE_PROXY.replace("sys.stderr.write", "pass  # "))
    with pytest.raises(bench.BenchFailed, match="did not log its setup retries"):
        bench.run_session([sys.executable, str(script)], 10, 20)


def test_a_proxy_that_exits_early_fails_the_session(tmp_path):
    script = tmp_path / "dead.py"
    script.write_text("import sys\nsys.exit(0)\n")
    with pytest.raises((bench.BenchFailed, BrokenPipeError)):
        bench.run_session([sys.executable, str(script)], 10, 20)


def test_a_proxy_that_exits_with_an_error_fails_the_session(tmp_path):
    script = tmp_path / "failing.py"
    script.write_text(FAKE_PROXY + "\nsys.exit(2)\n")
    with pytest.raises(bench.BenchFailed, match="exited with status 2"):
        bench.run_session([sys.executable, str(script)], 10, 20)


def test_a_run_with_no_warm_call_of_each_kind_is_refused(fake_proxy):
    with pytest.raises(bench.BenchFailed, match="no warm call"):
        bench.run_session(fake_proxy, 3, 1)


def test_an_unexpected_reply_fails_the_session(tmp_path):
    script = tmp_path / "wrong_id.py"
    script.write_text(
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': 99, 'result': {}}) + '\\n')\n"
        "    sys.stdout.flush()\n"
    )
    with pytest.raises(bench.BenchFailed, match="initialize returned"):
        bench.run_session([sys.executable, str(script)], 10, 20)


def test_the_prepared_state_is_a_task_the_real_proxy_state_loader_accepts(tmp_path):
    key = Ed25519PrivateKey.generate()
    request = TaskRequest(purpose="bench", scope=SCOPE, budget=10, subject=encode_public_key(key.public_key()), ttl=600)
    issued = issue_task(Ed25519PrivateKey.generate(), "issuer.quickstart", "decide.quickstart", request, NOW)
    task = {"task_root": issued.root.encode(), "decider_id": "decide.quickstart"}
    task_file, key_dir = bench.prepare_state(task, key, tmp_path)
    state = TaskState.load(task_file, key_dir)
    assert state.subject == encode_public_key(key.public_key())
    assert stat.S_IMODE(os.stat(key_dir).st_mode) == 0o700


def test_the_summary_separates_the_first_call_from_the_warm_calls():
    setup = {"initialize": 0.01, "tools_list": 0.02}
    samples = [(0.5, "result", False), (0.01, "result", False), (0.02, "refused: out_of_scope", True)] + [
        (0.01, "result", False)
    ] * 7
    report = bench.summarize(setup, samples, 0, 20)
    assert report["first_call_ms"] == 500.0
    assert report["p99_ms"] < 500.0
    assert report["refusals_per_100_calls"] == 10.0


def test_retries_from_each_closed_client_are_added():
    assert bench.retries_logged(b"a closed after\ngateway client closed after 1 setup retries\n" * 2) == 2


def test_the_json_the_benchmark_prints_is_serializable(fake_proxy):
    json.dumps(bench.run_session(fake_proxy, 20, 20))


def test_a_proxy_refusal_is_told_from_an_error_that_is_not_one():
    refusal = {
        "content": [{"type": "text", "text": "release_refused: agent-bailiff refused this call"}],
        "isError": True,
    }
    failure = {"content": [{"type": "text", "text": "upstream exploded"}], "isError": True}
    assert bench.classify(refusal) == "refused: release_refused"
    assert bench.classify(failure).startswith("error result: ")
    assert bench.classify({"content": [], "isError": False}) == "result"


def test_a_schedule_that_would_hit_the_custodian_rate_limit_is_refused(fake_proxy):
    with pytest.raises(bench.BenchFailed, match="releases per minute"):
        bench.run_session(fake_proxy, 100, 20)
