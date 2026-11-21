import json
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
import test_quickstart_stack
from test_quickstart import agent, verified_rows
from test_quickstart_stack import b

from agent_bailiff.docket.otlp import span_id_for, trace_id_for

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
PROFILES = ("trace", "rule")
DECIDE = b.NAMES["decide"]
RULE = b.NAMES["rule"]
RULE_TIMEOUT_SECONDS = 60
INJECTED = {
    "allowed call reaches gitea": "result",
    "injected out-of-scope call refused": "refused: out_of_scope",
}

EXPORT_TIMEOUT_SECONDS = 60
CHECKPOINT_SCRIPT = """
import json, os, stat, sys
info = os.lstat(sys.argv[1])
json.dump([info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)], sys.stdout)
"""
PROGRESS_SCRIPT = """
import json, sys
with open("/v/docket-data/docket.log", "rb") as docket:
    lines = docket.read().count(b"\\n")
try:
    with open("/v/exporter-data/checkpoint.json", "rb") as checkpoint:
        exported = json.load(checkpoint)["entries"]
except FileNotFoundError:
    exported = 0
json.dump({"docket": lines, "exported": exported}, sys.stdout)
"""


def jaeger(stack, path, **query):
    suffix = f"?{urllib.parse.urlencode(query)}" if query else ""
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{stack.jaeger_port}/api/v3{path}{suffix}", timeout=5
        ) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise


def spans_in(document):
    return [
        span
        for resource in document.get("result", {}).get("resourceSpans", [])
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
    ]


def attribute(span, key):
    values = [item["value"] for item in span["attributes"] if item["key"] == key]
    assert len(values) == 1, (key, span)
    return next(iter(values[0].values()))


def wait_for_export(stack):
    began = time.monotonic()
    progress = stack.probe(PROGRESS_SCRIPT)
    backlog = progress["docket"] - progress["exported"]
    while progress["exported"] < progress["docket"]:
        assert time.monotonic() - began < EXPORT_TIMEOUT_SECONDS, progress
        time.sleep(1)
        progress = stack.probe(PROGRESS_SCRIPT)
    return {"exported": progress["exported"], "backlog": backlog, "seconds": time.monotonic() - began}


def expected_spans(rows):
    expected = {}
    for row in rows:
        entry = row["entry"]
        trace_id, _ = trace_id_for(entry["trace_id"], entry["entry_id"])
        parent = span_id_for(entry["parent_entry"]) if entry.get("parent_entry") else None
        expected[span_id_for(entry["entry_id"])] = (trace_id, parent, row["line"])
    return expected


def exported_spans(stack, trace_ids, wanted):
    deadline = time.monotonic() + EXPORT_TIMEOUT_SECONDS
    while True:
        spans = {
            int(span["spanId"], 16): span
            for trace_id in trace_ids
            for span in spans_in(jaeger(stack, f"/traces/{trace_id:032x}"))
        }
        if wanted <= set(spans) or time.monotonic() > deadline:
            return spans
        time.sleep(1)


def rule_revokes(rows):
    return [row for row in rows if row["writer"] == RULE and row["entry"]["decision"] == "revoke"]


@pytest.fixture(scope="module")
def revoked(stack):
    task_id, observed = agent(stack, "inject")
    assert observed == INJECTED
    deadline = time.monotonic() + RULE_TIMEOUT_SECONDS
    while not rule_revokes(verified_rows(stack, task_id)):
        assert time.monotonic() < deadline, "the rule did not revoke the task"
        time.sleep(1)
    after_task, after = agent(stack, "after-revoke")
    assert after_task == task_id
    assert after == {"call after revoke refused": "refused: chain_invalid"}
    return task_id, verified_rows(stack, task_id)


def test_an_out_of_scope_refusal_revokes_its_task_through_the_rule(stack, revoked):
    task_id, rows = revoked
    refusals = [
        row["entry"]
        for row in rows
        if row["writer"] == DECIDE and (row["entry"]["decision"], row["entry"]["reason"]) == ("refuse", "out_of_scope")
    ]
    assert [entry["tool"] for entry in refusals] == ["gitea.contents.read"]
    [revoke] = [row["entry"] for row in rule_revokes(rows)]
    assert revoke["parent_entry"] == refusals[0]["entry_id"]
    assert (revoke["principal"], revoke["reason"], revoke["tenant"]) == ("rule", "task", b.TENANT)
    assert not [row for row in rows if row["writer"] == b.NAMES["control"]]
    checkpoint = "/v/rule-data/checkpoint.json"
    assert stack.probe(CHECKPOINT_SCRIPT, arguments=[checkpoint]) == [b.DECIDE_UID, b.LEDGER_GID, 0o600]


def test_every_verified_record_is_a_span_under_its_parent(stack, revoked):
    _, rows = revoked
    expected = expected_spans(rows)
    spans = exported_spans(stack, {trace_id for trace_id, _, _ in expected.values()}, set(expected))
    assert set(expected) <= set(spans), sorted(set(expected) - set(spans))
    children = 0
    for span_id, (trace_id, parent, line) in expected.items():
        span = spans[span_id]
        assert int(span["traceId"], 16) == trace_id
        assert int(attribute(span, "bailiff.docket.line")) == line
        if parent is None:
            assert not span.get("parentSpanId"), span
            continue
        children += 1
        assert span["parentSpanId"] == f"{parent:016x}", span
        assert spans[parent]["traceId"] == span["traceId"]
    assert children == 3
    checkpoint = "/v/exporter-data/checkpoint.json"
    assert stack.probe(CHECKPOINT_SCRIPT, arguments=[checkpoint]) == [b.EXPORTER_UID, b.EXPORTER_UID, 0o600]


def test_the_exporter_runs_as_its_own_uid(stack):
    identity = test_quickstart_stack.identity(stack.container("exporter"))
    assert identity == {(b.EXPORTER_UID, b.EXPORTER_UID, frozenset({b.EXPORTER_UID, b.DOCKET_READERS_GID}))}


def test_the_trace_image_ships_without_pip(stack):
    assert test_quickstart_stack.pip_absent(stack, "exporter")


def test_the_rule_runs_as_decide_with_docket_access(stack):
    identity = test_quickstart_stack.identity(stack.container("rule"))
    groups = frozenset({b.LEDGER_GID, b.DOCKET_WRITERS_GID, b.DOCKET_READERS_GID})
    assert identity == {(b.DECIDE_UID, b.LEDGER_GID, groups)}


def test_the_rule_restarts_on_failure_and_its_init_reads_decide_only(stack):
    services = json.loads(stack.compose("--profile", "rule", "config", "--format", "json"))["services"]
    assert services["rule"]["restart"] == "on-failure"
    decide = [volume for volume in services["rule-init"]["volumes"] if volume["source"] == "decide-data"]
    assert [volume.get("read_only", False) for volume in decide] == [True]
