import json
import time
import urllib.error
import urllib.parse
import urllib.request

import test_quickstart_stack
from test_quickstart import agent, verified_rows
from test_quickstart_stack import b

from agent_bailiff.docket.otlp import span_id_for, trace_id_for

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
PROFILES = ("trace",)

EXPORT_TIMEOUT_SECONDS = 60
CHECKPOINT_SCRIPT = """
import json, os, stat, sys
info = os.lstat("/v/exporter-data/checkpoint.json")
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


def test_every_verified_record_is_a_span_under_its_parent(stack):
    task_id, _ = agent(stack, "run")
    expected = expected_spans(verified_rows(stack, task_id))
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
    assert stack.probe(CHECKPOINT_SCRIPT) == [b.EXPORTER_UID, b.EXPORTER_UID, 0o600]


def test_the_exporter_runs_as_its_own_uid(stack):
    identity = test_quickstart_stack.identity(stack.container("exporter"))
    assert identity == {(b.EXPORTER_UID, b.EXPORTER_UID, frozenset({b.EXPORTER_UID, b.DOCKET_READERS_GID}))}
