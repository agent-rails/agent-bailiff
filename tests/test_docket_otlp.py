import json
import os
import shutil
import sys
import tempfile
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import SpanContext, SpanKind, StatusCode, TraceFlags
from test_docket import make_entry
from test_docket_report import PINS, WRITERS, Docket

from agent_bailiff import cli
from agent_bailiff.docket import DocketCorrupt
from agent_bailiff.docket.otlp import (
    CheckpointMismatch,
    DocketExporter,
    ExportFailed,
    load_checkpoint,
    span_id_for,
    to_span,
)
from agent_bailiff.docket.report import RELEASED
from agent_bailiff.docket.sink import VerifiedLine, build_kid_index

INDEX = build_kid_index(WRITERS)
TRACE = "0af7651916cd43dd8448eb211c80319c"


class Collector:
    def __init__(self) -> None:
        self.requests: list[ExportTraceServiceRequest] = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = ExportTraceServiceRequest()
                request.ParseFromString(body)
                collector.requests.append(request)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}/v1/traces"

    def spans(self):
        return [
            span
            for request in self.requests
            for resource in request.resource_spans
            for scope in resource.scope_spans
            for span in scope.spans
        ]


class FakeExporter(SpanExporter):
    def __init__(self, failures=0, during=None):
        self.batches: list[list[ReadableSpan]] = []
        self.failures = failures
        self.attempts = 0
        self.during = during

    def export(self, spans):
        self.attempts += 1
        if self.during is not None:
            self.during(self)
        if self.failures:
            self.failures -= 1
            return SpanExportResult.FAILURE
        self.batches.append(list(spans))
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

    def entry_ids(self):
        return [span.attributes["bailiff.entry_id"] for batch in self.batches for span in batch]


@pytest.fixture
def collector() -> Iterator[Collector]:
    stub = Collector()
    thread = threading.Thread(target=stub.server.serve_forever, daemon=True)
    thread.start()
    yield stub
    stub.server.shutdown()
    stub.server.server_close()


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bo-", dir="/tmp"))
    yield path
    shutil.rmtree(path)


@pytest.fixture
def docket(workdir):
    path = workdir / "docket.log"
    path.touch(mode=0o600)
    return Docket(path)


@pytest.fixture
def checkpoint(workdir):
    directory = workdir / "exporter"
    directory.mkdir(mode=0o700)
    return directory / "checkpoint.json"


def fill(docket, count, start=1):
    for number in range(start, start + count):
        docket.append("decide", make_entry(number, trace_id=TRACE))


def export(docket, checkpoint, exporter, **options):
    stop = threading.Event()
    return DocketExporter(docket.path, INDEX, checkpoint, exporter, **options).run(stop, follow=False)


def verified(record, line=1):
    return VerifiedLine(line=line, record=record, end=len(record.token) + 1)


def test_sdk_exports_a_span_with_the_given_ids(collector):
    trace_id = 0x0AF7651916CD43DD8448EB211C80319C
    span_id = 0x00F067AA0BA902B7
    parent_id = 0x1111111111111111
    span = ReadableSpan(
        name="decide",
        context=SpanContext(trace_id, span_id, is_remote=False, trace_flags=TraceFlags(TraceFlags.SAMPLED)),
        parent=SpanContext(trace_id, parent_id, is_remote=False, trace_flags=TraceFlags(TraceFlags.SAMPLED)),
        start_time=1_700_000_000_000_000_000,
        end_time=1_700_000_000_000_000_000,
        attributes={"bailiff.decision": "allow"},
        kind=SpanKind.INTERNAL,
        resource=Resource.create({"service.name": "agent-bailiff-docket"}),
    )
    exporter = OTLPSpanExporter(endpoint=collector.endpoint, timeout=5)

    assert exporter.export([span]) is SpanExportResult.SUCCESS

    exported = collector.requests[0].resource_spans[0].scope_spans[0].spans[0]
    assert exported.trace_id == trace_id.to_bytes(16, "big")
    assert exported.span_id == span_id.to_bytes(8, "big")
    assert exported.parent_span_id == parent_id.to_bytes(8, "big")
    assert exported.start_time_unix_nano == 1_700_000_000_000_000_000
    assert exported.end_time_unix_nano == 1_700_000_000_000_000_000


def test_span_ids_derive_from_the_docket_ids(docket):
    record = docket.append("decide", make_entry(1, trace_id=TRACE, parent_entry="e-0"))
    span = to_span(verified(record))
    assert span.context.trace_id == int(TRACE, 16)
    assert span.context.span_id == span_id_for("e-1") == to_span(verified(record)).context.span_id
    assert span.parent.span_id == span_id_for("e-0")
    assert span.parent.trace_id == int(TRACE, 16)
    assert span.end_time == (make_entry(1).at) * 1_000_000_000
    assert span.start_time == span.end_time - 4_000_000
    assert span.resource.attributes["service.name"] == "agent-bailiff-decide"


def test_a_root_entry_has_no_parent(docket):
    record = docket.append("decide", make_entry(1, trace_id=TRACE))
    assert to_span(verified(record)).parent is None


@pytest.mark.parametrize("trace_id", ["trace-1", "0" * 32, TRACE.upper(), TRACE + "0"])
def test_a_trace_id_that_is_not_w3c_is_mapped_and_not_exported(docket, trace_id):
    record = docket.append("decide", make_entry(1, trace_id=trace_id))
    span = to_span(verified(record))
    assert span.context.trace_id != 0
    assert span.context.trace_id != int(TRACE, 16)
    assert span.attributes["bailiff.trace_id_mapped"] is True
    assert trace_id not in [value for value in span.attributes.values() if isinstance(value, str)]


def test_a_mapped_trace_id_is_stable_per_entry(docket):
    first = to_span(verified(docket.append("decide", make_entry(1, trace_id="x"))))
    second = to_span(verified(docket.append("decide", make_entry(1, trace_id="y"))))
    assert first.context.trace_id == second.context.trace_id


def test_span_attributes_carry_the_record_but_never_arguments(docket):
    record = docket.append("decide", make_entry(1, trace_id=TRACE))
    attributes = to_span(verified(record)).attributes
    assert attributes["bailiff.args_digest"] == "digest-1"
    assert attributes["bailiff.docket.hash"] == record.hash
    assert attributes["bailiff.docket.writer"] == "decide"
    assert attributes["bailiff.handle.task"] == "root-1"
    assert attributes["gen_ai.operation.name"] == "execute_tool"
    assert attributes["gen_ai.tool.name"] == "github.create_issue"
    assert not [name for name in attributes if "argument" in name]
    assert "bailiff.note" not in attributes


def test_a_release_is_labelled_outcome_unknown(docket):
    record = docket.append("custodian", make_entry(1, trace_id=TRACE, decision="release", performed=True))
    assert to_span(verified(record)).attributes["bailiff.note"] == RELEASED


def test_a_refusal_is_an_error_span_with_its_reason(docket):
    record = docket.append("decide", make_entry(1, trace_id=TRACE, decision="refuse", reason="out_of_scope"))
    span = to_span(verified(record))
    assert span.status.status_code is StatusCode.ERROR
    assert span.attributes["error.type"] == "out_of_scope"


def test_export_ships_every_record_in_batches_and_checkpoints(docket, checkpoint):
    fill(docket, 5)
    exporter = FakeExporter()
    assert export(docket, checkpoint, exporter, batch_size=2) == 5
    assert [len(batch) for batch in exporter.batches] == [2, 2, 1]
    assert exporter.entry_ids() == [f"e-{n}" for n in range(1, 6)]
    saved = load_checkpoint(checkpoint)
    assert saved.entries == 5 and saved.offset == docket.path.stat().st_size
    assert saved.heads["decide"].hash == docket.records[-1].hash
    assert saved.last_hash == docket.records[-1].hash and saved.first_hash == docket.records[0].hash
    assert checkpoint.stat().st_mode & 0o777 == 0o600


def test_resume_exports_only_new_records(docket, checkpoint):
    fill(docket, 3)
    export(docket, checkpoint, FakeExporter())
    fill(docket, 2, start=4)
    docket.append("custodian", make_entry(6, trace_id=TRACE, hop="custodian", component="custodian"))
    exporter = FakeExporter()
    assert export(docket, checkpoint, exporter) == 3
    assert exporter.entry_ids() == ["e-4", "e-5", "e-6"]
    assert export(docket, checkpoint, FakeExporter()) == 0


def test_an_empty_docket_exports_nothing_and_writes_no_checkpoint(docket, checkpoint):
    assert export(docket, checkpoint, FakeExporter()) == 0
    assert not checkpoint.exists()


def test_a_failed_batch_is_retried_and_the_checkpoint_waits(docket, checkpoint):
    fill(docket, 2)
    seen = []
    exporter = FakeExporter(failures=2, during=lambda _: seen.append(checkpoint.exists()))
    assert export(docket, checkpoint, exporter, max_failures=3) == 2
    assert exporter.attempts == 3 and seen == [False, False, False]
    assert load_checkpoint(checkpoint).entries == 2


def test_export_exits_after_max_failures_with_the_checkpoint_unchanged(docket, checkpoint):
    fill(docket, 2)
    export(docket, checkpoint, FakeExporter(), batch_size=1)
    before = checkpoint.read_bytes()
    fill(docket, 1, start=3)
    exporter = FakeExporter(failures=10)
    with pytest.raises(ExportFailed, match="lines 3-3 were not exported after 3 attempts"):
        export(docket, checkpoint, exporter, max_failures=3)
    assert exporter.attempts == 3
    assert checkpoint.read_bytes() == before


def test_a_torn_tail_is_left_for_the_next_pass(docket, checkpoint):
    fill(docket, 2)
    whole = docket.path.read_bytes()
    first_line = whole.split(b"\n")[0]
    with open(docket.path, "ab") as stream:
        stream.write(first_line[:40])
    exporter = FakeExporter()
    assert export(docket, checkpoint, exporter) == 2
    assert load_checkpoint(checkpoint).offset == len(whole)


def test_a_corrupt_record_stops_the_export_after_the_verified_prefix(docket, checkpoint):
    fill(docket, 2)
    with open(docket.path, "ab") as stream:
        stream.write(b"not-a-token\n")
    exporter = FakeExporter()
    with pytest.raises(DocketCorrupt):
        export(docket, checkpoint, exporter)
    assert exporter.entry_ids() == ["e-1", "e-2"]
    assert load_checkpoint(checkpoint).entries == 2


def test_a_pass_reads_only_up_to_the_size_at_its_start(docket, checkpoint):
    fill(docket, 2)
    added = []

    def grow(_):
        if not added:
            added.append(docket.append("decide", make_entry(3, trace_id=TRACE)))

    exporter = FakeExporter(during=grow)
    assert export(docket, checkpoint, exporter, batch_size=1) == 2
    assert exporter.entry_ids() == ["e-1", "e-2"]
    assert export(docket, checkpoint, FakeExporter()) == 1


def test_stop_drains_the_batch_in_flight_then_exits(docket, checkpoint):
    fill(docket, 4)
    stop = threading.Event()
    exporter = FakeExporter(during=lambda _: stop.set())
    runner = DocketExporter(docket.path, INDEX, checkpoint, exporter, batch_size=2)
    assert runner.run(stop, follow=True) == 2
    assert exporter.entry_ids() == ["e-1", "e-2"]
    assert load_checkpoint(checkpoint).entries == 2


def test_follow_waits_for_new_records(docket, checkpoint):
    fill(docket, 1)
    stop = threading.Event()
    exporter = FakeExporter()
    runner = DocketExporter(docket.path, INDEX, checkpoint, exporter, poll_interval=0.01)
    thread = threading.Thread(target=runner.run, args=(stop,), kwargs={"follow": True})
    thread.start()
    try:
        fill(docket, 1, start=2)
        for _ in range(500):
            if len(exporter.entry_ids()) == 2:
                break
            threading.Event().wait(0.01)
    finally:
        stop.set()
        thread.join(5)
    assert exporter.entry_ids() == ["e-1", "e-2"]


def test_a_replaced_docket_is_refused(docket, checkpoint):
    fill(docket, 2)
    export(docket, checkpoint, FakeExporter())
    content = docket.path.read_bytes()
    docket.path.unlink()
    docket.path.write_bytes(content)
    with pytest.raises(CheckpointMismatch, match="not the file"):
        export(docket, checkpoint, FakeExporter())


def test_a_truncated_docket_is_refused(docket, checkpoint):
    fill(docket, 2)
    export(docket, checkpoint, FakeExporter())
    os.truncate(docket.path, 10)
    with pytest.raises(CheckpointMismatch, match="shorter"):
        export(docket, checkpoint, FakeExporter())


def test_a_rewritten_docket_of_the_same_length_is_refused(docket, checkpoint):
    fill(docket, 2)
    export(docket, checkpoint, FakeExporter())
    with open(docket.path, "r+b") as stream:
        stream.seek(5)
        stream.write(b"X")
    with pytest.raises(CheckpointMismatch, match="first record"):
        export(docket, checkpoint, FakeExporter())


def test_a_checkpoint_with_a_loose_mode_is_refused(docket, checkpoint):
    fill(docket, 1)
    export(docket, checkpoint, FakeExporter())
    os.chmod(checkpoint, 0o644)
    with pytest.raises(PermissionError, match="mode 0600"):
        export(docket, checkpoint, FakeExporter())


@pytest.mark.parametrize(
    "change",
    [
        {"version": 2},
        {"extra": 1},
        {"offset": -1},
        {"entries": 0},
        {"heads": {}},
        {"heads": {"decide": {"seq": 0, "hash": "h"}}},
        {"first_hash": ""},
    ],
)
def test_a_malformed_checkpoint_is_refused(docket, checkpoint, change):
    fill(docket, 1)
    export(docket, checkpoint, FakeExporter())
    document = {**json.loads(checkpoint.read_text()), **change}
    checkpoint.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        export(docket, checkpoint, FakeExporter())


def test_cli_exports_once_to_an_otlp_endpoint(docket, checkpoint, workdir, collector, capsys):
    fill(docket, 3)
    pin = workdir / "decide.pub.json"
    pin.write_text(json.dumps(PINS["decide"].to_document()))
    arguments = [
        "docket",
        "export",
        "--docket",
        str(docket.path),
        "--pin",
        str(pin),
        "--checkpoint",
        str(checkpoint),
        "--otlp",
        collector.endpoint,
        "--once",
    ]
    assert cli.main(arguments) == 0
    assert "3 records exported" in capsys.readouterr().err
    assert [span.span_id for span in collector.spans()] == [
        span_id_for(f"e-{n}").to_bytes(8, "big") for n in range(1, 4)
    ]
    assert cli.main(arguments) == 0
    assert "0 records exported" in capsys.readouterr().err
    assert len(collector.spans()) == 3


@pytest.mark.parametrize("endpoint", ["ftp://host/v1/traces", "http:///v1/traces", "http://user:pw@host/v1/traces"])
def test_cli_refuses_a_bad_endpoint(docket, checkpoint, workdir, capsys, endpoint):
    pin = workdir / "decide.pub.json"
    pin.write_text(json.dumps(PINS["decide"].to_document()))
    arguments = ["docket", "export", "--docket", str(docket.path), "--pin", str(pin)]
    arguments += ["--checkpoint", str(checkpoint), "--otlp", endpoint, "--once"]
    assert cli.main(arguments) == 1
    assert "--otlp must be an http or https URL" in capsys.readouterr().err


def test_a_lasting_torn_tail_is_logged(docket, checkpoint, caplog):
    fill(docket, 1)
    with open(docket.path, "ab") as stream:
        stream.write(b"partial")
    stop = threading.Event()
    ticks = iter([0.0, 10.0, 31.0])

    def clock():
        moment = next(ticks, None)
        if moment is None:
            stop.set()
            return 31.0
        return moment

    runner = DocketExporter(docket.path, INDEX, checkpoint, FakeExporter(), poll_interval=0, clock=clock)
    with caplog.at_level("WARNING", logger="agent_bailiff.docket.otlp"):
        runner.run(stop, follow=True)
    warnings = [record.getMessage() for record in caplog.records]
    assert warnings == ["the line after 1 has been incomplete for 31s; see Torn tail repair in docs/DOCKET.md"]


def test_cli_without_the_otel_extra_says_what_to_install(docket, checkpoint, workdir, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "opentelemetry.exporter.otlp.proto.http.trace_exporter", None)
    pin = workdir / "decide.pub.json"
    pin.write_text(json.dumps(PINS["decide"].to_document()))
    arguments = ["docket", "export", "--docket", str(docket.path), "--pin", str(pin)]
    arguments += ["--checkpoint", str(checkpoint), "--otlp", "http://127.0.0.1:1/v1/traces", "--once"]
    assert cli.main(arguments) == 1
    assert "needs the otel extra" in capsys.readouterr().err
