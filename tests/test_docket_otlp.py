import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExportResult
from opentelemetry.trace import SpanContext, SpanKind, TraceFlags


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


@pytest.fixture
def collector() -> Iterator[Collector]:
    stub = Collector()
    thread = threading.Thread(target=stub.server.serve_forever, daemon=True)
    thread.start()
    yield stub
    stub.server.shutdown()
    stub.server.server_close()


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
