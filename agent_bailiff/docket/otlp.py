from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import SpanContext, SpanKind, Status, StatusCode, TraceFlags
from opentelemetry.util.types import AttributeValue

from agent_bailiff.docket.follower import DEFAULT_BATCH_SIZE, DEFAULT_POLL_INTERVAL, DEFAULT_STALL_AFTER, DocketFollower
from agent_bailiff.docket.report import RELEASED
from agent_bailiff.docket.sink import KidIndex, VerifiedLine

SEMCONV_COMMIT = "622b2b6073b15e5ed886c3c12a65a892b9cd5c70"
SCOPE = InstrumentationScope(
    "agent_bailiff.docket.otlp",
    attributes={"bailiff.semconv": f"open-telemetry/semantic-conventions-genai@{SEMCONV_COMMIT}"},
)
DEFAULT_MAX_FAILURES = 5
SPAN_ID_TAG = b"agent-bailiff/otlp/span-id/v1\x00"
TRACE_ID_TAG = b"agent-bailiff/otlp/trace-id/v1\x00"
W3C_TRACE_ID = re.compile(r"(?!0{32})[0-9a-f]{32}")
SAMPLED = TraceFlags(TraceFlags.SAMPLED)
OPTIONAL_TEXT = (
    "op_id",
    "parent_entry",
    "principal",
    "tenant",
    "task_root",
    "agent_key",
    "tool",
    "resource",
    "args_digest",
    "policy_id",
    "policy_version",
    "policy_digest",
    "rule",
    "verdict",
    "outcome",
    "receipt_digest",
    "clearance_digest",
    "credential_tier",
    "reason",
)

logger = logging.getLogger(__name__)


def span_id_for(entry_id: str) -> int:
    digest = hashlib.sha256(SPAN_ID_TAG + entry_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") or 1


def trace_id_for(trace_id: str, entry_id: str) -> tuple[int, bool]:
    if W3C_TRACE_ID.fullmatch(trace_id):
        return int(trace_id, 16), False
    digest = hashlib.sha256(TRACE_ID_TAG + entry_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:16], "big") or 1, True


def to_span(verified: VerifiedLine) -> ReadableSpan:
    record = verified.record
    entry = record.entry
    trace_id, mapped = trace_id_for(entry.trace_id, entry.entry_id)
    attributes: dict[str, AttributeValue] = {
        "bailiff.entry_id": entry.entry_id,
        "bailiff.hop": entry.hop,
        "bailiff.component": entry.component,
        "bailiff.decision": entry.decision,
        "bailiff.performed": entry.performed,
        "bailiff.docket.line": verified.line,
        "bailiff.docket.writer": record.writer,
        "bailiff.docket.seq": record.seq,
        "bailiff.docket.kid": record.kid,
        "bailiff.docket.hash": record.hash,
    }
    for name in OPTIONAL_TEXT:
        value = getattr(entry, name)
        if value is not None:
            attributes[f"bailiff.{name}"] = value
    for name in ("cost", "latency_ms"):
        number = getattr(entry, name)
        if number is not None:
            attributes[f"bailiff.{name}"] = number
    if entry.links:
        attributes["bailiff.links"] = list(entry.links)
    for level, handle in sorted(entry.handles.items()):
        attributes[f"bailiff.handle.{level}"] = handle
    if entry.performed:
        attributes["bailiff.note"] = RELEASED
    if mapped:
        attributes["bailiff.trace_id_mapped"] = True
    if entry.tool is not None:
        attributes["gen_ai.operation.name"] = "execute_tool"
        attributes["gen_ai.tool.name"] = entry.tool
    status = Status(StatusCode.UNSET)
    if entry.decision == "refuse":
        attributes["error.type"] = entry.reason or "refused"
        status = Status(StatusCode.ERROR, entry.reason)
    end = entry.at * 1_000_000_000
    start = max(end - (entry.latency_ms or 0) * 1_000_000, 0)
    parent = None
    if entry.parent_entry is not None:
        parent = SpanContext(trace_id, span_id_for(entry.parent_entry), is_remote=False, trace_flags=SAMPLED)
    return ReadableSpan(
        name=f"{entry.hop} {entry.decision}",
        context=SpanContext(trace_id, span_id_for(entry.entry_id), is_remote=False, trace_flags=SAMPLED),
        parent=parent,
        resource=Resource({"service.name": f"agent-bailiff-{record.writer}"}),
        attributes=attributes,
        kind=SpanKind.INTERNAL,
        status=status,
        start_time=start,
        end_time=end,
        instrumentation_scope=SCOPE,
    )


class ExportFailed(Exception):
    pass


class DocketExporter:
    def __init__(
        self,
        docket_path: Path,
        index: KidIndex,
        checkpoint_path: Path,
        exporter: SpanExporter,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_failures: int = DEFAULT_MAX_FAILURES,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        stall_after: float = DEFAULT_STALL_AFTER,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_failures < 1:
            raise ValueError("max failures must be at least 1")
        self._exporter = exporter
        self._max_failures = max_failures
        self._follower = DocketFollower(
            docket_path,
            index,
            checkpoint_path,
            self._ship,
            batch_size=batch_size,
            poll_interval=poll_interval,
            stall_after=stall_after,
            clock=clock,
        )

    def run(self, stop: threading.Event, *, follow: bool) -> int:
        return self._follower.run(stop, follow=follow)

    def _ship(self, batch: Sequence[VerifiedLine], stop: threading.Event) -> None:
        spans = [to_span(verified) for verified in batch]
        failures = 0
        while self._exporter.export(spans) is not SpanExportResult.SUCCESS:
            failures += 1
            if failures >= self._max_failures or stop.is_set():
                raise ExportFailed(
                    f"lines {batch[0].line}-{batch[-1].line} were not exported after {failures} attempts; "
                    f"the checkpoint stays at line {batch[0].line - 1}"
                )
            logger.warning("export of lines %d-%d failed, attempt %d", batch[0].line, batch[-1].line, failures)
        logger.info("exported lines %d-%d", batch[0].line, batch[-1].line)
