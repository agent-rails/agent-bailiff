from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import SpanContext, SpanKind, Status, StatusCode, TraceFlags
from opentelemetry.util.types import AttributeValue

from agent_bailiff.docket.private_dir import open_private_dir
from agent_bailiff.docket.report import RELEASED
from agent_bailiff.docket.sink import DocketCorrupt, Head, KidIndex, Verification, VerifiedLine
from agent_bailiff.signing import MAX_TOKEN_CHARS, token_hash

SEMCONV_COMMIT = "622b2b6073b15e5ed886c3c12a65a892b9cd5c70"
SCOPE = InstrumentationScope(
    "agent_bailiff.docket.otlp",
    attributes={"bailiff.semconv": f"open-telemetry/semantic-conventions-genai@{SEMCONV_COMMIT}"},
)
CHECKPOINT_VERSION = 1
CHECKPOINT_MODE = 0o600
MAX_CHECKPOINT_BYTES = 1 << 20
DEFAULT_BATCH_SIZE = 256
DEFAULT_MAX_FAILURES = 5
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_STALL_AFTER = 30.0
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


class CheckpointMismatch(Exception):
    pass


class ExportFailed(Exception):
    pass


@dataclass(frozen=True)
class Checkpoint:
    device: int
    inode: int
    first_hash: str
    offset: int
    entries: int
    last_start: int
    last_hash: str
    heads: Mapping[str, Head] = field(default_factory=dict)

    def to_document(self) -> dict[str, Any]:
        return {
            "version": CHECKPOINT_VERSION,
            "device": self.device,
            "inode": self.inode,
            "first_hash": self.first_hash,
            "offset": self.offset,
            "entries": self.entries,
            "last_start": self.last_start,
            "last_hash": self.last_hash,
            "heads": {writer: {"seq": head.seq, "hash": head.hash} for writer, head in sorted(self.heads.items())},
        }

    @classmethod
    def from_document(cls, document: object) -> Checkpoint:
        if not isinstance(document, dict) or set(document) != set(cls._fields()) | {"version"}:
            raise ValueError("checkpoint fields do not match version 1")
        if document["version"] != CHECKPOINT_VERSION:
            raise ValueError(f"checkpoint version must be {CHECKPOINT_VERSION}")
        for name in ("device", "inode", "offset", "entries", "last_start"):
            if not _is_count(document[name]):
                raise ValueError(f"checkpoint {name} must be a non-negative integer")
        for name in ("first_hash", "last_hash"):
            if not isinstance(document[name], str) or not document[name]:
                raise ValueError(f"checkpoint {name} must be a non-empty str")
        if not document["last_start"] < document["offset"] or document["entries"] < 1:
            raise ValueError("checkpoint must cover at least one record")
        return cls(
            device=document["device"],
            inode=document["inode"],
            first_hash=document["first_hash"],
            offset=document["offset"],
            entries=document["entries"],
            last_start=document["last_start"],
            last_hash=document["last_hash"],
            heads=_heads(document["heads"]),
        )

    @staticmethod
    def _fields() -> tuple[str, ...]:
        return ("device", "inode", "first_hash", "offset", "entries", "last_start", "last_hash", "heads")


def _heads(value: object) -> dict[str, Head]:
    if not isinstance(value, dict) or not value:
        raise ValueError("checkpoint heads must be a non-empty object")
    heads: dict[str, Head] = {}
    for writer, head in value.items():
        if not isinstance(head, dict) or set(head) != {"seq", "hash"}:
            raise ValueError(f"checkpoint head for {writer!r} must hold seq and hash")
        if not _is_count(head["seq"]) or head["seq"] < 1 or not isinstance(head["hash"], str) or not head["hash"]:
            raise ValueError(f"checkpoint head for {writer!r} must have a positive seq and a non-empty hash")
        heads[writer] = Head(seq=head["seq"], hash=head["hash"])
    return heads


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def load_checkpoint(path: Path) -> Checkpoint | None:
    directory_fd = open_private_dir(path.parent)
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as checkpoint:
            info = os.fstat(checkpoint.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != CHECKPOINT_MODE
            ):
                raise PermissionError(f"{path} must be a regular file owned by uid {os.geteuid()} with mode 0600")
            raw = checkpoint.read(MAX_CHECKPOINT_BYTES + 1)
    finally:
        os.close(directory_fd)
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_CHECKPOINT_BYTES} bytes")
    return Checkpoint.from_document(json.loads(raw))


def save_checkpoint(path: Path, checkpoint: Checkpoint) -> None:
    content = json.dumps(checkpoint.to_document(), sort_keys=True).encode("utf-8")
    staged = f".{path.name}.tmp"
    directory_fd = open_private_dir(path.parent)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(staged, flags, CHECKPOINT_MODE, dir_fd=directory_fd)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), CHECKPOINT_MODE)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(staged, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


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


class _Bounded:
    def __init__(self, docket: BinaryIO, end: int) -> None:
        self._docket = docket
        self._end = end

    def readline(self, size: int = -1, /) -> bytes:
        return self._docket.readline(self._remaining(size))

    def read(self, size: int = -1, /) -> bytes:
        return self._docket.read(self._remaining(size))

    def _remaining(self, size: int) -> int:
        left = max(self._end - self._docket.tell(), 0)
        return left if size < 0 else min(size, left)


@dataclass
class _Position:
    first_hash: str | None = None
    offset: int = 0
    entries: int = 0
    last_start: int = 0
    last_hash: str | None = None
    heads: dict[str, Head] = field(default_factory=dict)


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
        if batch_size < 1 or max_failures < 1:
            raise ValueError("batch size and max failures must be at least 1")
        self._docket_path = docket_path
        self._index = index
        self._checkpoint_path = checkpoint_path
        self._exporter = exporter
        self._batch_size = batch_size
        self._max_failures = max_failures
        self._poll_interval = poll_interval
        self._stall_after = stall_after
        self._clock = clock
        self._exported = 0

    def run(self, stop: threading.Event, *, follow: bool) -> int:
        with open(self._docket_path, "rb") as docket:
            info = os.fstat(docket.fileno())
            identity = (info.st_dev, info.st_ino)
            position = _resume(docket, identity, info.st_size, load_checkpoint(self._checkpoint_path))
            torn_since: float | None = None
            while not stop.is_set():
                torn = self._pass(docket, identity, position, stop)
                if stop.is_set():
                    break
                torn_since = self._watch_torn_tail(torn, torn_since, position)
                if not follow:
                    break
                stop.wait(self._poll_interval)
        return self._exported

    def _pass(self, docket: BinaryIO, identity: tuple[int, int], position: _Position, stop: threading.Event) -> bool:
        end = os.fstat(docket.fileno()).st_size
        if end < position.offset:
            raise CheckpointMismatch(f"{self._docket_path} is shorter than the exported offset {position.offset}")
        docket.seek(position.offset)
        verification = Verification(
            _Bounded(docket, end), self._index, heads=position.heads, entries=position.entries, offset=position.offset
        )
        batch: list[VerifiedLine] = []
        for verified in verification:
            batch.append(verified)
            if len(batch) == self._batch_size:
                self._ship(batch, identity, position, stop)
                batch = []
                if stop.is_set():
                    return False
        if batch:
            self._ship(batch, identity, position, stop)
        report = verification.report
        if not report.ok and report.reason != "torn_tail":
            raise DocketCorrupt(report)
        return not report.ok

    def _ship(
        self, batch: Sequence[VerifiedLine], identity: tuple[int, int], position: _Position, stop: threading.Event
    ) -> None:
        spans = [to_span(verified) for verified in batch]
        failures = 0
        while self._exporter.export(spans) is not SpanExportResult.SUCCESS:
            failures += 1
            if failures >= self._max_failures or stop.is_set():
                raise ExportFailed(
                    f"lines {batch[0].line}-{batch[-1].line} were not exported after {failures} attempts; "
                    f"the checkpoint stays at line {position.entries}"
                )
            logger.warning("export of lines %d-%d failed, attempt %d", batch[0].line, batch[-1].line, failures)
        _advance(position, batch)
        save_checkpoint(self._checkpoint_path, _checkpoint(identity, position))
        self._exported += len(batch)
        logger.info("exported lines %d-%d", batch[0].line, batch[-1].line)

    def _watch_torn_tail(self, torn: bool, torn_since: float | None, position: _Position) -> float | None:
        if not torn:
            return None
        now = self._clock()
        if torn_since is None:
            return now
        if now - torn_since >= self._stall_after:
            logger.warning(
                "the line after %d has been incomplete for %.0fs; see Torn tail repair in docs/DOCKET.md",
                position.entries,
                now - torn_since,
            )
            return now
        return torn_since


def _resume(docket: BinaryIO, identity: tuple[int, int], size: int, checkpoint: Checkpoint | None) -> _Position:
    if checkpoint is None:
        return _Position()
    if identity != (checkpoint.device, checkpoint.inode):
        raise CheckpointMismatch("the docket is not the file the checkpoint was written for")
    if size < checkpoint.offset:
        raise CheckpointMismatch(f"the docket is shorter than the exported offset {checkpoint.offset}")
    if _line_hash(docket.readline(MAX_TOKEN_CHARS + 2)) != checkpoint.first_hash:
        raise CheckpointMismatch("the docket's first record differs from the checkpoint")
    docket.seek(checkpoint.last_start)
    if _line_hash(docket.read(checkpoint.offset - checkpoint.last_start)) != checkpoint.last_hash:
        raise CheckpointMismatch("the docket's last exported record differs from the checkpoint")
    return _Position(
        first_hash=checkpoint.first_hash,
        offset=checkpoint.offset,
        entries=checkpoint.entries,
        last_start=checkpoint.last_start,
        last_hash=checkpoint.last_hash,
        heads=dict(checkpoint.heads),
    )


def _line_hash(raw: bytes) -> str | None:
    if not raw.endswith(b"\n"):
        return None
    try:
        return token_hash(raw[:-1].decode("ascii"))
    except UnicodeDecodeError:
        return None


def _advance(position: _Position, batch: Sequence[VerifiedLine]) -> None:
    start = position.offset
    for verified in batch:
        if verified.line == 1:
            position.first_hash = verified.record.hash
        position.heads[verified.record.writer] = Head(seq=verified.record.seq, hash=verified.record.hash)
        position.last_start = start
        position.last_hash = verified.record.hash
        start = verified.end
    position.offset = batch[-1].end
    position.entries = batch[-1].line


def _checkpoint(identity: tuple[int, int], position: _Position) -> Checkpoint:
    if position.first_hash is None or position.last_hash is None:
        raise RuntimeError("a checkpoint needs at least one exported record")
    return Checkpoint(
        device=identity[0],
        inode=identity[1],
        first_hash=position.first_hash,
        offset=position.offset,
        entries=position.entries,
        last_start=position.last_start,
        last_hash=position.last_hash,
        heads=dict(position.heads),
    )
