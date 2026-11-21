from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.docket.entry import Entry, Head
from agent_bailiff.docket.manifest import read_docket_manifest
from agent_bailiff.docket.segments import BoundedReader, OpenedSegment, SegmentMismatch, open_segment
from agent_bailiff.docket.sink import (
    SEGMENT_MISMATCH,
    ChainState,
    KidIndex,
    Verification,
    VerifiedLine,
    VerifyReport,
    Writers,
    build_kid_index,
)
from agent_bailiff.docket.snapshot import Snapshot, SnapshotInvalid, read_snapshot
from agent_bailiff.keys import PublicKeyRecord

RELEASED = "released, target outcome unknown"
TABLE_COLUMNS = ("line", "at", "writer", "seq", "decision", "tool", "resource", "reason", "note")
SNAPSHOT_FIELDS = ("segment", "entries", "prefix_sha256", "anchors", "kids")
READER_MODE = 0o640


@dataclass(frozen=True)
class RecordFilter:
    trace: str | None = None
    task: str | None = None
    since: int | None = None

    def matches(self, entry: Entry) -> bool:
        if self.trace is not None and entry.trace_id != self.trace:
            return False
        if self.task is not None and self.task not in (entry.task_root, entry.handles.get("task")):
            return False
        return self.since is None or entry.at >= self.since


def pinned_writers(pins: Iterable[PublicKeyRecord]) -> dict[str, dict[str, Ed25519PublicKey]]:
    writers: dict[str, dict[str, Ed25519PublicKey]] = {}
    for pin in pins:
        writers.setdefault(pin.component, {})[pin.kid] = pin.public_key
    if not writers:
        raise ValueError("at least one writer pin is required")
    return writers


def verify_docket(path: Path, writers: Writers) -> VerifyReport:
    return verify_records(path, writers, RecordFilter(), lambda _line: None)


def verify_records(
    path: Path,
    writers: Writers,
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
    check: SnapshotCheck | None = None,
) -> VerifyReport:
    index = build_kid_index(writers)
    manifest = read_docket_manifest(path)
    segment = manifest.first_segment
    heads = {} if manifest.base is None else dict(manifest.base.end_heads)
    entries = 0 if manifest.base is None else manifest.base.entries
    while True:
        opened = open_segment(path, segment)
        if opened is None:
            raise SegmentMismatch(f"segment {segment} of {path} cannot be opened; start the sink to finish a cut")
        with opened.stream:
            active_check = check if opened.sealed is None else None
            if active_check is not None:
                active_check.begin(segment, entries)
            report = _verify_segment(opened, index, heads, entries, selected, emit, active_check)
        if not report.ok or opened.sealed is None:
            return report
        heads, entries = dict(report.heads), report.entries
        segment += 1


class _Digesting:
    def __init__(self, source: BoundedReader) -> None:
        self._source = source
        self.digest = hashlib.sha256()

    def readline(self, size: int = -1, /) -> bytes:
        raw = self._source.readline(size)
        self.digest.update(raw)
        return raw

    def read(self, size: int = -1, /) -> bytes:
        raw = self._source.read(size)
        self.digest.update(raw)
        return raw


def _verify_segment(
    opened: OpenedSegment,
    index: KidIndex,
    heads: dict[str, Head],
    entries: int,
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
    check: SnapshotCheck | None,
) -> VerifyReport:
    source = _Digesting(BoundedReader(opened.stream, opened.end))
    verification = Verification(source, index, heads=heads, entries=entries)
    kids: set[str] = set()
    for verified in verification:
        kids.add(verified.record.kid)
        if check is not None:
            check.observe(verified)
        if selected.matches(verified.record.entry):
            emit(verified)
    report = verification.report
    sealed = opened.sealed
    if sealed is None:
        return report
    if not report.ok and report.reason != "torn_tail":
        return report
    differences = [] if report.ok else ["ends with an incomplete line"]
    if source.digest.hexdigest() != sealed.sha256:
        differences.append("sha256")
    if report.entries != sealed.first_entry + sealed.entries - 1:
        differences.append("entries")
    if report.heads != dict(sealed.end_heads):
        differences.append("end_heads")
    if kids != sealed.kids:
        differences.append("kids")
    if not differences:
        return report
    detail = f"segment {sealed.segment} does not match its manifest entry: {', '.join(differences)}"
    return VerifyReport(False, report.entries, report.heads, None, SEGMENT_MISMATCH, detail, report.valid_bytes)


def read_docket_snapshot(path: Path, docket_path: Path) -> Snapshot:
    info = os.stat(docket_path)
    reader_gid = info.st_gid if stat.S_IMODE(info.st_mode) == READER_MODE else None
    snapshot = read_snapshot(path, uid=info.st_uid, reader_gid=reader_gid)
    if snapshot is None:
        raise SnapshotInvalid(f"{path} does not exist")
    return snapshot


class SnapshotCheck:
    def __init__(self, snapshot: Snapshot) -> None:
        self.snapshot = snapshot
        self._chain = ChainState()
        self._seen: Snapshot | None = None
        self._passed = False

    def begin(self, segment: int, entries: int) -> None:
        self._chain = ChainState(segment=segment, entries=entries)
        self._seen = self._chain.snapshot() if self.snapshot.offset == 0 else None
        self._passed = self.snapshot.offset == 0

    def observe(self, verified: VerifiedLine) -> None:
        if self._passed:
            return
        self._chain.add(verified.start, verified.record)
        if self._chain.offset >= self.snapshot.offset:
            self._passed = True
            if self._chain.offset == self.snapshot.offset:
                self._seen = self._chain.snapshot()

    def records_after(self, entries: int) -> int:
        return entries - self.snapshot.entries

    def differences(self) -> list[str]:
        if self.snapshot.segment != self._chain.segment:
            return ["segment"]
        if self._seen is None:
            return [f"offset {self.snapshot.offset} is not the end of a verified line"]
        return [name for name in SNAPSHOT_FIELDS if getattr(self._seen, name) != getattr(self.snapshot, name)]


def note(entry: Entry) -> str | None:
    return RELEASED if entry.performed else None


def json_row(verified: VerifiedLine) -> str:
    record = verified.record
    entry = asdict(record.entry)
    entry["links"] = list(record.entry.links)
    entry["handles"] = dict(record.entry.handles)
    document = {
        "line": verified.line,
        "writer": record.writer,
        "seq": record.seq,
        "kid": record.kid,
        "hash": record.hash,
        "note": note(record.entry),
        "entry": entry,
        "token": record.token,
    }
    return json.dumps(document, sort_keys=True)


def table_header() -> str:
    return "\t".join(column.upper() for column in TABLE_COLUMNS)


def table_row(verified: VerifiedLine) -> str:
    record = verified.record
    entry = record.entry
    values = (
        str(verified.line),
        _utc(entry.at),
        record.writer,
        str(record.seq),
        entry.decision,
        entry.tool,
        entry.resource,
        entry.reason,
        note(entry),
    )
    return "\t".join(printable(value) for value in values)


def _utc(at: int) -> str:
    try:
        return datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return str(at)


def printable(value: str | None) -> str:
    if value is None:
        return "-"
    if value.isascii() and value.isprintable() and "\\" not in value:
        return value
    return value.encode("unicode_escape").decode("ascii")
