from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.docket.archiver import ArchiveCopies, ArchivedCopy, encode_sidecar
from agent_bailiff.docket.entry import ENTRY_TYP, Entry, Head
from agent_bailiff.docket.grant import GRANT_TYP, Grant
from agent_bailiff.docket.manifest import Base, Manifest, SegmentEntry, read_docket_manifest
from agent_bailiff.docket.receipt import Receipt, ReceiptDir
from agent_bailiff.docket.segments import (
    BoundedReader,
    OpenedSegment,
    SegmentMismatch,
    open_segment,
    read_listed_manifest,
)
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
GRANTED = "task grant"
GRANT_DECISION = "grant"
TABLE_COLUMNS = ("line", "at", "writer", "seq", "decision", "tool", "resource", "reason", "note")
SNAPSHOT_FIELDS = ("segment", "entries", "prefix_sha256", "anchors", "kids")
READER_MODE = 0o640


@dataclass(frozen=True)
class RecordFilter:
    trace: str | None = None
    task: str | None = None
    since: int | None = None

    def matches(self, entry: Entry | Grant) -> bool:
        if isinstance(entry, Grant):
            return self.trace is None and self.task is None and (self.since is None or entry.at >= self.since)
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


def verify_docket(path: Path, writers: Writers, grant_writers: Iterable[str] = ()) -> VerifyReport:
    return verify_records(path, writers, RecordFilter(), lambda _line: None, grant_writers=grant_writers)


def verify_records(
    path: Path,
    writers: Writers,
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
    check: SnapshotCheck | None = None,
    archive: Path | None = None,
    seeds: SeedCheck | None = None,
    grant_writers: Iterable[str] = (),
) -> VerifyReport:
    index = build_kid_index(writers, grant_writers)
    manifest = read_listed_manifest(path)
    if seeds is not None:
        seeds.compare(path, manifest)
    segment = manifest.first_segment
    heads: dict[str, Head] = {}
    entries = 0
    if manifest.base is not None and archive is None:
        heads, entries = dict(manifest.base.end_heads), manifest.base.entries
    if manifest.base is not None and archive is not None:
        report = _verify_archive(archive, manifest, manifest.base, index, selected, emit)
        if not report.ok:
            return report
        heads, entries = dict(report.heads), report.entries
    while True:
        opened = open_segment(path, segment)
        if opened is None and not path.exists() and read_docket_manifest(path).generation == 0:
            raise FileNotFoundError(f"{path} does not exist")
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


def _verify_archive(
    archive: Path,
    manifest: Manifest,
    base: Base,
    index: KidIndex,
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
) -> VerifyReport:
    heads: dict[str, Head] = {}
    entries = 0
    with ArchiveCopies.open(archive, manifest.docket_id) as copies:
        for segment in range(1, base.segment + 1):
            copy = copies.open_copy(segment)
            with copy.stream:
                report = _verify_archived(copy, manifest.docket_id, index, heads, entries, selected, emit)
            if not report.ok:
                return report
            heads, entries = dict(report.heads), report.entries
    if entries != base.entries or heads != dict(base.end_heads):
        detail = f"the archive ends at {entries} records with other heads than the manifest base"
        return VerifyReport(False, entries, heads, None, SEGMENT_MISMATCH, detail)
    return VerifyReport(True, entries, heads)


def _verify_archived(
    copy: ArchivedCopy,
    docket_id: str,
    index: KidIndex,
    heads: dict[str, Head],
    entries: int,
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
) -> VerifyReport:
    report, digest, kids = _read_records(copy.stream, copy.size, index, heads, entries, selected, emit, None)
    if not report.ok and report.reason != "torn_tail":
        return report
    derived = SegmentEntry(
        copy.segment, digest, copy.size, entries + 1, report.entries - entries, dict(report.heads), kids
    )
    if report.ok and encode_sidecar(docket_id, derived) == copy.sidecar:
        return report
    detail = f"archived segment {copy.segment} does not match its sidecar"
    return VerifyReport(False, report.entries, report.heads, None, SEGMENT_MISMATCH, detail, report.valid_bytes)


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
    report, digest, kids = _read_records(opened.stream, opened.end, index, heads, entries, selected, emit, check)
    sealed = opened.sealed
    if sealed is None:
        return report
    if not report.ok and report.reason != "torn_tail":
        return report
    differences = [] if report.ok else ["ends with an incomplete line"]
    if digest != sealed.sha256:
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


def _read_records(
    stream: BinaryIO,
    end: int,
    index: KidIndex,
    heads: dict[str, Head],
    entries: int,
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
    check: SnapshotCheck | None,
) -> tuple[VerifyReport, str, frozenset[str]]:
    source = _Digesting(BoundedReader(stream, end))
    verification = Verification(source, index, heads=heads, entries=entries)
    kids: set[str] = set()
    for verified in verification:
        kids.add(verified.record.kid)
        if check is not None:
            check.observe(verified)
        if selected.matches(verified.record.entry):
            emit(verified)
    return verification.report, source.digest.hexdigest(), frozenset(kids)


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


class SeedCheck:
    def __init__(self, receipt_dir: Path) -> None:
        self.receipt_dir = receipt_dir
        self.checked = 0
        self.base: int | None = None
        self.differences: list[str] = []

    def compare(self, docket_path: Path, manifest: Manifest) -> None:
        owner = os.lstat(self.receipt_dir).st_uid
        reader_gid = os.stat(docket_path).st_gid
        with ReceiptDir.open(self.receipt_dir, archiver_uid=owner, reader_gid=reader_gid) as receipts:
            for entry in manifest.segments:
                receipt = receipts.read(entry.segment)
                if receipt is None:
                    continue
                self.checked += 1
                if _receipt_fields(receipt) != (manifest.docket_id, entry.sha256, entry.size, dict(entry.end_heads)):
                    self.differences.append(f"segment {entry.segment} differs from its receipt")
            if manifest.base is not None:
                self._compare_base(receipts, manifest.docket_id, manifest.base)

    def _compare_base(self, receipts: ReceiptDir, docket_id: str, base: Base) -> None:
        self.base = base.segment
        tombstone = receipts.read(base.segment)
        if tombstone is None:
            self.differences.append(f"removed segment {base.segment} has no receipt")
        elif (tombstone.docket_id, dict(tombstone.end_heads)) != (docket_id, dict(base.end_heads)):
            self.differences.append(f"the base differs from the receipt of removed segment {base.segment}")


def _receipt_fields(receipt: Receipt) -> tuple[str, str, int, dict[str, Head]]:
    return receipt.docket_id, receipt.sha256, receipt.size, dict(receipt.end_heads)


def note(entry: Entry | Grant) -> str | None:
    if isinstance(entry, Grant):
        return GRANTED
    return RELEASED if entry.performed else None


def json_row(verified: VerifiedLine) -> str:
    record = verified.record
    document = {
        "line": verified.line,
        "writer": record.writer,
        "seq": record.seq,
        "kid": record.kid,
        "hash": record.hash,
        "note": note(record.entry),
        "token": record.token,
    }
    if isinstance(record.entry, Grant):
        document |= {"typ": GRANT_TYP, "grant": asdict(record.entry)}
    else:
        entry = asdict(record.entry)
        entry["links"] = list(record.entry.links)
        entry["handles"] = dict(record.entry.handles)
        document |= {"typ": ENTRY_TYP, "entry": entry}
    return json.dumps(document, sort_keys=True)


def table_header() -> str:
    return "\t".join(column.upper() for column in TABLE_COLUMNS)


def table_row(verified: VerifiedLine) -> str:
    record = verified.record
    entry = record.entry
    values = (str(verified.line), utc(entry.at), record.writer, str(record.seq), *_columns(entry), note(entry))
    return "\t".join(printable(value) for value in values)


def _columns(entry: Entry | Grant) -> tuple[str | None, ...]:
    if isinstance(entry, Grant):
        return GRANT_DECISION, None, None, None
    return entry.decision, entry.tool, entry.resource, entry.reason


def utc(at: int) -> str:
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
