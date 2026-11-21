from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.docket.entry import Entry
from agent_bailiff.docket.sink import ChainState, Verification, VerifiedLine, VerifyReport, build_kid_index
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


def verify_records(
    path: Path,
    writers: dict[str, dict[str, Ed25519PublicKey]],
    selected: RecordFilter,
    emit: Callable[[VerifiedLine], None],
    observe: Callable[[VerifiedLine], None] | None = None,
) -> VerifyReport:
    index = build_kid_index(writers)
    with open(path, "rb") as docket:
        verification = Verification(docket, index)
        for verified in verification:
            if observe is not None:
                observe(verified)
            if selected.matches(verified.record.entry):
                emit(verified)
    return verification.report


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
        self._seen: Snapshot | None = self._chain.snapshot() if snapshot.offset == 0 else None
        self._passed = snapshot.offset == 0

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
