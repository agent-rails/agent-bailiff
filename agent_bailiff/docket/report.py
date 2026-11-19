from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.docket.entry import Entry
from agent_bailiff.docket.sink import Verification, VerifiedLine, VerifyReport, build_kid_index
from agent_bailiff.keys import PublicKeyRecord

RELEASED = "released, target outcome unknown"
TABLE_COLUMNS = ("line", "at", "writer", "seq", "decision", "tool", "resource", "reason", "note")


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
) -> VerifyReport:
    index = build_kid_index(writers)
    with open(path, "rb") as docket:
        verification = Verification(docket, index)
        for verified in verification:
            if selected.matches(verified.record.entry):
                emit(verified)
    return verification.report


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
