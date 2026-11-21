from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize

from agent_bailiff.docket.manifest import MAX_SEGMENT
from agent_bailiff.docket.state_file import StateFileInvalid, read_state_file, replace_state_file
from agent_bailiff.strict_json import parse_strict_json

SNAPSHOT_VERSION = 2
LEGACY_SNAPSHOT_VERSION = 1
MAX_SNAPSHOT_BYTES = 1 << 22
MAX_INTEGER = 2**53 - 1
SNAPSHOT_KEYS = frozenset({"version", "segment", "offset", "entries", "prefix_sha256", "anchors", "kids"})
ANCHOR_KEYS = frozenset({"offset", "seq", "hash"})
PREFIX_SHA256 = re.compile(r"[0-9a-f]{64}")
RECORD_HASH = re.compile(r"[A-Za-z0-9_-]{43}")


class SnapshotInvalid(ValueError):
    pass


class SnapshotLegacy(SnapshotInvalid):
    pass


@dataclass(frozen=True)
class Anchor:
    offset: int
    seq: int
    hash: str


@dataclass(frozen=True)
class Snapshot:
    segment: int
    offset: int
    entries: int
    prefix_sha256: str
    anchors: Mapping[str, Anchor] = field(default_factory=dict)
    kids: frozenset[str] = frozenset()

    def to_document(self) -> dict[str, Any]:
        return {
            "version": SNAPSHOT_VERSION,
            "segment": self.segment,
            "offset": self.offset,
            "entries": self.entries,
            "prefix_sha256": self.prefix_sha256,
            "anchors": {
                writer: {"offset": anchor.offset, "seq": anchor.seq, "hash": anchor.hash}
                for writer, anchor in self.anchors.items()
            },
            "kids": sorted(self.kids),
        }

    def encode(self) -> bytes:
        return canonicalize(self.to_document())

    @classmethod
    def from_document(cls, document: object) -> Snapshot:
        if isinstance(document, dict) and type(document.get("version")) is int:
            if document["version"] == LEGACY_SNAPSHOT_VERSION:
                raise SnapshotLegacy(f"snapshot version {LEGACY_SNAPSHOT_VERSION} predates segments")
        if not isinstance(document, dict) or set(document) != SNAPSHOT_KEYS:
            raise SnapshotInvalid(f"snapshot must be an object with exactly {', '.join(sorted(SNAPSHOT_KEYS))}")
        if type(document["version"]) is not int or document["version"] != SNAPSHOT_VERSION:
            raise SnapshotInvalid(f"snapshot version must be {SNAPSHOT_VERSION}")
        segment = _integer(document["segment"], "segment", 1, MAX_SEGMENT)
        offset = _integer(document["offset"], "offset", 0)
        entries = _integer(document["entries"], "entries", 0)
        if entries == 0 and (offset, segment) != (0, 1):
            raise SnapshotInvalid("a snapshot of no entries must be at offset 0 of segment 1")
        digest = document["prefix_sha256"]
        if not isinstance(digest, str) or not PREFIX_SHA256.fullmatch(digest):
            raise SnapshotInvalid("prefix_sha256 must be 64 lowercase hex characters")
        anchors = _anchors(document["anchors"], offset, entries)
        kids = _kids(document["kids"])
        if bool(kids) != bool(offset) or bool(anchors) != bool(offset):
            raise SnapshotInvalid("anchors and kids must be empty exactly when offset is zero")
        return cls(segment, offset, entries, digest, anchors, kids)


def snapshot_path(docket_path: Path) -> Path:
    return docket_path.with_name(f"{docket_path.name}.snapshot")


def read_snapshot(path: Path, *, uid: int, reader_gid: int | None = None, dir_fd: int | None = None) -> Snapshot | None:
    try:
        content = read_state_file(path, uid=uid, reader_gid=reader_gid, max_bytes=MAX_SNAPSHOT_BYTES, dir_fd=dir_fd)
    except StateFileInvalid as exc:
        raise SnapshotInvalid(str(exc)) from None
    if content is None:
        return None
    try:
        return Snapshot.from_document(parse_strict_json(content))
    except SnapshotLegacy as exc:
        raise SnapshotLegacy(f"{path}: {exc}") from None
    except (ValueError, UnicodeDecodeError) as exc:
        raise SnapshotInvalid(f"{path} is not a valid snapshot: {exc}") from None


def write_snapshot(
    path: Path,
    snapshot: Snapshot,
    *,
    reader_gid: int | None = None,
    fsync: Callable[[int], None] = os.fsync,
) -> None:
    content = snapshot.encode()
    if len(content) > MAX_SNAPSHOT_BYTES:
        raise SnapshotInvalid(f"snapshot of {len(content)} bytes is larger than {MAX_SNAPSHOT_BYTES} bytes")
    replace_state_file(path, content, reader_gid=reader_gid, fsync=fsync)


def _integer(value: object, name: str, minimum: int, maximum: int = MAX_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SnapshotInvalid(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _anchors(document: object, offset: int, entries: int) -> dict[str, Anchor]:
    if not isinstance(document, dict):
        raise SnapshotInvalid("anchors must be an object of writer names to anchors")
    anchors: dict[str, Anchor] = {}
    for writer, value in document.items():
        if not isinstance(writer, str) or not writer:
            raise SnapshotInvalid("anchor writer names must be non-empty str")
        if not isinstance(value, dict) or set(value) != ANCHOR_KEYS:
            raise SnapshotInvalid(f"anchor for {writer!r} must have exactly hash, offset and seq")
        anchor_offset = _integer(value["offset"], f"anchors.{writer}.offset", 0)
        if anchor_offset >= offset:
            raise SnapshotInvalid(f"anchor for {writer!r} must start before the snapshot offset")
        seq = _integer(value["seq"], f"anchors.{writer}.seq", 1)
        if seq > entries:
            raise SnapshotInvalid(f"anchor seq for {writer!r} exceeds the entry count")
        digest = value["hash"]
        if not isinstance(digest, str) or not RECORD_HASH.fullmatch(digest):
            raise SnapshotInvalid(f"anchor hash for {writer!r} must be a base64url SHA-256")
        anchors[writer] = Anchor(anchor_offset, seq, digest)
    if len({anchor.offset for anchor in anchors.values()}) != len(anchors):
        raise SnapshotInvalid("two anchors cannot share one line")
    if len(anchors) > entries:
        raise SnapshotInvalid("there are more anchors than entries")
    return anchors


def _kids(document: object) -> frozenset[str]:
    if not isinstance(document, list) or not all(isinstance(kid, str) and kid for kid in document):
        raise SnapshotInvalid("kids must be a list of non-empty str")
    if document != sorted(set(document)):
        raise SnapshotInvalid("kids must be sorted and unique")
    return frozenset(document)
