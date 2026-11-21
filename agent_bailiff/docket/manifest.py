from __future__ import annotations

import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize

from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.state_file import READER_MODE, StateFileInvalid, read_state_file, replace_state_file
from agent_bailiff.strict_json import parse_strict_json

MANIFEST_VERSION = 1
MAX_MANIFEST_BYTES = 1 << 22
MAX_INTEGER = 2**53 - 1
MAX_SEGMENT = 10**12 - 1
MANIFEST_KEYS = frozenset({"version", "docket_id", "generation", "base", "segments"})
BASE_KEYS = frozenset({"segment", "entries", "end_heads"})
SEGMENT_KEYS = frozenset({"segment", "sha256", "size", "first_entry", "entries", "end_heads", "kids"})
HEAD_KEYS = frozenset({"seq", "hash"})
DOCKET_ID = re.compile(r"[0-9a-f]{32}")
SHA256 = re.compile(r"[0-9a-f]{64}")
RECORD_HASH = re.compile(r"[A-Za-z0-9_-]{43}")

Heads = Mapping[str, Head]


class ManifestInvalid(ValueError):
    pass


@dataclass(frozen=True)
class Base:
    segment: int
    entries: int
    end_heads: Heads

    def to_document(self) -> dict[str, Any]:
        return {"segment": self.segment, "entries": self.entries, "end_heads": _heads_document(self.end_heads)}


@dataclass(frozen=True)
class SegmentEntry:
    segment: int
    sha256: str
    size: int
    first_entry: int
    entries: int
    end_heads: Heads
    kids: frozenset[str]

    def to_document(self) -> dict[str, Any]:
        return {
            "segment": self.segment,
            "sha256": self.sha256,
            "size": self.size,
            "first_entry": self.first_entry,
            "entries": self.entries,
            "end_heads": _heads_document(self.end_heads),
            "kids": sorted(self.kids),
        }


@dataclass(frozen=True)
class Manifest:
    docket_id: str
    generation: int
    base: Base | None = None
    segments: tuple[SegmentEntry, ...] = field(default_factory=tuple)

    @classmethod
    def new(cls) -> Manifest:
        return cls(secrets.token_hex(16), 0)

    @property
    def active_segment(self) -> int:
        if self.segments:
            return self.segments[-1].segment + 1
        return 1 if self.base is None else self.base.segment + 1

    @property
    def first_segment(self) -> int:
        return 1 if self.base is None else self.base.segment + 1

    def sealed_entry(self, segment: int) -> SegmentEntry | None:
        position = segment - self.first_segment
        if 0 <= position < len(self.segments):
            return self.segments[position]
        return None

    @property
    def entries(self) -> int:
        if self.segments:
            last = self.segments[-1]
            return last.first_entry + last.entries - 1
        return 0 if self.base is None else self.base.entries

    @property
    def seeds(self) -> dict[str, Head]:
        if self.segments:
            return dict(self.segments[-1].end_heads)
        return {} if self.base is None else dict(self.base.end_heads)

    def sealed(self, entry: SegmentEntry) -> Manifest:
        return Manifest.from_document(
            replace(self, generation=self.generation + 1, segments=(*self.segments, entry)).to_document()
        )

    def to_document(self) -> dict[str, Any]:
        return {
            "version": MANIFEST_VERSION,
            "docket_id": self.docket_id,
            "generation": self.generation,
            "base": None if self.base is None else self.base.to_document(),
            "segments": [segment.to_document() for segment in self.segments],
        }

    def encode(self) -> bytes:
        return canonicalize(self.to_document())

    @classmethod
    def from_document(cls, document: object) -> Manifest:
        if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
            raise ManifestInvalid(f"manifest must be an object with exactly {', '.join(sorted(MANIFEST_KEYS))}")
        if type(document["version"]) is not int or document["version"] != MANIFEST_VERSION:
            raise ManifestInvalid(f"manifest version must be {MANIFEST_VERSION}")
        docket_id = document["docket_id"]
        if not isinstance(docket_id, str) or not DOCKET_ID.fullmatch(docket_id):
            raise ManifestInvalid("docket_id must be 32 lowercase hex characters")
        generation = _integer(document["generation"], "generation", 1)
        base = _base(document["base"])
        segments = _segments(document["segments"], base)
        return cls(docket_id, generation, base, segments)


def manifest_path(docket_path: Path) -> Path:
    return docket_path.with_name(f"{docket_path.name}.manifest")


def segment_path(docket_path: Path, segment: int) -> Path:
    if not 1 <= segment <= MAX_SEGMENT:
        raise ValueError(f"segment must be between 1 and {MAX_SEGMENT}")
    return docket_path.with_name(f"{docket_path.name}.seg-{segment:012d}")


def read_manifest(path: Path, *, uid: int, reader_gid: int | None = None, dir_fd: int | None = None) -> Manifest | None:
    try:
        content = read_state_file(path, uid=uid, reader_gid=reader_gid, max_bytes=MAX_MANIFEST_BYTES, dir_fd=dir_fd)
    except StateFileInvalid as exc:
        raise ManifestInvalid(str(exc)) from None
    if content is None:
        return None
    try:
        return Manifest.from_document(parse_strict_json(content))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ManifestInvalid(f"{path} is not a valid manifest: {exc}") from None


def read_docket_manifest(docket_path: Path) -> Manifest:
    path = manifest_path(docket_path)
    owner = os.stat(docket_path.parent).st_uid
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return Manifest.new()
    reader_gid = info.st_gid if stat.S_IMODE(info.st_mode) == READER_MODE else None
    manifest = read_manifest(path, uid=owner, reader_gid=reader_gid)
    return Manifest.new() if manifest is None else manifest


def write_manifest(
    path: Path,
    manifest: Manifest,
    *,
    reader_gid: int | None = None,
    fsync: Callable[[int], None] = os.fsync,
) -> None:
    content = manifest.encode()
    if len(content) > MAX_MANIFEST_BYTES:
        raise ManifestInvalid(f"manifest of {len(content)} bytes is larger than {MAX_MANIFEST_BYTES} bytes")
    replace_state_file(path, content, reader_gid=reader_gid, fsync=fsync)


def _integer(value: object, name: str, minimum: int, maximum: int = MAX_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ManifestInvalid(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _base(document: object) -> Base | None:
    if document is None:
        return None
    if not isinstance(document, dict) or set(document) != BASE_KEYS:
        raise ManifestInvalid(f"base must be null or an object with exactly {', '.join(sorted(BASE_KEYS))}")
    segment = _integer(document["segment"], "base.segment", 1, MAX_SEGMENT)
    entries = _integer(document["entries"], "base.entries", 1)
    end_heads = _heads(document["end_heads"], "base.end_heads")
    if sum(head.seq for head in end_heads.values()) != entries:
        raise ManifestInvalid("base.entries must equal the sum of base.end_heads seq")
    return Base(segment, entries, end_heads)


def _segments(document: object, base: Base | None) -> tuple[SegmentEntry, ...]:
    if not isinstance(document, list):
        raise ManifestInvalid("segments must be a list")
    previous: Heads = {} if base is None else base.end_heads
    next_segment = 1 if base is None else base.segment + 1
    next_entry = 1 if base is None else base.entries + 1
    segments: list[SegmentEntry] = []
    for position, value in enumerate(document):
        entry = _segment(value, f"segments[{position}]", previous)
        if entry.segment != next_segment:
            raise ManifestInvalid(f"segments[{position}].segment must be {next_segment}")
        if entry.first_entry != next_entry:
            raise ManifestInvalid(f"segments[{position}].first_entry must be {next_entry}")
        segments.append(entry)
        previous = entry.end_heads
        next_segment += 1
        next_entry += entry.entries
    return tuple(segments)


def _segment(document: object, name: str, previous: Heads) -> SegmentEntry:
    if not isinstance(document, dict) or set(document) != SEGMENT_KEYS:
        raise ManifestInvalid(f"{name} must be an object with exactly {', '.join(sorted(SEGMENT_KEYS))}")
    segment = _integer(document["segment"], f"{name}.segment", 1, MAX_SEGMENT)
    digest = document["sha256"]
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ManifestInvalid(f"{name}.sha256 must be 64 lowercase hex characters")
    size = _integer(document["size"], f"{name}.size", 1)
    first_entry = _integer(document["first_entry"], f"{name}.first_entry", 1)
    entries = _integer(document["entries"], f"{name}.entries", 1)
    end_heads = _heads(document["end_heads"], f"{name}.end_heads")
    _check_advance(previous, end_heads, entries, name)
    kids = _kids(document["kids"], f"{name}.kids")
    if len(kids) > entries:
        raise ManifestInvalid(f"{name}.kids has more key ids than entries")
    return SegmentEntry(segment, digest, size, first_entry, entries, end_heads, kids)


def _check_advance(previous: Heads, end_heads: Heads, entries: int, name: str) -> None:
    missing = sorted(previous.keys() - end_heads.keys())
    if missing:
        raise ManifestInvalid(f"{name}.end_heads drops writers {', '.join(missing)}")
    for writer, before in previous.items():
        after = end_heads[writer]
        if after.seq < before.seq:
            raise ManifestInvalid(f"{name}.end_heads.{writer}.seq goes backwards")
        if after.seq == before.seq and after.hash != before.hash:
            raise ManifestInvalid(f"{name}.end_heads.{writer}.hash changes without a new entry")
    advanced = sum(head.seq for head in end_heads.values()) - sum(head.seq for head in previous.values())
    if advanced != entries:
        raise ManifestInvalid(f"{name}.entries must equal the seq advance of its end_heads")


def _heads(document: object, name: str) -> dict[str, Head]:
    if not isinstance(document, dict) or not document:
        raise ManifestInvalid(f"{name} must be a non-empty object of writer names to heads")
    heads: dict[str, Head] = {}
    for writer, value in document.items():
        if not isinstance(writer, str) or not writer:
            raise ManifestInvalid(f"{name} writer names must be non-empty str")
        if not isinstance(value, dict) or set(value) != HEAD_KEYS:
            raise ManifestInvalid(f"{name}.{writer} must have exactly hash and seq")
        seq = _integer(value["seq"], f"{name}.{writer}.seq", 1)
        digest = value["hash"]
        if not isinstance(digest, str) or not RECORD_HASH.fullmatch(digest):
            raise ManifestInvalid(f"{name}.{writer}.hash must be a base64url SHA-256")
        heads[writer] = Head(seq, digest)
    return heads


def _heads_document(heads: Heads) -> dict[str, Any]:
    return {writer: {"seq": head.seq, "hash": head.hash} for writer, head in heads.items()}


def _kids(document: object, name: str) -> frozenset[str]:
    if not isinstance(document, list) or not document or not all(isinstance(kid, str) and kid for kid in document):
        raise ManifestInvalid(f"{name} must be a non-empty list of non-empty str")
    if document != sorted(set(document)):
        raise ManifestInvalid(f"{name} must be sorted and unique")
    return frozenset(document)
