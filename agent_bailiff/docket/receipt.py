from __future__ import annotations

import calendar
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

from agent_warrant.canonical import canonicalize

from agent_bailiff.docket.manifest import (
    DOCKET_ID,
    MAX_INTEGER,
    MAX_SEGMENT,
    SHA256,
    Heads,
    ManifestInvalid,
    heads_document,
    parse_heads,
)
from agent_bailiff.docket.state_file import StateFileInvalid, read_state_file, replace_state_file
from agent_bailiff.strict_json import parse_strict_json

RECEIPT_VERSION = 1
MAX_RECEIPT_BYTES = 1 << 20
RECEIPT_DIR_MODE = 0o750
RECEIPT_KEYS = frozenset({"version", "docket_id", "segment", "sha256", "size", "end_heads", "verified_at"})
VERIFIED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
VERIFIED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class ReceiptInvalid(ValueError):
    pass


@dataclass(frozen=True)
class Receipt:
    docket_id: str
    segment: int
    sha256: str
    size: int
    end_heads: Heads
    verified_at: int

    def to_document(self) -> dict[str, Any]:
        return {
            "version": RECEIPT_VERSION,
            "docket_id": self.docket_id,
            "segment": self.segment,
            "sha256": self.sha256,
            "size": self.size,
            "end_heads": heads_document(self.end_heads),
            "verified_at": time.strftime(VERIFIED_AT_FORMAT, time.gmtime(self.verified_at)),
        }

    def encode(self) -> bytes:
        return canonicalize(self.to_document())

    @classmethod
    def from_document(cls, document: object) -> Receipt:
        if not isinstance(document, dict) or set(document) != RECEIPT_KEYS:
            raise ReceiptInvalid(f"receipt must be an object with exactly {', '.join(sorted(RECEIPT_KEYS))}")
        if type(document["version"]) is not int or document["version"] != RECEIPT_VERSION:
            raise ReceiptInvalid(f"receipt version must be {RECEIPT_VERSION}")
        docket_id = document["docket_id"]
        if not isinstance(docket_id, str) or not DOCKET_ID.fullmatch(docket_id):
            raise ReceiptInvalid("docket_id must be 32 lowercase hex characters")
        segment = _integer(document["segment"], "segment", MAX_SEGMENT)
        digest = document["sha256"]
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ReceiptInvalid("sha256 must be 64 lowercase hex characters")
        size = _integer(document["size"], "size", MAX_INTEGER)
        try:
            end_heads = parse_heads(document["end_heads"], "end_heads")
        except ManifestInvalid as exc:
            raise ReceiptInvalid(str(exc)) from None
        verified_at = _verified_at(document["verified_at"])
        return cls(docket_id, segment, digest, size, end_heads, verified_at)


def receipt_name(segment: int) -> str:
    if not 1 <= segment <= MAX_SEGMENT:
        raise ValueError(f"segment must be between 1 and {MAX_SEGMENT}")
    return f"seg-{segment:012d}.receipt"


class ReceiptDir:
    def __init__(self, path: Path, fd: int, *, archiver_uid: int, reader_gid: int) -> None:
        self.path = path
        self._fd = fd
        self._archiver_uid = archiver_uid
        self._reader_gid = reader_gid

    @classmethod
    def open(cls, path: Path, *, archiver_uid: int, reader_gid: int) -> ReceiptDir:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise ReceiptInvalid(f"{path} cannot be opened as a directory: {exc.strerror}") from None
        info = os.fstat(fd)
        if info.st_uid != archiver_uid or info.st_gid != reader_gid or stat.S_IMODE(info.st_mode) != RECEIPT_DIR_MODE:
            os.close(fd)
            raise ReceiptInvalid(
                f"{path} must be owned by uid {archiver_uid}, group {reader_gid}, with mode {RECEIPT_DIR_MODE:04o}"
            )
        return cls(path, fd, archiver_uid=archiver_uid, reader_gid=reader_gid)

    def read(self, segment: int) -> Receipt | None:
        path = self.path / receipt_name(segment)
        try:
            content = read_state_file(
                path, uid=self._archiver_uid, reader_gid=self._reader_gid, max_bytes=MAX_RECEIPT_BYTES, dir_fd=self._fd
            )
        except StateFileInvalid as exc:
            raise ReceiptInvalid(str(exc)) from None
        if content is None:
            return None
        try:
            receipt = Receipt.from_document(parse_strict_json(content))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReceiptInvalid(f"{path} is not a valid receipt: {exc}") from None
        if receipt.segment != segment:
            raise ReceiptInvalid(f"{path} names segment {receipt.segment}")
        return receipt

    def write(self, receipt: Receipt, *, fsync: Callable[[int], None] = os.fsync) -> None:
        path = self.path / receipt_name(receipt.segment)
        replace_state_file(path, receipt.encode(), reader_gid=self._reader_gid, fsync=fsync, dir_fd=self._fd)

    def remove(self, segment: int, *, fsync: Callable[[int], None] = os.fsync) -> None:
        try:
            os.unlink(receipt_name(segment), dir_fd=self._fd)
        except FileNotFoundError:
            return
        fsync(self._fd)

    def close(self) -> None:
        os.close(self._fd)

    def __enter__(self) -> ReceiptDir:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()


def _integer(value: object, name: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ReceiptInvalid(f"{name} must be an integer between 1 and {maximum}")
    return value


def _verified_at(value: object) -> int:
    if not isinstance(value, str) or not VERIFIED_AT.fullmatch(value):
        raise ReceiptInvalid("verified_at must be an RFC 3339 UTC time like 2026-11-21T12:00:00Z")
    try:
        return calendar.timegm(time.strptime(value, VERIFIED_AT_FORMAT))
    except ValueError:
        raise ReceiptInvalid(f"verified_at {value} is not a valid time") from None
