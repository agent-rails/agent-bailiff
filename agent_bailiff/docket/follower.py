from __future__ import annotations

import json
import logging
import os
import stat
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from agent_bailiff.docket.private_dir import open_private_dir
from agent_bailiff.docket.sink import DocketCorrupt, Head, KidIndex, Verification, VerifiedLine
from agent_bailiff.docket.socket_dir import open_lock_file, try_lock
from agent_bailiff.signing import MAX_TOKEN_CHARS, token_hash

CHECKPOINT_VERSION = 1
CHECKPOINT_MODE = 0o600
MAX_CHECKPOINT_BYTES = 1 << 20
DEFAULT_BATCH_SIZE = 256
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_STALL_AFTER = 30.0

BatchHandler = Callable[[Sequence[VerifiedLine], threading.Event], None]

logger = logging.getLogger(__name__)


class CheckpointMismatch(Exception):
    pass


class FollowerLocked(Exception):
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


class DocketFollower:
    def __init__(
        self,
        docket_path: Path,
        index: KidIndex,
        checkpoint_path: Path,
        handle: BatchHandler,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        stall_after: float = DEFAULT_STALL_AFTER,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch size must be at least 1")
        self._docket_path = docket_path
        self._index = index
        self._checkpoint_path = checkpoint_path
        self._handle = handle
        self._batch_size = batch_size
        self._poll_interval = poll_interval
        self._stall_after = stall_after
        self._clock = clock
        self._handled = 0

    def run(self, stop: threading.Event, *, follow: bool) -> int:
        lock_path = self._checkpoint_path.with_name(f"{self._checkpoint_path.name}.lock")
        lock_fd = open_lock_file(lock_path)
        try:
            if not try_lock(lock_fd):
                raise FollowerLocked(f"{lock_path} is held by another follower")
            return self._run_locked(stop, follow=follow)
        finally:
            os.close(lock_fd)

    def _run_locked(self, stop: threading.Event, *, follow: bool) -> int:
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
        return self._handled

    def _pass(self, docket: BinaryIO, identity: tuple[int, int], position: _Position, stop: threading.Event) -> bool:
        current = os.stat(self._docket_path)
        if (current.st_dev, current.st_ino) != identity:
            raise CheckpointMismatch(f"{self._docket_path} was replaced while following")
        end = os.fstat(docket.fileno()).st_size
        if end < position.offset:
            raise CheckpointMismatch(f"{self._docket_path} is shorter than the checkpoint offset {position.offset}")
        docket.seek(position.offset)
        verification = Verification(
            _Bounded(docket, end), self._index, heads=position.heads, entries=position.entries, offset=position.offset
        )
        batch: list[VerifiedLine] = []
        for verified in verification:
            batch.append(verified)
            if len(batch) == self._batch_size:
                self._commit(batch, identity, position, stop)
                batch = []
                if stop.is_set():
                    return False
        if batch:
            self._commit(batch, identity, position, stop)
        report = verification.report
        if not report.ok and report.reason != "torn_tail":
            raise DocketCorrupt(report)
        return not report.ok

    def _commit(
        self, batch: Sequence[VerifiedLine], identity: tuple[int, int], position: _Position, stop: threading.Event
    ) -> None:
        self._handle(batch, stop)
        _advance(position, batch)
        save_checkpoint(self._checkpoint_path, _checkpoint(identity, position))
        self._handled += len(batch)

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
        raise CheckpointMismatch(f"the docket is shorter than the checkpoint offset {checkpoint.offset}")
    if _line_hash(docket.readline(MAX_TOKEN_CHARS + 2)) != checkpoint.first_hash:
        raise CheckpointMismatch("the docket's first record differs from the checkpoint")
    docket.seek(checkpoint.last_start)
    if _line_hash(docket.read(checkpoint.offset - checkpoint.last_start)) != checkpoint.last_hash:
        raise CheckpointMismatch("the docket's last checkpointed record differs from the checkpoint")
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
        raise RuntimeError("a checkpoint needs at least one handled record")
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
