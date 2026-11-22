from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import random
import stat
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO

from agent_warrant.canonical import canonicalize

from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.manifest import (
    DOCKET_ID,
    MAX_INTEGER,
    MAX_SEGMENT,
    Heads,
    Manifest,
    ManifestInvalid,
    SegmentEntry,
    heads_document,
    parse_heads,
    parse_segment_entry,
    read_docket_manifest,
)
from agent_bailiff.docket.receipt import Receipt, ReceiptDir
from agent_bailiff.docket.segments import BoundedReader, SegmentRemoved, open_segment
from agent_bailiff.docket.sink import KidIndex, Verification
from agent_bailiff.docket.socket_dir import open_lock_file, try_lock
from agent_bailiff.docket.state_file import READER_MODE, StateFileInvalid, read_state_file, replace_state_file
from agent_bailiff.strict_json import parse_strict_json

CHECKPOINT_VERSION = 1
SIDECAR_VERSION = 1
MAX_CHECKPOINT_BYTES = 1 << 20
ARCHIVE_DIR_MODE = 0o750
READ_CHUNK = 1 << 20
DEFAULT_POLL_INTERVAL = 10.0
DEFAULT_REFRESH_INTERVAL = 900.0
REFRESH_JITTER = 0.1
REFRESH_BATCH = 8
MAX_PRUNE = 64
CHECKPOINT_KEYS = frozenset({"version", "docket_id", "segment", "entries", "heads"})

logger = logging.getLogger(__name__)


class ArchiveMismatch(Exception):
    pass


class ArchiverLocked(Exception):
    pass


@dataclass(frozen=True)
class ArchiverCheckpoint:
    docket_id: str
    segment: int
    entries: int = 0
    heads: Heads = field(default_factory=dict)

    def encode(self) -> bytes:
        return canonicalize(
            {
                "version": CHECKPOINT_VERSION,
                "docket_id": self.docket_id,
                "segment": self.segment,
                "entries": self.entries,
                "heads": heads_document(self.heads),
            }
        )

    @classmethod
    def from_document(cls, document: object) -> ArchiverCheckpoint:
        if not isinstance(document, dict) or set(document) != CHECKPOINT_KEYS:
            raise ValueError(f"archiver checkpoint must have exactly {', '.join(sorted(CHECKPOINT_KEYS))}")
        if type(document["version"]) is not int or document["version"] != CHECKPOINT_VERSION:
            raise ValueError(f"archiver checkpoint version must be {CHECKPOINT_VERSION}")
        docket_id = document["docket_id"]
        if not isinstance(docket_id, str) or not DOCKET_ID.fullmatch(docket_id):
            raise ValueError("archiver checkpoint docket_id must be 32 lowercase hex characters")
        segment, entries = document["segment"], document["entries"]
        if type(segment) is not int or not 1 <= segment <= MAX_SEGMENT:
            raise ValueError(f"archiver checkpoint segment must be between 1 and {MAX_SEGMENT}")
        if type(entries) is not int or not 0 <= entries <= MAX_INTEGER:
            raise ValueError(f"archiver checkpoint entries must be between 0 and {MAX_INTEGER}")
        heads = {} if document["heads"] == {} else parse_heads(document["heads"], "heads")
        if sum(head.seq for head in heads.values()) != entries:
            raise ValueError("archiver checkpoint entries must equal the sum of its heads seq")
        return cls(docket_id, segment, entries, heads)


def sidecar_name(segment: int) -> str:
    return f"seg-{segment:012d}.json"


def copy_name(segment: int) -> str:
    return f"seg-{segment:012d}"


def encode_sidecar(docket_id: str, entry: SegmentEntry) -> bytes:
    return canonicalize({"version": SIDECAR_VERSION, "docket_id": docket_id, **entry.to_document()})


def decode_sidecar(raw: bytes, docket_id: str, segment: int) -> SegmentEntry:
    name = f"the sidecar of segment {segment}"
    try:
        document = parse_strict_json(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ArchiveMismatch(f"{name} is not valid JSON: {exc}") from None
    if not isinstance(document, dict) or (type(document.get("version")), document.get("docket_id")) != (
        int,
        docket_id,
    ):
        raise ArchiveMismatch(f"{name} is not a sidecar of docket {docket_id}")
    fields = {key: value for key, value in document.items() if key not in ("version", "docket_id")}
    try:
        entry = parse_segment_entry(fields, name)
    except ManifestInvalid as exc:
        raise ArchiveMismatch(str(exc)) from None
    if entry.segment != segment or encode_sidecar(docket_id, entry) != raw:
        raise ArchiveMismatch(f"{name} is not the canonical sidecar of that segment")
    return entry


def open_uncached(name: str, dir_fd: int) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        if sys.platform == "darwin":
            fcntl.fcntl(fd, fcntl.F_NOCACHE, 1)
        else:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except OSError:
        os.close(fd)
        raise
    return fd


@dataclass
class ArchivedCopy:
    segment: int
    stream: BinaryIO
    size: int
    sidecar: bytes


class ArchiveCopies:
    def __init__(self, path: Path, fd: int) -> None:
        self.path = path
        self._fd = fd
        self._owner = os.fstat(fd).st_uid

    @classmethod
    def open(cls, archive_dir: Path, docket_id: str) -> ArchiveCopies:
        path = archive_dir / docket_id
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            raise ArchiveMismatch(f"{path} does not exist; the archive holds no copies of this docket") from None
        if stat.S_IMODE(os.fstat(fd).st_mode) != ARCHIVE_DIR_MODE:
            os.close(fd)
            raise ArchiveMismatch(f"{path} must have mode {ARCHIVE_DIR_MODE:04o}")
        return cls(path, fd)

    def open_copy(self, segment: int) -> ArchivedCopy:
        sidecar_fd = self._open_owned(sidecar_name(segment), segment)
        try:
            sidecar = os.read(sidecar_fd, MAX_CHECKPOINT_BYTES)
        finally:
            os.close(sidecar_fd)
        fd = self._open_owned(copy_name(segment), segment)
        return ArchivedCopy(segment, os.fdopen(fd, "rb"), os.fstat(fd).st_size, sidecar)

    def _open_owned(self, name: str, segment: int) -> int:
        try:
            fd = open_uncached(name, self._fd)
        except FileNotFoundError:
            raise ArchiveMismatch(f"segment {segment} has no archived copy in {self.path}") from None
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self._owner or stat.S_IMODE(info.st_mode) != READER_MODE:
            os.close(fd)
            raise ArchiveMismatch(
                f"{self.path / name} must be a regular file owned by uid {self._owner} with mode {READER_MODE:04o}"
            )
        return fd

    def close(self) -> None:
        os.close(self._fd)

    def __enter__(self) -> ArchiveCopies:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()


class _Copying:
    def __init__(self, source: BoundedReader | BinaryIO, target_fd: int | None) -> None:
        self._source = source
        self._target_fd = target_fd
        self.digest = hashlib.sha256()
        self.size = 0

    def readline(self, size: int = -1, /) -> bytes:
        return self._take(self._source.readline(size))

    def read(self, size: int = -1, /) -> bytes:
        return self._take(self._source.read(size))

    def _take(self, raw: bytes) -> bytes:
        self.digest.update(raw)
        self.size += len(raw)
        if self._target_fd is not None:
            view = memoryview(raw)
            while view:
                view = view[os.write(self._target_fd, view) :]
        return raw


class DocketArchiver:
    def __init__(
        self,
        docket_path: Path,
        index: KidIndex,
        archive_dir: Path,
        receipt_dir: Path,
        checkpoint_path: Path,
        *,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        clock: Callable[[], float] = time.time,
        fsync: Callable[[int], None] = os.fsync,
        device_of: Callable[[Path], int] = lambda path: os.stat(path).st_dev,
        refresh_interval: float = DEFAULT_REFRESH_INTERVAL,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if refresh_interval <= 0:
            raise ValueError("the receipt refresh interval must be positive")
        self._docket_path = docket_path
        self._index = index
        self._archive_dir = archive_dir
        self._receipt_dir = receipt_dir
        self._checkpoint_path = checkpoint_path
        self._poll_interval = poll_interval
        self._clock = clock
        self._fsync = fsync
        self._device_of = device_of
        self._reader_gid = 0
        self._archive_fd: int | None = None
        self._copies_fd: int | None = None
        self._receipts: ReceiptDir | None = None
        self._checkpoint: ArchiverCheckpoint | None = None
        self._refresh_interval = refresh_interval
        self._jitter = jitter
        self._next_refresh = 0.0
        self._refreshing: deque[int] = deque()
        self._pruned_below: int | None = None

    def run(self, stop: threading.Event, *, follow: bool) -> int:
        lock_path = self._checkpoint_path.with_name(f"{self._checkpoint_path.name}.lock")
        lock_fd = open_lock_file(lock_path)
        try:
            if not try_lock(lock_fd):
                raise ArchiverLocked(f"{lock_path} is held by another archiver")
            self._open()
            archived = 0
            while not stop.is_set():
                if self._archive_next():
                    archived += 1
                    continue
                if self._refresh_next():
                    continue
                if not follow:
                    break
                stop.wait(self._poll_interval)
            return archived
        finally:
            self._close()
            os.close(lock_fd)

    def _open(self) -> None:
        self._reader_gid = self._docket_reader_gid()
        self._archive_fd = self._check_archive_dir()
        self._receipts = ReceiptDir.open(self._receipt_dir, archiver_uid=os.geteuid(), reader_gid=self._reader_gid)
        self._checkpoint = self._load_checkpoint()

    def _close(self) -> None:
        for fd in (self._copies_fd, self._archive_fd):
            if fd is not None:
                os.close(fd)
        if self._receipts is not None:
            self._receipts.close()
        self._copies_fd = self._archive_fd = self._receipts = None

    def _docket_reader_gid(self) -> int:
        info = os.stat(self._docket_path)
        if stat.S_IMODE(info.st_mode) != READER_MODE:
            raise PermissionError(f"{self._docket_path} must be shared with a reader_group (mode 0640) to archive it")
        return info.st_gid

    def _check_archive_dir(self) -> int:
        fd = os.open(self._archive_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid():
            os.close(fd)
            raise PermissionError(f"{self._archive_dir} must be owned by uid {os.geteuid()}")
        if info.st_dev == self._device_of(self._docket_path.parent):
            os.close(fd)
            raise PermissionError(
                f"{self._archive_dir} is on the docket's device; mount separate storage there (docs/DOCKET.md)"
            )
        return fd

    def _copies(self, docket_id: str) -> int:
        if self._copies_fd is not None:
            return self._copies_fd
        if self._archive_fd is None:
            raise RuntimeError("the archiver is not open")
        try:
            os.mkdir(docket_id, 0o700, dir_fd=self._archive_fd)
        except FileExistsError:
            pass
        fd = os.open(docket_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._archive_fd)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid():
            os.close(fd)
            raise PermissionError(f"{self._archive_dir / docket_id} must be owned by uid {os.geteuid()}")
        if info.st_gid != self._reader_gid or stat.S_IMODE(info.st_mode) != ARCHIVE_DIR_MODE:
            os.fchown(fd, -1, self._reader_gid)
            os.fchmod(fd, ARCHIVE_DIR_MODE)
        for name in os.listdir(fd):
            if name.endswith(".tmp"):
                os.unlink(name, dir_fd=fd)
                logger.warning("removed the unfinished archive copy %s", self._archive_dir / docket_id / name)
        self._copies_fd = fd
        return fd

    def _check_pinned(self, docket_id: str) -> None:
        if self._archive_fd is None or self._copies_fd is None:
            raise RuntimeError("the archiver is not open")
        for path, fd in ((self._archive_dir, self._archive_fd), (self._archive_dir / docket_id, self._copies_fd)):
            current = os.stat(path, follow_symlinks=False)
            opened = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ArchiveMismatch(f"{path} is no longer the directory the archiver opened")

    def _load_checkpoint(self) -> ArchiverCheckpoint | None:
        try:
            content = read_state_file(
                self._checkpoint_path, uid=os.geteuid(), reader_gid=None, max_bytes=MAX_CHECKPOINT_BYTES
            )
        except StateFileInvalid as exc:
            raise ValueError(str(exc)) from None
        if content is None:
            return None
        try:
            return ArchiverCheckpoint.from_document(parse_strict_json(content))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"{self._checkpoint_path} is not a valid archiver checkpoint: {exc}") from None

    def _save_checkpoint(self, checkpoint: ArchiverCheckpoint) -> None:
        replace_state_file(self._checkpoint_path, checkpoint.encode(), reader_gid=None, fsync=self._fsync)
        self._checkpoint = checkpoint

    def _archive_next(self) -> bool:
        manifest = read_docket_manifest(self._docket_path)
        if manifest.generation == 0:
            return False
        checkpoint = self._checkpoint or ArchiverCheckpoint(manifest.docket_id, 1)
        if checkpoint.docket_id != manifest.docket_id:
            raise ArchiveMismatch(
                f"the archiver checkpoint is for docket {checkpoint.docket_id}, not {manifest.docket_id}"
            )
        copies = self._copies(manifest.docket_id)
        if checkpoint.segment < manifest.first_segment:
            self._rebuild(checkpoint, copies)
            return True
        entry = manifest.sealed_entry(checkpoint.segment)
        if entry is None:
            return False
        try:
            return self._archive(checkpoint, entry, copies)
        except SegmentRemoved:
            return True

    def _archive(self, checkpoint: ArchiverCheckpoint, entry: SegmentEntry, copies: int) -> bool:
        opened = open_segment(self._docket_path, entry.segment)
        if opened is None:
            return False
        temporary = f"{copy_name(entry.segment)}.tmp"
        try:
            with opened.stream:
                target = self._create(temporary, copies)
                try:
                    derived = self._derive(BoundedReader(opened.stream, opened.end), checkpoint, entry.segment, target)
                    self._fsync(target)
                finally:
                    os.close(target)
            _require_equal(derived, entry)
            self._install_copy(temporary, entry, copies)
        finally:
            _unlink_if_present(temporary, copies)
        self._install_sidecar(checkpoint.docket_id, entry, copies)
        self._fsync(copies)
        self._check_copy(entry, copies)
        if self._receipts is None:
            raise RuntimeError("the archiver is not open")
        self._check_pinned(checkpoint.docket_id)
        now = int(self._clock())
        receipt = Receipt(checkpoint.docket_id, entry.segment, entry.sha256, entry.size, entry.end_heads, now)
        self._receipts.write(receipt, fsync=self._fsync)
        self._save_checkpoint(_advanced(checkpoint, entry))
        logger.info("archived docket segment %d (%d bytes, %d records)", entry.segment, entry.size, entry.entries)
        return True

    def _refresh_next(self) -> bool:
        now = self._clock()
        if self._checkpoint is None or (not self._refreshing and now < self._next_refresh):
            return False
        manifest = read_docket_manifest(self._docket_path)
        if not self._refreshing:
            self._next_refresh = now + self._refresh_interval * (1 + REFRESH_JITTER * (2 * self._jitter() - 1))
            self._prune(manifest)
            archived = self._checkpoint.segment
            self._refreshing.extend(entry.segment for entry in manifest.segments if entry.segment < archived)
            if not self._refreshing:
                return False
        copies = self._copies(manifest.docket_id)
        for _ in range(min(REFRESH_BATCH, len(self._refreshing))):
            self._refresh(manifest.docket_id, manifest.sealed_entry(self._refreshing.popleft()), copies)
        return True

    def _refresh(self, docket_id: str, entry: SegmentEntry | None, copies: int) -> None:
        if entry is None or self._receipts is None:
            return
        receipt = self._receipts.read(entry.segment)
        if receipt is None:
            return
        try:
            copied = _hash_copy(copy_name(entry.segment), copies)
        except FileNotFoundError:
            copied = None
        expected = (docket_id, entry.size, entry.sha256, dict(entry.end_heads))
        if copied != (entry.size, entry.sha256) or _receipt_fields(receipt) != expected:
            self._receipts.remove(entry.segment, fsync=self._fsync)
            logger.error(
                "the archived copy of docket segment %d is missing or differs from its manifest entry; "
                "its receipt was removed, so the segment is kept",
                entry.segment,
            )
            return
        self._check_pinned(docket_id)
        self._receipts.write(replace(receipt, verified_at=int(self._clock())), fsync=self._fsync)

    def _prune(self, manifest: Manifest) -> None:
        if manifest.base is None or self._receipts is None:
            return
        tombstone = manifest.base.segment
        start = self._pruned_below or max(1, tombstone - MAX_PRUNE)
        for segment in range(start, tombstone):
            self._receipts.remove(segment, fsync=self._fsync)
        self._pruned_below = max(start, tombstone)

    def _rebuild(self, checkpoint: ArchiverCheckpoint, copies: int) -> None:
        segment = checkpoint.segment
        try:
            fd = open_uncached(copy_name(segment), copies)
        except FileNotFoundError:
            raise ArchiveMismatch(f"segment {segment} was removed from the docket but has no archived copy") from None
        with os.fdopen(fd, "rb") as stream:
            derived = self._derive(stream, checkpoint, segment, None)
        if _read_small(sidecar_name(segment), copies) != encode_sidecar(checkpoint.docket_id, derived):
            raise ArchiveMismatch(f"the archived copy of segment {segment} does not match its sidecar")
        self._save_checkpoint(_advanced(checkpoint, derived))
        logger.info("re-derived the heads of archived docket segment %d", segment)

    def _derive(
        self, source: BoundedReader | BinaryIO, checkpoint: ArchiverCheckpoint, segment: int, target: int | None
    ) -> SegmentEntry:
        copying = _Copying(source, target)
        verification = Verification(copying, self._index, heads=checkpoint.heads, entries=checkpoint.entries)
        kids = {verified.record.kid for verified in verification}
        report = verification.report
        if not report.ok:
            raise ArchiveMismatch(f"segment {segment} fails verification at line {report.line}: {report.reason}")
        while copying.read(READ_CHUNK):
            pass
        return SegmentEntry(
            segment,
            copying.digest.hexdigest(),
            copying.size,
            checkpoint.entries + 1,
            report.entries - checkpoint.entries,
            dict(report.heads),
            frozenset(kids),
        )

    def _create(self, name: str, copies: int) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=copies)
        try:
            os.fchown(fd, -1, self._reader_gid)
            os.fchmod(fd, READER_MODE)
        except OSError:
            os.close(fd)
            raise
        return fd

    def _install_copy(self, temporary: str, entry: SegmentEntry, copies: int) -> None:
        name = copy_name(entry.segment)
        try:
            os.link(temporary, name, src_dir_fd=copies, dst_dir_fd=copies, follow_symlinks=False)
        except FileExistsError:
            size, digest = _hash_copy(name, copies)
            if (size, digest) != (entry.size, entry.sha256):
                raise ArchiveMismatch(
                    f"an archived copy of segment {entry.segment} exists with other content"
                ) from None
            logger.warning("reusing the archived copy of segment %d, which matches its manifest entry", entry.segment)

    def _install_sidecar(self, docket_id: str, entry: SegmentEntry, copies: int) -> None:
        name = sidecar_name(entry.segment)
        content = encode_sidecar(docket_id, entry)
        temporary = f"{name}.tmp"
        try:
            fd = self._create(temporary, copies)
            try:
                _write_all(fd, content)
                self._fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temporary, name, src_dir_fd=copies, dst_dir_fd=copies, follow_symlinks=False)
            except FileExistsError:
                if _read_small(name, copies) != content:
                    raise ArchiveMismatch(f"the sidecar of segment {entry.segment} exists with other content") from None
        finally:
            _unlink_if_present(temporary, copies)

    def _check_copy(self, entry: SegmentEntry, copies: int) -> None:
        size, digest = _hash_copy(copy_name(entry.segment), copies)
        if (size, digest) != (entry.size, entry.sha256):
            raise ArchiveMismatch(f"the archived copy of segment {entry.segment} reads back with other content")


def _require_equal(derived: SegmentEntry, entry: SegmentEntry) -> None:
    differences = [
        item.name for item in fields(SegmentEntry) if getattr(derived, item.name) != _value(entry, item.name)
    ]
    if differences:
        raise ArchiveMismatch(f"segment {entry.segment} does not match its manifest entry: {', '.join(differences)}")


def _value(entry: SegmentEntry, name: str) -> Any:
    value = getattr(entry, name)
    return dict(value) if name == "end_heads" else value


def _receipt_fields(receipt: Receipt) -> tuple[str, int, str, dict[str, Head]]:
    return receipt.docket_id, receipt.size, receipt.sha256, dict(receipt.end_heads)


def _advanced(checkpoint: ArchiverCheckpoint, entry: SegmentEntry) -> ArchiverCheckpoint:
    heads: dict[str, Head] = dict(entry.end_heads)
    return ArchiverCheckpoint(checkpoint.docket_id, entry.segment + 1, entry.first_entry + entry.entries - 1, heads)


def _hash_copy(name: str, copies: int) -> tuple[int, str]:
    fd = open_uncached(name, copies)
    digest = hashlib.sha256()
    size = 0
    try:
        while chunk := os.read(fd, READ_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return size, digest.hexdigest()


def _read_small(name: str, copies: int) -> bytes:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=copies)
    except FileNotFoundError:
        return b""
    try:
        return os.read(fd, MAX_CHECKPOINT_BYTES)
    finally:
        os.close(fd)


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        view = view[os.write(fd, view) :]


def _unlink_if_present(name: str, dir_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
