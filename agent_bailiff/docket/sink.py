from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.docket.entry import Record, decode_record
from agent_bailiff.docket.peer import PeerCredentialsUnavailable, peer_uid
from agent_bailiff.docket.private_dir import open_private_dir
from agent_bailiff.docket.protocol import LENGTH, MAX_FRAME_BYTES, OP_APPEND, OP_HEAD, encode_response
from agent_bailiff.docket.socket_dir import (
    SOCKET_MODE,
    open_lock_file,
    prepare_socket_dir,
    remove_stale_socket,
    try_lock,
    unlink_if_same,
)
from agent_bailiff.signing import MAX_TOKEN_CHARS, Refused

DOCKET_MODE = 0o600
READER_DOCKET_MODE = 0o640
DEFAULT_FRAME_TIMEOUT = 5.0
DEFAULT_IDLE_TIMEOUT = 5.0
DEFAULT_MAX_LIFETIME = 60.0
DEFAULT_MAX_CONNECTIONS = 16

Writers = Mapping[str, Mapping[str, Ed25519PublicKey]]
KidIndex = dict[str, tuple[str, Ed25519PublicKey]]


@dataclass(frozen=True)
class Head:
    seq: int
    hash: str | None


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    entries: int
    heads: dict[str, Head] = field(default_factory=dict)
    line: int | None = None
    reason: str = ""
    detail: str = ""
    valid_bytes: int = 0


class DocketLocked(Exception):
    pass


class DocketCorrupt(Exception):
    def __init__(self, report: VerifyReport) -> None:
        super().__init__(f"docket fails verification at line {report.line}: {report.reason} {report.detail}".strip())
        self.report = report


def build_kid_index(writers: Writers) -> KidIndex:
    index: KidIndex = {}
    for writer, keys in writers.items():
        if not isinstance(writer, str) or not writer:
            raise ValueError("writer names must be non-empty str")
        for kid, key in keys.items():
            if not isinstance(kid, str) or not kid:
                raise ValueError(f"key ids for writer {writer!r} must be non-empty str")
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError(f"key {kid!r} for writer {writer!r} must be an Ed25519PublicKey")
            if kid in index:
                raise ValueError(f"key id {kid!r} is pinned for more than one writer")
            index[kid] = (writer, key)
    return index


def check_chain(heads: Mapping[str, Head], record: Record) -> Refused | None:
    head = heads.get(record.writer, Head(seq=0, hash=None))
    if record.seq != head.seq + 1:
        return Refused("wrong_seq", f"expected seq {head.seq + 1} for writer {record.writer}, got {record.seq}")
    if record.prev != head.hash:
        return Refused("broken_prev", f"prev does not match the last entry of writer {record.writer}")
    return None


def verify_docket(path: Path, writers: Writers) -> VerifyReport:
    with open(path, "rb") as docket:
        return _verify_stream(docket, build_kid_index(writers))


def _verify_fd(fd: int, index: KidIndex) -> VerifyReport:
    with os.fdopen(os.dup(fd), "rb") as docket:
        docket.seek(0)
        return _verify_stream(docket, index)


def _verify_stream(docket: BinaryIO, index: KidIndex) -> VerifyReport:
    verification = Verification(docket, index)
    for _ in verification:
        pass
    return verification.report


@dataclass(frozen=True)
class VerifiedLine:
    line: int
    record: Record
    start: int
    end: int


class LineSource(Protocol):
    def readline(self, size: int = -1, /) -> bytes: ...

    def read(self, size: int = -1, /) -> bytes: ...


class Verification:
    def __init__(
        self,
        docket: LineSource,
        index: KidIndex,
        *,
        heads: Mapping[str, Head] | None = None,
        entries: int = 0,
        offset: int = 0,
    ) -> None:
        self._docket = docket
        self._index = index
        self._heads = dict(heads or {})
        self._entries = entries
        self._offset = offset
        self._started = False
        self._report: VerifyReport | None = None

    @property
    def report(self) -> VerifyReport:
        if self._report is None:
            raise RuntimeError("the verification has not read the docket to its end")
        return self._report

    def __iter__(self) -> Iterator[VerifiedLine]:
        if self._started:
            raise RuntimeError("a verification can be iterated only once")
        self._started = True
        return self._lines()

    def _lines(self) -> Iterator[VerifiedLine]:
        heads = self._heads
        count = self._entries
        offset = self._offset
        while raw := self._docket.readline(MAX_TOKEN_CHARS + 2):
            line_number = count + 1
            if not raw.endswith(b"\n"):
                if self._docket.read(1):
                    self._report = VerifyReport(
                        False, count, heads, line_number, "malformed", "line exceeds the limit", offset
                    )
                else:
                    self._report = VerifyReport(
                        False, count, heads, line_number, "torn_tail", "last line is incomplete", offset
                    )
                return
            record = _verify_line(raw[:-1], self._index, heads)
            if isinstance(record, Refused):
                self._report = VerifyReport(False, count, heads, line_number, record.reason, record.detail, offset)
                return
            heads[record.writer] = Head(seq=record.seq, hash=record.hash)
            count = line_number
            start = offset
            offset += len(raw)
            yield VerifiedLine(line_number, record, start, offset)
        self._report = VerifyReport(True, count, heads, valid_bytes=offset)


def repair(docket_path: Path, side_path: Path, writers: Writers, *, reader_gid: int | None = None) -> VerifyReport:
    index = build_kid_index(writers)
    directory_fd = open_private_dir(docket_path.parent)
    try:
        fd = os.open(docket_path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            _lock(fd, docket_path)
            _check_docket_file(fd, docket_path, reader_gid)
            report = _verify_fd(fd, index)
            if report.ok:
                return report
            if report.reason != "torn_tail":
                raise DocketCorrupt(report)
            tail = os.pread(fd, os.fstat(fd).st_size - report.valid_bytes, report.valid_bytes)
            _write_side_file(side_path, tail)
            os.ftruncate(fd, report.valid_bytes)
            os.fsync(fd)
            os.fsync(directory_fd)
            repaired = _verify_fd(fd, index)
            if not repaired.ok:
                raise DocketCorrupt(repaired)
            return repaired
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _write_side_file(path: Path, content: bytes) -> None:
    directory_fd = open_private_dir(path.parent)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(path.name, flags, DOCKET_MODE, dir_fd=directory_fd)
        with os.fdopen(fd, "wb") as side:
            side.write(content)
            side.flush()
            os.fsync(side.fileno())
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _verify_line(raw: bytes, index: KidIndex, heads: Mapping[str, Head]) -> Record | Refused:
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError:
        return Refused("malformed", "line is not ASCII")
    record = decode_record(token, index)
    if isinstance(record, Refused):
        return record
    return check_chain(heads, record) or record


class DocketSink:
    def __init__(
        self,
        docket_path: Path,
        socket_path: Path,
        writers: Writers,
        allowed_uids: Iterable[int],
        *,
        socket_gid: int | None = None,
        reader_gid: int | None = None,
        max_frame_bytes: int = MAX_FRAME_BYTES,
        frame_timeout: float = DEFAULT_FRAME_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_lifetime: float = DEFAULT_MAX_LIFETIME,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        fsync: Callable[[int], None] = os.fsync,
    ) -> None:
        self._docket_path = docket_path
        self._socket_path = socket_path
        self._writers = writers
        self._index = build_kid_index(writers)
        self._allowed_uids = frozenset(allowed_uids)
        self._socket_gid = os.getegid() if socket_gid is None else socket_gid
        self._reader_gid = reader_gid
        self._max_frame_bytes = max_frame_bytes
        self._frame_timeout = frame_timeout
        self._idle_timeout = idle_timeout
        self._max_lifetime = max_lifetime
        self._max_connections = max_connections
        self._fsync = fsync
        self._heads: dict[str, Head] = {}
        self._fd: int | None = None
        self._socket_lock_fd: int | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._server: asyncio.Server | None = None
        self._active = 0
        self._failed = False

    @property
    def heads(self) -> dict[str, Head]:
        return dict(self._heads)

    async def start(self) -> None:
        try:
            await self._start()
        except BaseException:
            await self.close()
            raise

    async def _start(self) -> None:
        self._fd = self._open_docket()
        _lock(self._fd, self._docket_path)
        _check_docket_file(self._fd, self._docket_path, self._reader_gid)
        report = _verify_fd(self._fd, self._index)
        if not report.ok:
            raise DocketCorrupt(report)
        self._heads = dict(report.heads)
        prepare_socket_dir(self._socket_path.parent, self._socket_gid)
        lock_path = self._socket_path.with_name(f"{self._socket_path.name}.lock")
        self._socket_lock_fd = open_lock_file(lock_path)
        _lock(self._socket_lock_fd, lock_path)
        remove_stale_socket(self._socket_path)
        self._server = await asyncio.start_unix_server(self._handle, path=str(self._socket_path), cleanup_socket=False)
        info = os.lstat(self._socket_path)
        self._socket_identity = (info.st_dev, info.st_ino)
        os.chown(self._socket_path, -1, self._socket_gid)
        os.chmod(self._socket_path, SOCKET_MODE)

    def _open_docket(self) -> int:
        directory_fd = open_private_dir(self._docket_path.parent)
        try:
            flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(self._docket_path.name, flags | os.O_CREAT | os.O_EXCL, DOCKET_MODE, dir_fd=directory_fd)
            except FileExistsError:
                fd = os.open(self._docket_path.name, flags, dir_fd=directory_fd)
            else:
                self._share_with_readers(fd)
            try:
                self._fsync(directory_fd)
            except OSError:
                self._failed = True
            return fd
        finally:
            os.close(directory_fd)

    def _share_with_readers(self, fd: int) -> None:
        if self._reader_gid is None:
            return
        try:
            os.fchown(fd, -1, self._reader_gid)
            os.fchmod(fd, READER_DOCKET_MODE)
        except OSError:
            os.close(fd)
            raise

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._socket_identity is not None:
            unlink_if_same(self._socket_path, self._socket_identity)
            self._socket_identity = None
        if self._socket_lock_fd is not None:
            os.close(self._socket_lock_fd)
            self._socket_lock_fd = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not await self._admit(writer):
                return
            self._active += 1
            try:
                async with asyncio.timeout(self._max_lifetime):
                    await self._serve(reader, writer)
            except TimeoutError:
                return
            finally:
                self._active -= 1
        finally:
            writer.close()

    async def _admit(self, writer: asyncio.StreamWriter) -> bool:
        try:
            uid = peer_uid(writer.get_extra_info("socket"))
        except (OSError, PeerCredentialsUnavailable):
            return False
        if uid not in self._allowed_uids:
            await self._reply(writer, _refusal("peer_not_allowed"))
            return False
        if self._active >= self._max_connections:
            await self._reply(writer, _refusal("overloaded"))
            return False
        return True

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            try:
                async with asyncio.timeout(self._idle_timeout):
                    header = await reader.readexactly(LENGTH.size)
                async with asyncio.timeout(self._frame_timeout):
                    (length,) = LENGTH.unpack(header)
                    if length > self._max_frame_bytes:
                        await self._reply(writer, _refusal("frame_too_large"))
                        return
                    payload = await reader.readexactly(length)
            except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                return
            if not await self._reply(writer, self._dispatch(payload)):
                return

    async def _reply(self, writer: asyncio.StreamWriter, response: dict[str, Any]) -> bool:
        try:
            async with asyncio.timeout(self._frame_timeout):
                writer.write(encode_response(response))
                await writer.drain()
        except (TimeoutError, ConnectionError):
            return False
        return True

    def _dispatch(self, payload: bytes) -> dict[str, Any]:
        operation, body = payload[:1], payload[1:]
        if operation == OP_APPEND:
            return self._append(body)
        if operation == OP_HEAD:
            return self._head(body)
        return _refusal("malformed")

    def _head(self, body: bytes) -> dict[str, Any]:
        try:
            writer = body.decode("utf-8")
        except UnicodeDecodeError:
            return _refusal("malformed")
        if writer not in self._writers:
            return _refusal("unknown_writer")
        head = self._heads.get(writer, Head(seq=0, hash=None))
        return {"ok": True, "seq": head.seq, "hash": head.hash}

    def _append(self, body: bytes) -> dict[str, Any]:
        if self._failed or self._fd is None:
            return _refusal("sink_failed")
        try:
            token = body.decode("ascii")
        except UnicodeDecodeError:
            return _refusal("malformed")
        record = decode_record(token, self._index)
        if isinstance(record, Refused):
            return _refusal(record.reason)
        refusal = check_chain(self._heads, record)
        if refusal is not None:
            return _refusal(refusal.reason)
        line = f"{token}\n".encode("ascii")
        self._failed = True
        try:
            if os.write(self._fd, line) != len(line):
                return _refusal("write_failed")
            self._fsync(self._fd)
        except OSError:
            return _refusal("write_failed")
        self._failed = False
        self._heads[record.writer] = Head(seq=record.seq, hash=record.hash)
        return {"ok": True, "seq": record.seq, "hash": record.hash}


def _refusal(reason: str) -> dict[str, Any]:
    return {"ok": False, "reason": reason}


def _check_docket_file(fd: int, path: Path, reader_gid: int | None) -> None:
    info = os.fstat(fd)
    owned = stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
    if reader_gid is None:
        if not owned or stat.S_IMODE(info.st_mode) != DOCKET_MODE:
            raise PermissionError(f"{path} must be a regular file owned by uid {os.geteuid()} with mode 0600")
        return
    if not owned or stat.S_IMODE(info.st_mode) != READER_DOCKET_MODE or info.st_gid != reader_gid:
        raise PermissionError(
            f"{path} must be a regular file owned by uid {os.geteuid()}, group {reader_gid}, with mode 0640"
        )


def _lock(fd: int, path: Path) -> None:
    if not try_lock(fd):
        raise DocketLocked(f"{path} is held by another sink")
