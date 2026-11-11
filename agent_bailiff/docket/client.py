from __future__ import annotations

import os
import re
import socket
import stat
import threading
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize, strict_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.docket.entry import Entry, Record, encode_record
from agent_bailiff.docket.peer import PeerCredentialsUnavailable, peer_uid
from agent_bailiff.docket.private_dir import open_private_dir
from agent_bailiff.docket.protocol import (
    MAX_RESPONSE_BYTES,
    OP_APPEND,
    OP_HEAD,
    decode_response,
    encode_frame,
    read_frame,
)
from agent_bailiff.docket.sink import Head

DEFAULT_TIMEOUT = 5.0
STATE_MODE = 0o600
MAX_STATE_BYTES = 256
CHAIN_REFUSALS = frozenset({"wrong_seq", "broken_prev"})
WRITER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class DocketError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class DocketRollback(DocketError):
    pass


class DocketClient:
    def __init__(
        self,
        socket_path: Path,
        writer: str,
        kid: str,
        private_key: Ed25519PrivateKey,
        *,
        sink_uid: int,
        state_dir: Path,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not WRITER_NAME.fullmatch(writer):
            raise ValueError(f"writer {writer!r} must match {WRITER_NAME.pattern} to name a state file")
        self._socket_path = socket_path
        self._sink_uid = sink_uid
        self._writer = writer
        self._kid = kid
        self._private_key = private_key
        self._timeout = timeout
        self._head: Head | None = None
        self._lock = threading.Lock()
        self._state_dir = state_dir
        self._state_name = f"{writer}.head"
        self._acked = self._load_acked()

    def append(self, entry: Entry) -> Record:
        with self._lock:
            try:
                return self._append(entry)
            except BaseException:
                self._head = None
                raise

    def head(self) -> Head:
        with self._lock:
            return self._fetch_head()

    def _append(self, entry: Entry) -> Record:
        if self._head is None:
            self._head = self._fetch_head()
        record = encode_record(self._private_key, self._kid, self._writer, self._head.seq + 1, self._head.hash, entry)
        try:
            response = self._request(OP_APPEND + record.token.encode("ascii"))
        except DocketError as exc:
            if exc.reason in CHAIN_REFUSALS:
                self._fetch_head()
            raise
        if response.get("seq") != record.seq or response.get("hash") != record.hash:
            raise DocketError("bad_ack", "acknowledgement does not match the record sent")
        self._head = Head(seq=record.seq, hash=record.hash)
        self._acked = self._head
        self._save_acked(self._head)
        return record

    def _fetch_head(self) -> Head:
        head = _head_from(self._request(OP_HEAD + self._writer.encode("utf-8")))
        acked = self._acked
        if acked is None:
            return head
        if head.seq < acked.seq:
            raise DocketRollback("rollback", f"sink head seq {head.seq} is behind acked seq {acked.seq}")
        if head.seq == acked.seq and head.hash != acked.hash:
            raise DocketRollback("rollback", f"sink entry at acked seq {acked.seq} has a different hash")
        return head

    def _load_acked(self) -> Head | None:
        directory_fd = open_private_dir(self._state_dir)
        try:
            fd = os.open(self._state_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        finally:
            os.close(directory_fd)
        with os.fdopen(fd, "rb") as state:
            info = os.fstat(state.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != STATE_MODE
            ):
                raise DocketError(
                    "state_invalid", f"{self._state_name} must be a 0600 file owned by uid {os.geteuid()}"
                )
            return _acked_from(state.read(MAX_STATE_BYTES + 1))

    def _save_acked(self, head: Head) -> None:
        content = canonicalize({"seq": head.seq, "hash": head.hash})
        temporary = f"{self._state_name}.{os.urandom(8).hex()}.tmp"
        directory_fd = open_private_dir(self._state_dir)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(temporary, flags, STATE_MODE, dir_fd=directory_fd)
            with os.fdopen(fd, "wb") as state:
                state.write(content)
                state.flush()
                os.fsync(state.fileno())
            os.rename(temporary, self._state_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError as exc:
            raise DocketError("state_write_failed", str(exc)) from exc
        finally:
            os.close(directory_fd)

    def _request(self, payload: bytes) -> dict[str, Any]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout)
                connection.connect(str(self._socket_path))
                self._check_sink(connection)
                try:
                    connection.sendall(encode_frame(payload))
                except OSError as exc:
                    response = _early_refusal(connection, exc)
                else:
                    response = decode_response(read_frame(connection, MAX_RESPONSE_BYTES))
        except (OSError, ValueError) as exc:
            raise DocketError("no_ack", str(exc)) from exc
        if response["ok"] is not True:
            reason = response.get("reason")
            raise DocketError(reason if isinstance(reason, str) else "refused")
        return response

    def _check_sink(self, connection: socket.socket) -> None:
        try:
            uid = peer_uid(connection)
        except PeerCredentialsUnavailable as exc:
            raise DocketError("sink_not_trusted", str(exc)) from exc
        if uid != self._sink_uid:
            raise DocketError("sink_not_trusted", f"sink peer uid {uid} is not {self._sink_uid}")


def _early_refusal(connection: socket.socket, send_error: OSError) -> dict[str, Any]:
    response = decode_response(read_frame(connection, MAX_RESPONSE_BYTES))
    if response["ok"] is True:
        raise DocketError("no_ack", str(send_error))
    return response


def _acked_from(content: bytes) -> Head:
    try:
        state = strict_decode(content, required=("seq", "hash"), integer_fields=("seq",), max_bytes=MAX_STATE_BYTES)
    except ValueError as exc:
        raise DocketError("state_invalid", str(exc)) from exc
    seq = state["seq"]
    digest = state["hash"]
    if not isinstance(seq, int) or seq < 1 or not isinstance(digest, str) or not digest:
        raise DocketError("state_invalid", "state must hold a positive seq and a non-empty hash")
    return Head(seq=seq, hash=digest)


def _head_from(response: dict[str, Any]) -> Head:
    seq = response.get("seq")
    digest = response.get("hash")
    if not isinstance(seq, int) or seq < 0 or not (digest is None or isinstance(digest, str)):
        raise DocketError("bad_ack", "head response is malformed")
    if (seq == 0) != (digest is None):
        raise DocketError("bad_ack", "head response is inconsistent")
    return Head(seq=seq, hash=digest)
