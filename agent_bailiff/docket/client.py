from __future__ import annotations

import socket
import threading
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.docket.entry import Entry, Record, encode_record
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


class DocketError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class DocketClient:
    def __init__(
        self,
        socket_path: Path,
        writer: str,
        kid: str,
        private_key: Ed25519PrivateKey,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._socket_path = socket_path
        self._writer = writer
        self._kid = kid
        self._private_key = private_key
        self._timeout = timeout
        self._head: Head | None = None
        self._lock = threading.Lock()

    def append(self, entry: Entry) -> Record:
        with self._lock:
            try:
                return self._append(entry)
            except BaseException:
                self._head = None
                raise

    def head(self) -> Head:
        with self._lock:
            response = self._request(OP_HEAD + self._writer.encode("utf-8"))
            return _head_from(response)

    def _append(self, entry: Entry) -> Record:
        if self._head is None:
            self._head = _head_from(self._request(OP_HEAD + self._writer.encode("utf-8")))
        record = encode_record(self._private_key, self._kid, self._writer, self._head.seq + 1, self._head.hash, entry)
        response = self._request(OP_APPEND + record.token.encode("ascii"))
        if response.get("seq") != record.seq or response.get("hash") != record.hash:
            raise DocketError("bad_ack", "acknowledgement does not match the record sent")
        self._head = Head(seq=record.seq, hash=record.hash)
        return record

    def _request(self, payload: bytes) -> dict[str, Any]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout)
                connection.connect(str(self._socket_path))
                connection.sendall(encode_frame(payload))
                response = decode_response(read_frame(connection, MAX_RESPONSE_BYTES))
        except (OSError, ValueError) as exc:
            raise DocketError("no_ack", str(exc)) from exc
        if response["ok"] is not True:
            reason = response.get("reason")
            raise DocketError(reason if isinstance(reason, str) else "refused")
        return response


def _head_from(response: dict[str, Any]) -> Head:
    seq = response.get("seq")
    digest = response.get("hash")
    if not isinstance(seq, int) or seq < 0 or not (digest is None or isinstance(digest, str)):
        raise DocketError("bad_ack", "head response is malformed")
    if (seq == 0) != (digest is None):
        raise DocketError("bad_ack", "head response is inconsistent")
    return Head(seq=seq, hash=digest)
