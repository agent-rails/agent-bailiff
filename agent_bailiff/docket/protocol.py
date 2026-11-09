from __future__ import annotations

import socket
import struct
from typing import Any

from agent_warrant.canonical import canonicalize, strict_decode

from agent_bailiff.signing import MAX_TOKEN_CHARS

OP_APPEND = b"A"
OP_HEAD = b"H"
MAX_FRAME_BYTES = 1 + MAX_TOKEN_CHARS
MAX_RESPONSE_BYTES = 4096
LENGTH = struct.Struct(">I")


def encode_frame(payload: bytes) -> bytes:
    return LENGTH.pack(len(payload)) + payload


def encode_response(response: dict[str, Any]) -> bytes:
    return encode_frame(canonicalize(response))


def decode_response(payload: bytes) -> dict[str, Any]:
    return strict_decode(
        payload,
        required=("ok",),
        optional=("seq", "hash", "reason"),
        integer_fields=("seq",),
        max_bytes=MAX_RESPONSE_BYTES,
    )


def read_frame(sock: socket.socket, max_bytes: int) -> bytes:
    (length,) = LENGTH.unpack(_read_exact(sock, LENGTH.size))
    if length > max_bytes:
        raise ValueError(f"frame of {length} bytes exceeds the {max_bytes} byte limit")
    return _read_exact(sock, length)


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("connection closed before a complete frame")
        chunks.extend(chunk)
    return bytes(chunks)
