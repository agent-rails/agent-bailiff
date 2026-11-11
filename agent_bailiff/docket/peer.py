from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import struct
import sys
from typing import Protocol


class PeerSocket(Protocol):
    def fileno(self) -> int: ...

    def getsockopt(self, level: int, optname: int, buflen: int, /) -> bytes: ...


class PeerCredentialsUnavailable(Exception):
    pass


def peer_uid(sock: PeerSocket) -> int:
    if sys.platform == "linux":
        size = struct.calcsize("iII")
        _, uid, _ = struct.unpack("iII", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
        return int(uid)
    if sys.platform == "darwin":
        return _darwin_peer_uid(sock.fileno())
    raise PeerCredentialsUnavailable(f"peer credentials are not supported on {sys.platform}")


def _darwin_peer_uid(fd: int) -> int:
    library = ctypes.util.find_library("c")
    if library is None:
        raise PeerCredentialsUnavailable("libc not found")
    libc = ctypes.CDLL(library, use_errno=True)
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    if libc.getpeereid(fd, ctypes.byref(uid), ctypes.byref(gid)) != 0:
        error = ctypes.get_errno()
        raise PeerCredentialsUnavailable(f"getpeereid failed: {os.strerror(error)}")
    return uid.value
