from __future__ import annotations

import logging
import os
import socket
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Protocol

import grpc

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.docket.peer import PeerCredentialsUnavailable, peer_uid
from agent_bailiff.docket.socket_dir import (
    SOCKET_MODE,
    open_lock_file,
    prepare_socket_dir,
    remove_stale_socket,
    try_lock,
    unlink_if_same,
)

SERVICE = "agentgateway.dev.ext_mcp.ExtMcp"
GRPC_SOCKET_NAME = "grpc.sock"
PRIVATE_DIR_FORBIDDEN_BITS = 0o077
DEFAULT_WORKERS = 8
DEFAULT_MAX_CONNECTIONS = 64
ACCEPT_POLL_SECONDS = 0.2
CHUNK_BYTES = 65536

logger = logging.getLogger(__name__)


class ExtMcpProcessor(Protocol):
    def check_request(self, message: ext_mcp_pb2.McpRequest) -> ext_mcp_pb2.McpRequestResult: ...


class ProcessorLocked(Exception):
    pass


class ProcessorServer:
    def __init__(
        self,
        processor: ExtMcpProcessor,
        socket_path: Path,
        private_dir: Path,
        *,
        gateway_uid: int,
        socket_gid: int | None = None,
        workers: int = DEFAULT_WORKERS,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
    ) -> None:
        if isinstance(gateway_uid, bool) or not isinstance(gateway_uid, int) or gateway_uid < 0:
            raise ValueError("gateway_uid must be a non-negative integer")
        self._processor = processor
        self._socket_path = socket_path
        self._grpc_path = private_dir / GRPC_SOCKET_NAME
        self._private_dir = private_dir
        self._gateway_uid = gateway_uid
        self._socket_gid = os.getegid() if socket_gid is None else socket_gid
        self._workers = workers
        self._max_connections = max_connections
        self._grpc: Any = None
        self._listener: socket.socket | None = None
        self._lock_fd: int | None = None
        self._identity: tuple[int, int] | None = None
        self._accepting: threading.Thread | None = None
        self._stopping = threading.Event()
        self._relays: set[tuple[socket.socket, socket.socket]] = set()
        self._relays_lock = threading.Lock()

    def start(self) -> None:
        try:
            self._start()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self._stopping.set()
        if self._accepting is not None:
            self._accepting.join()
            self._accepting = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._identity is not None:
            unlink_if_same(self._socket_path, self._identity)
            self._identity = None
        with self._relays_lock:
            relays = list(self._relays)
        for pair in relays:
            for connection in pair:
                _shutdown(connection)
        if self._grpc is not None:
            self._grpc.stop(None).wait()
            self._grpc = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def _start(self) -> None:
        _check_private_dir(self._private_dir)
        prepare_socket_dir(self._socket_path.parent, self._socket_gid)
        lock_path = self._socket_path.with_name(f"{self._socket_path.name}.lock")
        self._lock_fd = open_lock_file(lock_path)
        if not try_lock(self._lock_fd):
            raise ProcessorLocked(f"{lock_path} is held by another processor")
        remove_stale_socket(self._grpc_path)
        self._grpc = _grpc_server(self._processor, self._grpc_path, self._workers)
        remove_stale_socket(self._socket_path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener = listener
        listener.bind(str(self._socket_path))
        info = os.lstat(self._socket_path)
        self._identity = (info.st_dev, info.st_ino)
        os.chown(self._socket_path, -1, self._socket_gid)
        os.chmod(self._socket_path, SOCKET_MODE)
        listener.listen(self._max_connections)
        listener.settimeout(ACCEPT_POLL_SECONDS)
        self._accepting = threading.Thread(target=self._accept_loop, name="ext-mcp-accept", daemon=True)
        self._accepting.start()

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stopping.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stopping.is_set():
                    logger.exception("processor socket stopped accepting connections")
                return
            connection.settimeout(None)
            self._admit(connection)

    def _admit(self, connection: socket.socket) -> None:
        try:
            uid = peer_uid(connection)
        except (OSError, PeerCredentialsUnavailable):
            logger.warning("refused a processor connection whose peer uid could not be read")
            connection.close()
            return
        if uid != self._gateway_uid:
            logger.warning("refused a processor connection from uid %d; only the gateway uid may connect", uid)
            connection.close()
            return
        with self._relays_lock:
            full = len(self._relays) >= self._max_connections
        if full:
            logger.warning("refused a processor connection over the %d connection limit", self._max_connections)
            connection.close()
            return
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(str(self._grpc_path))
        except OSError:
            logger.exception("processor gRPC socket is unreachable")
            upstream.close()
            connection.close()
            return
        self._relay(connection, upstream)

    def _relay(self, downstream: socket.socket, upstream: socket.socket) -> None:
        pair = (downstream, upstream)
        with self._relays_lock:
            self._relays.add(pair)
        remaining = [2]
        remaining_lock = threading.Lock()

        def pump(source: socket.socket, target: socket.socket) -> None:
            try:
                while chunk := source.recv(CHUNK_BYTES):
                    target.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                with remaining_lock:
                    remaining[0] -= 1
                    done = remaining[0] == 0
                if done:
                    self._forget(pair)

        for source, target in ((downstream, upstream), (upstream, downstream)):
            threading.Thread(target=pump, args=(source, target), name="ext-mcp-relay", daemon=True).start()

    def _forget(self, pair: tuple[socket.socket, socket.socket]) -> None:
        with self._relays_lock:
            self._relays.discard(pair)
        for connection in pair:
            connection.close()


def _grpc_server(processor: ExtMcpProcessor, path: Path, workers: int) -> Any:
    server = grpc.server(ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ext-mcp"))
    handler = grpc.method_handlers_generic_handler(
        SERVICE,
        {
            "CheckRequest": grpc.unary_unary_rpc_method_handler(
                lambda message, _context: processor.check_request(message),
                request_deserializer=ext_mcp_pb2.McpRequest.FromString,
                response_serializer=ext_mcp_pb2.McpRequestResult.SerializeToString,
            )
        },
    )
    server.add_generic_rpc_handlers((handler,))
    server.add_insecure_port(f"unix:{path}")
    server.start()
    return server


def _check_private_dir(directory: Path) -> None:
    info = os.lstat(directory)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & PRIVATE_DIR_FORBIDDEN_BITS
    ):
        raise PermissionError(f"{directory} must be a directory owned by uid {os.geteuid()} with mode 0700")


def _shutdown(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
