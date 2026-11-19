from __future__ import annotations

import json
import logging
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, cast
from urllib.parse import urlsplit

from agent_bailiff.webhook.admission import MAX_BODY_BYTES, Admission, MalformedReview

logger = logging.getLogger(__name__)

CONNECTION_DEADLINE_SECONDS = 5.0


def _cut(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class WebhookServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(
        self,
        admission: Admission,
        host: str,
        port: int,
        cert: Path,
        key: Path,
        *,
        max_concurrency: int = 32,
        connection_deadline: float = CONNECTION_DEADLINE_SECONDS,
    ) -> None:
        if max_concurrency < 1 or max_concurrency > 256:
            raise ValueError("max_concurrency must be 1..256")
        if not 0 < connection_deadline <= 30:
            raise ValueError("connection_deadline must be in (0, 30] seconds")
        self.admission = admission
        self._deadline = connection_deadline
        self._slots = threading.BoundedSemaphore(max_concurrency)
        # TLS handshakes are network-facing work, separate from AdmissionReview
        # evaluation. A stalled handshake must not consume every review slot.
        self._handshakes = threading.BoundedSemaphore(max(2, max_concurrency // 4))
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.load_cert_chain(str(cert), str(key))
        super().__init__((host, port), _Handler)

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
    ) -> None:
        if not self._handshakes.acquire(blocking=False):
            cast(socket.socket, request).close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._handshakes.release()
            raise

    def process_request_thread(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
    ) -> None:
        handshake_acquired = True
        slot_acquired = False
        raw = cast(socket.socket, request)
        current: list[socket.socket] = [raw]
        guard = threading.Lock()
        done = [False]

        def expire() -> None:
            with guard:
                if not done[0]:
                    _cut(current[0])

        def finish() -> None:
            with guard:
                done[0] = True

        deadline = threading.Timer(self._deadline, expire)
        deadline.daemon = True
        deadline.start()
        try:
            raw.settimeout(3)
            secure = self._context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            with guard:
                current[0] = secure
            secure.do_handshake()
            self._handshakes.release()
            handshake_acquired = False
            if not self._slots.acquire(blocking=False):
                finish()
                secure.close()
                return
            slot_acquired = True
            with secure:
                try:
                    super().process_request_thread(secure, client_address)
                finally:
                    finish()
        except (OSError, ssl.SSLError):
            pass
        finally:
            finish()
            deadline.cancel()
            if slot_acquired:
                self._slots.release()
            if handshake_acquired:
                self._handshakes.release()


class _Handler(BaseHTTPRequestHandler):
    server: WebhookServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        logger.info('{"event":"bailiff_webhook_health_check"}')
        path = urlsplit(self.path).path
        if path == "/readyz/audit":
            ready = not self.server.admission.enforce
        elif path == "/readyz/enforce":
            ready = self.server.admission.enforce
        else:
            self._reply(404, {})
            return
        self._reply(200 if ready else 503, {"ready": ready})

    def do_POST(self) -> None:
        logger.info('{"event":"bailiff_webhook_request"}')
        if urlsplit(self.path).path != "/validate":
            self._reply(404, {})
            return
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1 or not lengths[0].isdigit() or self.headers.get("Transfer-Encoding") is not None:
            self._reply(400, {})
            return
        length = int(lengths[0])
        if length > MAX_BODY_BYTES:
            self._reply(413, {})
            return
        try:
            result = self.server.admission.review(self.rfile.read(length), int(time.time()))
        except (MalformedReview, TimeoutError):
            logger.warning(
                '{"event":"bailiff_admission_invalid_request",'
                '"action":"check webhook request size and API server compatibility"}'
            )
            self._reply(400, {})
            return
        except Exception:
            # Exception text may contain untrusted request values. Keep the
            # operator signal useful without echoing AdmissionReview contents.
            logger.error(
                '{"event":"bailiff_admission_internal_error",'
                '"action":"check webhook health and configuration; keep failurePolicy Fail"}'
            )
            self._reply(500, {})
            return
        self._reply(200, result)

    def _reply(self, status: int, document: dict[str, Any]) -> None:
        data = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True
