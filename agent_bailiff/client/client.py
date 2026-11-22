from __future__ import annotations

import http.client
import json
import random
import secrets
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

from agent_warrant.ledger import STATES
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.client.contract import Holder, PreparedCall, TokenBytes, prepare_call
from agent_bailiff.routes import ToolRoutes

PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2025-11-25", "2025-06-18"})
SESSION_HEADER = "mcp-session-id"
PROTOCOL_HEADER = "mcp-protocol-version"
CLIENT_NAME = "agent-bailiff-client"
CLIENT_VERSION = "1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
SETUP_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 0.2
BACKOFF_CAP_SECONDS = 2.0
RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
NEEDS_APPROVAL = "needs_approval"
REFUSAL_REASONS = frozenset(
    {
        "malformed_request",
        "unknown_tool",
        "method_refused",
        "chain_invalid",
        "out_of_scope",
        "unbounded_scope",
        "unknown_cost",
        "cost_over_call_cap",
        "no_binding",
        "policy_denied",
        NEEDS_APPROVAL,
        "suspended",
        "docket_unavailable",
        "reservation_refused",
        "ledger_unavailable",
        "internal_error",
        "clearance_missing",
        "release_refused",
    }
    | {f"already_{state}" for state in STATES}
)

RETRY_LATER_REASONS = frozenset({"docket_unavailable", "ledger_unavailable", "internal_error"})
ASK_USER_REASONS = frozenset({NEEDS_APPROVAL, "suspended"})

Clock = Callable[[], int]
Action = Literal["stop", "ask_user", "retry_later"]

EFFECTOR_ERROR_PREFIX = "effector_"
EFFECTOR_ERROR_ACTIONS: Mapping[str, Action] = MappingProxyType(
    {
        "effector_suspended": "ask_user",
        "effector_busy": "retry_later",
        "effector_docket_unavailable": "retry_later",
        "effector_rbac_unverified": "retry_later",
        "effector_restart_unverified": "retry_later",
        "effector_webhook_unverified": "retry_later",
        "effector_kubernetes_429": "retry_later",
    }
)


def system_clock() -> int:
    return int(time.time())


@dataclass(frozen=True)
class Result:
    result: Mapping[str, Any]

    @property
    def is_error(self) -> bool:
        return self.result.get("isError") is True

    @property
    def effector_error(self) -> str | None:
        text = _only_text(self.result)
        return text if text is not None and text.startswith(EFFECTOR_ERROR_PREFIX) else None


def effector_error_action(reason: str) -> Action:
    return EFFECTOR_ERROR_ACTIONS.get(reason, "stop")


def refusal_action(reason: str) -> Action:
    if reason not in REFUSAL_REASONS:
        raise ValueError(f"{reason!r} is not a bailiff refusal reason")
    if reason in RETRY_LATER_REASONS:
        return "retry_later"
    if reason in ASK_USER_REASONS:
        return "ask_user"
    return "stop"


@dataclass(frozen=True)
class Refused:
    reason: str

    @property
    def action(self) -> Action:
        return refusal_action(self.reason)

    @property
    def retryable(self) -> bool:
        return self.action == "retry_later"


@dataclass(frozen=True)
class NeedsApproval:
    reason: str = NEEDS_APPROVAL

    @property
    def action(self) -> Action:
        return refusal_action(self.reason)

    @property
    def retryable(self) -> bool:
        return False


@dataclass(frozen=True)
class OutcomeUnknown:
    detail: str


Outcome = Result | Refused | NeedsApproval | OutcomeUnknown


class GatewayError(Exception):
    pass


class _ResponseError(Exception):
    pass


class _SessionExpired(Exception):
    pass


@dataclass(frozen=True)
class _Exchange:
    status: int
    headers: Mapping[str, str]
    message: dict[str, Any] | None


class BailiffClient:
    def __init__(
        self,
        url: str,
        holder: Holder,
        routes: ToolRoutes,
        *,
        timeout: float = 30.0,
        clock: Clock = system_clock,
        token_bytes: TokenBytes = secrets.token_bytes,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.query or parts.fragment:
            raise ValueError("url must be an http or https URL without a query or fragment")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._parts = parts
        self._path = parts.path or "/"
        self._holder = holder
        self._routes = routes
        self._timeout = timeout
        self._clock = clock
        self._token_bytes = token_bytes
        self._sleep = sleep
        self._jitter = jitter
        self._owner = threading.get_ident()
        self._connection: http.client.HTTPConnection | None = None
        self._protocol: str | None = None
        self._session: str | None = None
        self._expired = False
        self._next_id = 1

    def prepare(
        self, service: str, name: str, arguments: dict[str, Any], traceparent: str | None = None
    ) -> PreparedCall:
        self._check_thread()
        return prepare_call(
            self._holder,
            self._routes,
            service,
            name,
            arguments,
            request_id=self._take_id(),
            now=self._clock(),
            token_bytes=self._token_bytes,
            traceparent=traceparent,
        )

    def delegate(self, child: Ed25519PublicKey, *, scope: dict[str, Any], budget: int, ttl: int) -> tuple[str, ...]:
        self._check_thread()
        return self._holder.delegate(child, scope=scope, budget=budget, ttl=ttl, now=self._clock())

    def send(self, call: PreparedCall) -> Outcome:
        self._check_thread()
        call.consume()
        self._ensure_session()
        try:
            exchange = self._exchange(call.body, call.headers, call.request_id)
        except (OSError, http.client.HTTPException, _ResponseError) as error:
            self._drop_connection()
            return OutcomeUnknown(f"transport: {type(error).__name__}")
        if exchange.status == 404 and self._session is not None:
            self._expire_session()
            return OutcomeUnknown("session_expired")
        return classify(exchange)

    def call(self, service: str, name: str, arguments: dict[str, Any], traceparent: str | None = None) -> Outcome:
        return self.send(self.prepare(service, name, arguments, traceparent))

    def list_tools(self) -> list[dict[str, Any]]:
        self._check_thread()
        self._ensure_session()
        try:
            message = self._setup_request("tools/list", {})
        except _SessionExpired:
            self._ensure_session()
            try:
                message = self._setup_request("tools/list", {})
            except _SessionExpired:
                raise GatewayError("tools/list returned HTTP 404 after the session was initialized again") from None
        tools = message.get("result", {}).get("tools")
        if not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
            raise GatewayError("tools/list returned no tool list")
        return tools

    @property
    def protocol_version(self) -> str | None:
        return self._protocol

    @property
    def session_id(self) -> str | None:
        return self._session

    def close(self) -> None:
        self._drop_connection()

    def _ensure_session(self) -> None:
        if self._protocol is not None:
            return
        if self._expired:
            self._sleep(self._jitter() * BACKOFF_BASE_SECONDS)
            self._expired = False
        message = self._setup_request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        )
        version = message.get("result", {}).get("protocolVersion")
        if version not in SUPPORTED_PROTOCOL_VERSIONS:
            self._session = None
            raise GatewayError(f"the gateway negotiated an unsupported MCP protocol version: {str(version)[:32]!r}")
        self._protocol = version
        body = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        try:
            exchange = self._with_retries(lambda: self._exchange(body, {}, None))
        except GatewayError:
            self._reset_session()
            raise
        if exchange.status not in {200, 202}:
            self._reset_session()
            raise GatewayError(f"notifications/initialized returned HTTP {exchange.status}")

    def _setup_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._take_id()
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
        exchange = self._with_retries(lambda: self._exchange(body, {}, request_id))
        if exchange.status == 404 and self._session is not None and method != "initialize":
            self._expire_session()
            raise _SessionExpired
        if exchange.status != 200 or exchange.message is None:
            raise GatewayError(f"{method} returned HTTP {exchange.status}")
        if not isinstance(exchange.message.get("result"), dict):
            raise GatewayError(f"{method} returned no result")
        if method == "initialize":
            self._session = exchange.headers.get(SESSION_HEADER)
        return exchange.message

    def _with_retries(self, attempt: Callable[[], _Exchange]) -> _Exchange:
        for number in range(SETUP_ATTEMPTS):
            try:
                exchange = attempt()
            except (OSError, http.client.HTTPException, _ResponseError) as error:
                self._drop_connection()
                if number == SETUP_ATTEMPTS - 1:
                    raise GatewayError(f"the gateway did not answer after {SETUP_ATTEMPTS} attempts") from error
            else:
                if exchange.status not in RETRYABLE_STATUSES or number == SETUP_ATTEMPTS - 1:
                    return exchange
                self._drop_connection()
            self._sleep(self._jitter() * min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * 2**number))
        raise AssertionError("unreachable")

    def _exchange(self, body: bytes, extra: Mapping[str, str], request_id: int | None) -> _Exchange:
        headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            **extra,
        }
        if self._protocol is not None:
            headers[PROTOCOL_HEADER] = self._protocol
        if self._session is not None:
            headers[SESSION_HEADER] = self._session
        connection = self._connect()
        connection.request("POST", self._path, body, headers)
        response = connection.getresponse()
        deadline = time.monotonic() + self._timeout
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        streaming = response_headers.get("content-type", "").startswith("text/event-stream")
        try:
            if streaming and request_id is not None:
                message: dict[str, Any] | None = read_event_stream(response, request_id, deadline, self._set_timeout)
            else:
                message = read_json(response)
                if message is not None and request_id is not None and message.get("id") != request_id:
                    raise _ResponseError("the response id does not match the request id")
        finally:
            if streaming or response.will_close:
                self._drop_connection()
        return _Exchange(response.status, response_headers, message)

    def _connect(self) -> http.client.HTTPConnection:
        if self._connection is None:
            host = self._parts.hostname or ""
            if self._parts.scheme == "https":
                self._connection = http.client.HTTPSConnection(
                    host, self._parts.port, timeout=self._timeout, context=ssl.create_default_context()
                )
            else:
                self._connection = http.client.HTTPConnection(host, self._parts.port, timeout=self._timeout)
        return self._connection

    def _drop_connection(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _set_timeout(self, seconds: float) -> None:
        if self._connection is not None and self._connection.sock is not None:
            self._connection.sock.settimeout(seconds)

    def _reset_session(self) -> None:
        self._drop_connection()
        self._session = None
        self._protocol = None

    def _expire_session(self) -> None:
        self._reset_session()
        self._expired = True

    def _take_id(self) -> int:
        request_id = self._next_id
        self._next_id += 1
        return request_id

    def _check_thread(self) -> None:
        if threading.get_ident() != self._owner:
            raise RuntimeError("a BailiffClient is used by the thread that created it; create one per thread")


def classify(exchange: _Exchange) -> Outcome:
    if exchange.status != 200 or exchange.message is None:
        return OutcomeUnknown(f"http_{exchange.status}")
    result = exchange.message.get("result")
    if not isinstance(result, dict):
        error = exchange.message.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        return OutcomeUnknown(f"jsonrpc_error_{code}" if isinstance(code, int) else "no_result")
    reason = refusal_reason(result)
    if reason == NEEDS_APPROVAL:
        return NeedsApproval()
    if reason is not None:
        return Refused(reason)
    return Result(result)


def refusal_reason(result: Mapping[str, Any]) -> str | None:
    text = _only_text(result)
    return text if text in REFUSAL_REASONS else None


def _only_text(result: Mapping[str, Any]) -> str | None:
    if result.get("isError") is not True:
        return None
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        return None
    if set(content[0]) != {"type", "text"} or content[0]["type"] != "text":
        return None
    text = content[0]["text"]
    return text if isinstance(text, str) else None


def read_json(response: http.client.HTTPResponse) -> dict[str, Any] | None:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise _ResponseError("response too large")
    if not raw.strip():
        return None
    try:
        message = json.loads(raw)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


def read_event_stream(
    response: http.client.HTTPResponse, request_id: int, deadline: float, set_timeout: Callable[[float], None]
) -> dict[str, Any]:
    received = 0
    pending = b""
    data: list[str] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ResponseError("response deadline passed")
        set_timeout(remaining)
        chunk = response.read1(STREAM_CHUNK_BYTES)
        received += len(chunk)
        if received > MAX_RESPONSE_BYTES:
            raise _ResponseError("response too large")
        lines = (pending + chunk).split(b"\n")
        pending = lines.pop() if chunk else b""
        if not chunk:
            lines.append(b"")
        for line in lines:
            message = _event_line(line, data, request_id)
            if message is not None:
                return message
        if not chunk:
            raise _ResponseError("the stream ended without a response")


def _event_line(line: bytes, data: list[str], request_id: int) -> dict[str, Any] | None:
    try:
        text = line.decode("utf-8").rstrip("\r")
    except UnicodeDecodeError:
        raise _ResponseError("an event was not UTF-8") from None
    if text:
        field, _, value = text.partition(":")
        if field == "data":
            data.append(value.removeprefix(" "))
        return None
    message = _event_message(data, request_id)
    data.clear()
    return message


def _event_message(data: list[str], request_id: int) -> dict[str, Any] | None:
    if not "".join(data):
        return None
    try:
        message = json.loads("\n".join(data))
    except ValueError:
        raise _ResponseError("an event carried invalid JSON") from None
    if isinstance(message, dict) and message.get("id") == request_id:
        return message
    return None
