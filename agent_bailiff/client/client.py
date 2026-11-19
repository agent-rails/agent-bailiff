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
from typing import Any
from urllib.parse import urlsplit

from agent_warrant.ledger import STATES

from agent_bailiff.client.contract import Holder, PreparedCall, TokenBytes, prepare_call
from agent_bailiff.routes import ToolRoutes

PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2025-11-25", "2025-06-18"})
SESSION_HEADER = "mcp-session-id"
PROTOCOL_HEADER = "mcp-protocol-version"
CLIENT_NAME = "agent-bailiff-client"
CLIENT_VERSION = "1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
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

Clock = Callable[[], int]


def system_clock() -> int:
    return int(time.time())


@dataclass(frozen=True)
class Result:
    result: Mapping[str, Any]

    @property
    def is_error(self) -> bool:
        return self.result.get("isError") is True


@dataclass(frozen=True)
class Refused:
    reason: str


@dataclass(frozen=True)
class NeedsApproval:
    reason: str = NEEDS_APPROVAL


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
            message = self._setup_request("tools/list", {})
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
        exchange = self._with_retries(lambda: self._exchange(body, {}, None))
        if exchange.status not in {200, 202}:
            self._protocol = None
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
                message: dict[str, Any] | None = read_event_stream(response, request_id, deadline)
            else:
                message = read_json(response)
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

    def _expire_session(self) -> None:
        self._drop_connection()
        self._session = None
        self._protocol = None
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
    if result.get("isError") is not True:
        return None
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        return None
    if set(content[0]) != {"type", "text"} or content[0]["type"] != "text":
        return None
    text = content[0]["text"]
    return text if text in REFUSAL_REASONS else None


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


def read_event_stream(response: http.client.HTTPResponse, request_id: int, deadline: float) -> dict[str, Any]:
    budget = MAX_RESPONSE_BYTES
    data: list[str] = []
    while True:
        if time.monotonic() > deadline:
            raise _ResponseError("response deadline passed")
        line = response.readline(budget + 1)
        budget -= len(line)
        if budget < 0:
            raise _ResponseError("response too large")
        text = line.decode("utf-8").rstrip("\r\n")
        if not line or text == "":
            message = _event_message(data, request_id)
            if message is not None:
                return message
            if not line:
                raise _ResponseError("the stream ended without a response")
            data = []
            continue
        field, _, value = text.partition(":")
        if field == "data":
            data.append(value.removeprefix(" "))


def _event_message(data: list[str], request_id: int) -> dict[str, Any] | None:
    if not data:
        return None
    try:
        message = json.loads("\n".join(data))
    except ValueError:
        raise _ResponseError("an event carried invalid JSON") from None
    if isinstance(message, dict) and message.get("id") == request_id:
        return message
    return None
