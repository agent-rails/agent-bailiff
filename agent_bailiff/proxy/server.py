"""The agent's stdio MCP server: lists the routed upstream tools and sends each call through the gateway, signed
with the key the current task root is bound to. The task file is re-read on every call."""

from __future__ import annotations

import json
import logging
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

from agent_bailiff.client import BailiffClient, GatewayError, Holder, OutcomeUnknown
from agent_bailiff.client.client import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, Clock, system_clock
from agent_bailiff.proxy.agent_key import AgentKeyError, prune
from agent_bailiff.proxy.guidance import GATEWAY_UNAVAILABLE, NO_TASK, OUTCOME_UNKNOWN, TASK_EXPIRED, mcp_result, text
from agent_bailiff.proxy.task_state import NoTask, TaskState, TaskUnavailable, read_task_bytes
from agent_bailiff.routes import ToolRoutes
from agent_bailiff.strict_json import parse_strict_json

MAX_LINE_BYTES = 1 << 20
MAX_ROUTES_BYTES = 1 << 20
MAX_DESCRIPTION_BYTES = 4096
MAX_SCHEMA_BYTES = 16384
MAX_SCHEMA_DEPTH = 32
LISTED_FIELDS = ("name", "title", "description", "inputSchema")
SERVER_INFO = {"name": "agent-bailiff-proxy", "version": "1"}
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
SERVER_ERROR = -32000

logger = logging.getLogger(__name__)

ClientFactory = Callable[[str, Holder, ToolRoutes], BailiffClient]


class Stop(Exception):
    pass


class RequestError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class StdioProxy:
    def __init__(
        self,
        task_file: Path,
        key_dir: Path,
        gateway_url: str,
        routes: ToolRoutes,
        *,
        clock: Clock = system_clock,
        client_factory: ClientFactory = BailiffClient,
    ) -> None:
        self._task_file = task_file
        self._key_dir = key_dir
        self._gateway_url = gateway_url
        self._routes = routes
        self._services = route_services(routes)
        self._clock = clock
        self._client_factory = client_factory
        self._state: TaskState | None = None
        self._client: BailiffClient | None = None
        self._tools: list[dict[str, Any]] | None = None
        self.busy = False
        self.stop_requested = False

    def run(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        try:
            self._serve(stdin, stdout)
        except Stop:
            pass
        finally:
            self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def handle(self, message: object) -> dict[str, Any] | None:
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            return error_reply(None, INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        if "id" not in message:
            return None
        request_id = message["id"]
        if isinstance(request_id, bool) or not isinstance(request_id, str | int):
            return error_reply(None, INVALID_REQUEST, "the id must be a string or an integer")
        params = message.get("params", {})
        if not isinstance(params, dict):
            return error_reply(request_id, INVALID_PARAMS, "params must be an object")
        try:
            result = self._dispatch(message["method"], params)
        except RequestError as exc:
            return error_reply(request_id, exc.code, exc.message)
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _serve(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        while not self.stop_requested:
            line = stdin.readline(MAX_LINE_BYTES + 1)
            if not line:
                return
            self.busy = True
            try:
                reply = self._reply_to(line, stdin)
                if reply is not None:
                    stdout.write(json.dumps(reply, separators=(",", ":")).encode() + b"\n")
                    stdout.flush()
            finally:
                self.busy = False

    def _reply_to(self, line: bytes, stdin: BinaryIO) -> dict[str, Any] | None:
        if len(line) > MAX_LINE_BYTES:
            drain_line(line, stdin)
            return error_reply(None, INVALID_REQUEST, f"the message is larger than {MAX_LINE_BYTES} bytes")
        if not line.strip():
            return None
        try:
            message = parse_strict_json(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return error_reply(None, PARSE_ERROR, "the message is not strict UTF-8 JSON")
        return self.handle(message)

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return initialize_result(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self._list_tools()}
        if method == "tools/call":
            return self._call(params)
        raise RequestError(METHOD_NOT_FOUND, f"method {method[:64]!r} is not supported")

    def _list_tools(self) -> list[dict[str, Any]]:
        if self._tools is not None:
            return self._tools
        try:
            _, client = self._current()
            upstream = client.list_tools()
        except NoTask:
            raise RequestError(SERVER_ERROR, "no task issued; ask the user to issue one") from None
        except TaskUnavailable as exc:
            raise RequestError(SERVER_ERROR, exc.reason) from None
        except GatewayError as exc:
            raise RequestError(SERVER_ERROR, f"the gateway did not list tools: {exc}") from None
        self._tools = routed_tools(upstream, frozenset(self._services))
        return self._tools

    def _call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise RequestError(INVALID_PARAMS, "tools/call needs a string name and object arguments")
        service = self._services.get(name)
        if service is None:
            raise RequestError(INVALID_PARAMS, f"unknown tool {name[:64]!r}")
        try:
            state, client = self._current()
        except NoTask:
            return text(NO_TASK, error=True)
        except TaskUnavailable as exc:
            return text(exc.reason, error=True)
        if state.expired(self._clock()):
            return text(TASK_EXPIRED, error=True)
        try:
            call = client.prepare(service, name, arguments)
        except ValueError as exc:
            return text(str(exc), error=True)
        try:
            outcome = client.send(call)
        except GatewayError:
            return text(GATEWAY_UNAVAILABLE, error=True)
        if isinstance(outcome, OutcomeUnknown):
            return text(f"outcome_unknown: {outcome.detail}; {OUTCOME_UNKNOWN}", error=True)
        return mcp_result(outcome)

    def _current(self) -> tuple[TaskState, BailiffClient]:
        raw = read_task_bytes(self._task_file)
        if self._client is not None and self._state is not None and raw == self._state.raw:
            return self._state, self._client
        state = TaskState.from_bytes(raw, self._key_dir)
        self.close()
        client = self._client_factory(self._gateway_url, state.holder, self._routes)
        self._state, self._client = state, client
        logger.info("loaded task %s", state.task.root.task_id)
        self._prune(state.subject)
        return state, client

    def _prune(self, subject: str) -> None:
        try:
            removed = prune(self._key_dir, subject)
        except AgentKeyError as exc:
            logger.warning("could not prune old agent keys: %s", exc)
            return
        if removed:
            logger.info("pruned %d old agent key(s)", len(removed))


def route_services(routes: ToolRoutes) -> dict[str, str]:
    services: dict[str, str] = {}
    for route in routes:
        if route.name in services:
            raise ValueError(f"tool {route.name!r} is routed on more than one service; the proxy needs unique names")
        services[route.name] = route.service
    return services


def routed_tools(upstream: list[dict[str, Any]], names: frozenset[str]) -> list[dict[str, Any]]:
    tools = []
    for tool in upstream:
        name = tool.get("name")
        if not isinstance(name, str) or name not in names:
            continue
        problem = tool_problem(tool)
        if problem:
            logger.warning("dropped tool %r from tools/list: %s", name, problem)
            continue
        tools.append({field: tool[field] for field in LISTED_FIELDS if field in tool})
    return tools


def tool_problem(tool: dict[str, Any]) -> str | None:
    for field in ("title", "description"):
        value = tool.get(field, "")
        if not isinstance(value, str) or len(value.encode()) > MAX_DESCRIPTION_BYTES:
            return f"the {field} is not a string of at most {MAX_DESCRIPTION_BYTES} bytes"
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return "the inputSchema is not an object"
    if len(json.dumps(schema).encode()) > MAX_SCHEMA_BYTES:
        return f"the inputSchema is larger than {MAX_SCHEMA_BYTES} bytes"
    if depth(schema) > MAX_SCHEMA_DEPTH:
        return f"the inputSchema nests deeper than {MAX_SCHEMA_DEPTH}"
    return None


def depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((depth(item) for item in value), default=0)
    return 0


def initialize_result(params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
    return {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}


def error_reply(request_id: str | int | None, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def drain_line(line: bytes, stdin: BinaryIO) -> None:
    while line and not line.endswith(b"\n"):
        line = stdin.readline(MAX_LINE_BYTES)


def read_routes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"the route table {path} is not a regular file")
        raw = os.read(fd, MAX_ROUTES_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_ROUTES_BYTES:
        raise ValueError(f"the route table is larger than {MAX_ROUTES_BYTES} bytes")
    return raw


def load_routes(raw: bytes) -> ToolRoutes:
    try:
        return ToolRoutes.from_document(parse_strict_json(raw.decode("utf-8")))
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ValueError(f"the route table is invalid: {exc}") from None
