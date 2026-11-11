from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, fields
from typing import Any

from agent_warrant.scope import validate_entry

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.decide.identity import MAX_ARGS_BYTES
from agent_bailiff.decide.request import OperationRequest

TOOLS_CALL = "tools/call"
TASK_ROOT_HEADER = "x-bailiff-task-root"
LINKS_HEADER = "x-bailiff-links"
LEAF_PROOF_HEADER = "x-bailiff-leaf-proof"
NONCE_HEADER = "x-bailiff-nonce"
TRACEPARENT_HEADER = "traceparent"
REQUIRED_HEADERS = frozenset({TASK_ROOT_HEADER, LEAF_PROOF_HEADER, NONCE_HEADER})
CALL_HEADERS = REQUIRED_HEADERS | {LINKS_HEADER, TRACEPARENT_HEADER}
MAX_PARAMS_BYTES = 2 * MAX_ARGS_BYTES
TRACEPARENT = re.compile(r"00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}")


class CallRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ToolRoute:
    service: str
    name: str
    tool: str
    resource: str

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
                raise ValueError(f"{item.name} must be a non-empty ASCII printable str without whitespace")
        for name in ("tool", "resource"):
            problem = validate_entry(getattr(self, name))
            if problem or "*" in getattr(self, name):
                raise ValueError(f"{name} must be a concrete scope id: {problem or 'no wildcards'}")


ROUTE_FIELDS = frozenset(item.name for item in fields(ToolRoute))


class ToolRoutes:
    def __init__(self, routes: Iterable[ToolRoute]) -> None:
        table: dict[tuple[str, str], ToolRoute] = {}
        for route in routes:
            if not isinstance(route, ToolRoute):
                raise TypeError("routes must be ToolRoute records")
            key = (route.service, route.name)
            if key in table:
                raise ValueError(f"duplicate route for tool {route.name!r} on service {route.service!r}")
            table[key] = route
        self._table = table

    @classmethod
    def from_document(cls, document: object) -> ToolRoutes:
        if not isinstance(document, dict) or set(document) != {"routes"} or not isinstance(document["routes"], list):
            raise ValueError('a route document must be an object with only a "routes" list')
        routes = []
        for item in document["routes"]:
            if not isinstance(item, dict) or set(item) != ROUTE_FIELDS:
                raise ValueError(f"each route must have exactly the fields {', '.join(sorted(ROUTE_FIELDS))}")
            routes.append(ToolRoute(**item))
        return cls(routes)

    @property
    def services(self) -> frozenset[str]:
        return frozenset(service for service, _ in self._table)

    def route(self, service: str, name: str) -> ToolRoute | None:
        return self._table.get((service, name))


def read_call(message: ext_mcp_pb2.McpRequest, routes: ToolRoutes) -> OperationRequest:
    if len(message.service_names) != 1:
        raise CallRefused("malformed_request")
    name, arguments = _params(message)
    route = routes.route(message.service_names[0], name)
    if route is None:
        raise CallRefused("unknown_tool")
    headers = _call_headers(message)
    links = headers.get(LINKS_HEADER)
    link_tokens = tuple(links.split(",")) if links is not None else ()
    if not all(link_tokens):
        raise CallRefused("malformed_request")
    trace = TRACEPARENT.fullmatch(headers.get(TRACEPARENT_HEADER, ""))
    return OperationRequest(
        tool=route.tool,
        resource=route.resource,
        args=arguments,
        nonce=headers[NONCE_HEADER],
        task_root=headers[TASK_ROOT_HEADER],
        links=link_tokens,
        leaf_proof=headers[LEAF_PROOF_HEADER],
        trace_id=trace.group(1) if trace else "",
    )


def _params(message: ext_mcp_pb2.McpRequest) -> tuple[str, dict[str, Any]]:
    if not message.HasField("mcp_request") or len(message.mcp_request) > MAX_PARAMS_BYTES:
        raise CallRefused("malformed_request")
    try:
        params = parse_strict_json(message.mcp_request)
    except (ValueError, UnicodeDecodeError):
        raise CallRefused("malformed_request") from None
    if not isinstance(params, dict):
        raise CallRefused("malformed_request")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not name or not isinstance(arguments, dict):
        raise CallRefused("malformed_request")
    return name, arguments


def _call_headers(message: ext_mcp_pb2.McpRequest) -> dict[str, str]:
    values: dict[str, list[bytes]] = {}
    for header in message.headers:
        name = header.key.lower()
        if name in CALL_HEADERS:
            values.setdefault(name, []).append(header.value)
    headers = {}
    for name, items in values.items():
        if len(items) != 1:
            raise CallRefused("malformed_request")
        try:
            text = items[0].decode("ascii")
        except UnicodeDecodeError:
            raise CallRefused("malformed_request") from None
        if not text or not all("!" <= character <= "~" for character in text):
            raise CallRefused("malformed_request")
        headers[name] = text
    if not REQUIRED_HEADERS <= headers.keys():
        raise CallRefused("malformed_request")
    return headers


def parse_strict_json(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_keys, parse_constant=_no_constant)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")
