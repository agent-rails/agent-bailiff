from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agent_warrant.scope import validate_entry

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.decide.identity import MAX_ARGS_BYTES
from agent_bailiff.decide.request import OperationRequest
from agent_bailiff.effector.catalog import Argument, OperationCatalog
from agent_bailiff.strict_json import parse_strict_json

TOOLS_CALL = "tools/call"
TASK_ROOT_HEADER = "x-bailiff-task-root"
LINKS_HEADER = "x-bailiff-links"
LEAF_PROOF_HEADER = "x-bailiff-leaf-proof"
NONCE_HEADER = "x-bailiff-nonce"
TRACEPARENT_HEADER = "traceparent"
REQUIRED_HEADERS = frozenset({TASK_ROOT_HEADER, LEAF_PROOF_HEADER, NONCE_HEADER})
CALL_HEADERS = REQUIRED_HEADERS | {LINKS_HEADER, TRACEPARENT_HEADER}
MAX_PARAMS_BYTES = 2 * MAX_ARGS_BYTES
CALL_PARAMS = frozenset({"name", "arguments", "_meta"})
META_TYPES: dict[str, tuple[type, ...]] = {
    "progressToken": (str, int),
    "io.modelcontextprotocol/protocolVersion": (str,),
    "io.modelcontextprotocol/clientInfo": (dict,),
    "io.modelcontextprotocol/clientCapabilities": (dict,),
}
PLACEHOLDER = re.compile(r"\{([a-z][A-Za-z0-9]{0,31})\}")
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
    schema: tuple[Argument, ...] | None = None

    def __post_init__(self) -> None:
        for name in ("service", "name", "tool", "resource"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
                raise ValueError(f"{name} must be a non-empty ASCII printable str without whitespace")
        problem = validate_entry(self.tool)
        if problem or "*" in self.tool:
            raise ValueError(f"tool must be a concrete scope id: {problem or 'no wildcards'}")
        placeholders = set(PLACEHOLDER.findall(self.resource))
        if self.schema is None and placeholders:
            raise ValueError("a resource template needs an argument schema")
        if self.schema is not None:
            object.__setattr__(self, "schema", tuple(self.schema))
            labels = {item.name for item in self.schema if item.kind == "label"}
            if not placeholders <= labels:
                raise ValueError("every resource placeholder must be a label argument in the schema")
        filled = PLACEHOLDER.sub("x", self.resource)
        problem = validate_entry(filled)
        if problem or any(character in filled for character in "*{}"):
            raise ValueError(f"resource must be a concrete scope id or template: {problem or 'no wildcards'}")

    def resource_for(self, arguments: dict[str, Any]) -> str | None:
        if self.schema is None:
            return self.resource
        if set(arguments) != {item.name for item in self.schema}:
            return None
        if not all(item.accepts(arguments[item.name]) for item in self.schema):
            return None
        return PLACEHOLDER.sub(lambda match: str(arguments[match.group(1)]), self.resource)


DOCUMENT_ROUTE_FIELDS = frozenset({"service", "name", "tool", "resource"})


class ToolRoutes:
    def __init__(self, routes: Iterable[ToolRoute]) -> None:
        table: dict[tuple[str, str], ToolRoute] = {}
        operations: set[tuple[str, str]] = set()
        for route in routes:
            if not isinstance(route, ToolRoute):
                raise TypeError("routes must be ToolRoute records")
            key = (route.service, route.name)
            if key in table:
                raise ValueError(f"duplicate route for tool {route.name!r} on service {route.service!r}")
            operation = (route.tool, route.resource)
            if operation in operations:
                raise ValueError(f"tool {route.tool!r} on resource {route.resource!r} is routed more than once")
            table[key] = route
            operations.add(operation)
        self._table = table

    @classmethod
    def from_document(cls, document: object) -> ToolRoutes:
        if not isinstance(document, dict) or set(document) != {"routes"} or not isinstance(document["routes"], list):
            raise ValueError('a route document must be an object with only a "routes" list')
        routes = []
        for item in document["routes"]:
            if not isinstance(item, dict) or set(item) != DOCUMENT_ROUTE_FIELDS:
                raise ValueError(f"each route must have exactly the fields {', '.join(sorted(DOCUMENT_ROUTE_FIELDS))}")
            routes.append(ToolRoute(**item))
        return cls(routes)

    @property
    def services(self) -> frozenset[str]:
        return frozenset(service for service, _ in self._table)

    def route(self, service: str, name: str) -> ToolRoute | None:
        return self._table.get((service, name))


def routes_from_catalog(service: str, catalog: OperationCatalog) -> ToolRoutes:
    return ToolRoutes(
        ToolRoute(service, item.name, item.tool, item.resource, item.arguments) for item in catalog.operations
    )


def read_call(message: ext_mcp_pb2.McpRequest, routes: ToolRoutes) -> OperationRequest:
    if len(message.service_names) != 1:
        raise CallRefused("malformed_request")
    name, arguments = _params(message)
    route = routes.route(message.service_names[0], name)
    if route is None:
        raise CallRefused("unknown_tool")
    resource = route.resource_for(arguments)
    if resource is None:
        raise CallRefused("malformed_request")
    headers = _call_headers(message)
    links = headers.get(LINKS_HEADER)
    link_tokens = tuple(links.split(",")) if links is not None else ()
    if not all(link_tokens):
        raise CallRefused("malformed_request")
    trace = TRACEPARENT.fullmatch(headers.get(TRACEPARENT_HEADER, ""))
    return OperationRequest(
        tool=route.tool,
        resource=resource,
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
    if not isinstance(params, dict) or not params.keys() <= CALL_PARAMS:
        raise CallRefused("malformed_request")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not name or not isinstance(arguments, dict):
        raise CallRefused("malformed_request")
    if "_meta" in params and not _spec_meta(params["_meta"]):
        raise CallRefused("malformed_request")
    return name, arguments


def _spec_meta(meta: object) -> bool:
    if not isinstance(meta, dict):
        return False
    return all(
        key in META_TYPES and isinstance(value, META_TYPES[key]) and not isinstance(value, bool)
        for key, value in meta.items()
    )


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
