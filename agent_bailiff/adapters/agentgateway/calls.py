from __future__ import annotations

from typing import Any

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.chain_headers import (
    CALL_HEADERS,
    LEAF_PROOF_HEADER,
    LINKS_HEADER,
    NONCE_HEADER,
    REQUIRED_HEADERS,
    TASK_ROOT_HEADER,
    TRACEPARENT,
    TRACEPARENT_HEADER,
)
from agent_bailiff.decide.identity import MAX_ARGS_BYTES
from agent_bailiff.decide.request import OperationRequest
from agent_bailiff.routes import ToolRoutes
from agent_bailiff.strict_json import parse_strict_json

TOOLS_CALL = "tools/call"
MAX_PARAMS_BYTES = 2 * MAX_ARGS_BYTES
CALL_PARAMS = frozenset({"name", "arguments", "_meta"})
META_TYPES: dict[str, tuple[type, ...]] = {
    "progressToken": (str, int),
    "io.modelcontextprotocol/protocolVersion": (str,),
    "io.modelcontextprotocol/clientInfo": (dict,),
    "io.modelcontextprotocol/clientCapabilities": (dict,),
}


class CallRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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
