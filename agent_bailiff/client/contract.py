from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from agent_warrant.chain import ChainLink, delegate, prove_leaf
from agent_warrant.identity import encode_public_key
from agent_warrant.task_root import TaskRoot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bailiff.chain_headers import (
    LEAF_PROOF_HEADER,
    LINKS_HEADER,
    NONCE_HEADER,
    TASK_ROOT_HEADER,
    TRACEPARENT,
    TRACEPARENT_HEADER,
)
from agent_bailiff.decide.identity import request_digest
from agent_bailiff.routes import ToolRoutes

CONTRACT_VERSION = 1
NONCE_BYTES = 16
TRACE_ID_BYTES = 16
PARENT_ID_BYTES = 8

TokenBytes = Callable[[int], bytes]


@dataclass(frozen=True)
class Holder:
    task_root: str
    links: tuple[str, ...]
    key: Ed25519PrivateKey
    audience: str
    leaf: TaskRoot | ChainLink = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "links", tuple(self.links))
        root = TaskRoot.decode(self.task_root)
        leaf = ChainLink.decode(self.links[-1]) if self.links else root
        if leaf.subject != encode_public_key(self.key.public_key()):
            raise ValueError("the holder key is not the subject of the last record in the chain")
        if not self.audience:
            raise ValueError("audience must be the decider id")
        object.__setattr__(self, "leaf", leaf)

    def delegate(
        self, child: Ed25519PublicKey, *, scope: dict[str, Any], budget: int, ttl: int, now: int
    ) -> tuple[str, ...]:
        link = delegate(
            TaskRoot.decode(self.task_root),
            self.leaf,
            self.key,
            child_subject=encode_public_key(child),
            scope=scope,
            budget=budget,
            ttl=ttl,
            now=now,
        )
        return (*self.links, link.encode())


class PreparedCall:
    __slots__ = ("_sent", "body", "headers", "nonce", "request_id", "resource", "tool")

    def __init__(
        self, request_id: int, tool: str, resource: str, nonce: str, headers: Mapping[str, str], body: bytes
    ) -> None:
        self.request_id = request_id
        self.tool = tool
        self.resource = resource
        self.nonce = nonce
        self.headers: Mapping[str, str] = MappingProxyType(dict(headers))
        self.body = body
        self._sent = False

    def consume(self) -> None:
        if self._sent:
            raise RuntimeError("a prepared call is sent at most once: prepare a new call to get a fresh nonce")
        self._sent = True


def new_traceparent(token_bytes: TokenBytes) -> str:
    trace_id = token_bytes(TRACE_ID_BYTES)
    parent_id = token_bytes(PARENT_ID_BYTES)
    if not any(trace_id) or not any(parent_id):
        raise ValueError("the random source returned an all-zero trace or parent id")
    return f"00-{trace_id.hex()}-{parent_id.hex()}-01"


def prepare_call(
    holder: Holder,
    routes: ToolRoutes,
    service: str,
    name: str,
    arguments: dict[str, Any],
    *,
    request_id: int,
    now: int,
    token_bytes: TokenBytes,
    traceparent: str | None = None,
) -> PreparedCall:
    route = routes.route(service, name)
    if route is None:
        raise ValueError(f"no route for tool {name!r} on service {service!r}")
    resource = route.resource_for(arguments)
    if resource is None:
        raise ValueError(f"arguments for {name!r} do not match the route's argument schema")
    if traceparent is None:
        traceparent = new_traceparent(token_bytes)
    elif not TRACEPARENT.fullmatch(traceparent):
        raise ValueError("traceparent must be a W3C version 00 traceparent with non-zero ids")
    nonce = token_bytes(NONCE_BYTES).hex()
    digest = request_digest(route.tool, resource, arguments, nonce)
    proof = prove_leaf(holder.leaf, holder.key, now, audience=holder.audience, request_digest=digest)
    headers = {
        TASK_ROOT_HEADER: holder.task_root,
        LEAF_PROOF_HEADER: proof.encode(),
        NONCE_HEADER: nonce,
        TRACEPARENT_HEADER: traceparent,
    }
    if holder.links:
        headers[LINKS_HEADER] = ",".join(holder.links)
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    body = json.dumps(message, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()
    return PreparedCall(request_id, route.tool, resource, nonce, headers, body)
