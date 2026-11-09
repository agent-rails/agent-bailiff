from __future__ import annotations

from typing import Any

from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import sha256_b64u

REQUEST_DOMAIN = b"agentic-security-reference/request/v1\x00"
OP_ID_DOMAIN = b"agentic-security-reference/op-id/v1\x00"


def request_digest(tool: str, resource: str, args: dict[str, Any], nonce: str) -> str:
    body = canonicalize({"tool": tool, "resource": resource, "args": args, "nonce": nonce})
    digest: str = sha256_b64u(REQUEST_DOMAIN + body)
    return digest


def derive_op_id(tenant_id: str, task_id: str, leaf_binding: str, digest_of_request: str) -> str:
    body = canonicalize(
        {"tenant_id": tenant_id, "task_id": task_id, "leaf": leaf_binding, "request": digest_of_request}
    )
    return sha256_b64u(OP_ID_DOMAIN + body)


def args_digest(args: dict[str, Any]) -> str:
    return sha256_b64u(canonicalize(args))
