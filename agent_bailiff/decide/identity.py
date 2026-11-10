from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from agent_warrant.canonical import MAX_SAFE_INTEGER, canonicalize
from agent_warrant.encoding import sha256_b64u

REQUEST_DOMAIN = b"agent-bailiff/request/v1\x00"
OP_ID_DOMAIN = b"agent-bailiff/op-id/v1\x00"
MAX_ARGS_DEPTH = 32
MAX_ARGS_BYTES = 65536
SURROGATES = re.compile("[\ud800-\udfff]")


class ArgsError(ValueError):
    pass


@dataclass(frozen=True)
class ArgsSnapshot:
    canonical: bytes
    value: Mapping[str, Any]

    @property
    def digest(self) -> str:
        digest: str = sha256_b64u(self.canonical)
        return digest

    def thaw(self) -> dict[str, Any]:
        thawed: dict[str, Any] = json.loads(self.canonical)
        return thawed


def snapshot_args(args: object) -> ArgsSnapshot:
    if not isinstance(args, dict):
        raise ArgsError("args must be an object")
    copy = _copy(args, 1)
    canonical = canonicalize(copy)
    if len(canonical) > MAX_ARGS_BYTES:
        raise ArgsError(f"args are {len(canonical)} bytes, over the {MAX_ARGS_BYTES} byte limit")
    return ArgsSnapshot(canonical, _freeze(copy))


def args_problem(args: object) -> str | None:
    try:
        snapshot_args(args)
    except ArgsError as exc:
        return str(exc)
    return None


def request_digest(tool: str, resource: str, args: dict[str, Any], nonce: str) -> str:
    body = canonicalize({"tool": tool, "resource": resource, "args": snapshot_args(args).thaw(), "nonce": nonce})
    digest: str = sha256_b64u(REQUEST_DOMAIN + body)
    return digest


def derive_op_id(tenant_id: str, task_id: str, leaf_binding: str, digest_of_request: str) -> str:
    body = canonicalize(
        {"tenant_id": tenant_id, "task_id": task_id, "leaf": leaf_binding, "request": digest_of_request}
    )
    return sha256_b64u(OP_ID_DOMAIN + body)


def args_digest(args: dict[str, Any]) -> str:
    return snapshot_args(args).digest


def _copy(value: object, depth: int) -> Any:
    if depth > MAX_ARGS_DEPTH:
        raise ArgsError(f"args nest deeper than {MAX_ARGS_DEPTH} levels")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ArgsError(f"integer {value} is outside +/-{MAX_SAFE_INTEGER}")
        return int(value)
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, dict):
        copied = {}
        for key, inner in value.items():
            if not isinstance(key, str):
                raise ArgsError(f"keys must be str, got {type(key).__name__}")
            copied[_text(key)] = _copy(inner, depth + 1)
        return copied
    if isinstance(value, list):
        return [_copy(inner, depth + 1) for inner in value]
    if isinstance(value, float):
        raise ArgsError(f"floats are not allowed: {value!r}")
    raise ArgsError(f"{type(value).__name__} is not a JSON value")


def _text(value: str) -> str:
    if SURROGATES.search(value):
        raise ArgsError("lone surrogate code point in string")
    return str(value)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(inner) for key, inner in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(inner) for inner in value)
    return value
