from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bailiff.signing import Refused, sign, token_hash, verify

ENTRY_TYP = "agent-bailiff/docket-entry/v1"
HANDLE_LEVELS = frozenset({"agent_key", "link", "task", "tenant", "root"})
CREDENTIAL_TIERS = frozenset({"target-bound", "gateway-bound", "exposed"})


@dataclass(frozen=True)
class Entry:
    entry_id: str
    trace_id: str
    hop: str
    component: str
    decision: str
    at: int
    op_id: str | None = None
    parent_entry: str | None = None
    principal: str | None = None
    tenant: str | None = None
    task_root: str | None = None
    links: tuple[str, ...] = ()
    agent_key: str | None = None
    tool: str | None = None
    resource: str | None = None
    args_digest: str | None = None
    cost: int | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    policy_digest: str | None = None
    rule: str | None = None
    verdict: str | None = None
    performed: bool = False
    outcome: str | None = None
    receipt_digest: str | None = None
    clearance_digest: str | None = None
    credential_tier: str | None = None
    reason: str | None = None
    latency_ms: int | None = None
    handles: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Record:
    writer: str
    seq: int
    prev: str | None
    entry: Entry
    kid: str
    token: str

    @property
    def hash(self) -> str:
        return token_hash(self.token)


REQUIRED_STRINGS = frozenset({"entry_id", "trace_id", "hop", "component", "decision"})
NON_NEGATIVE_INTEGERS = frozenset({"at"})
OPTIONAL_INTEGERS = frozenset({"cost", "latency_ms"})
ENTRY_FIELDS = frozenset(item.name for item in fields(Entry))
RECORD_FIELDS = ENTRY_FIELDS | {"writer", "seq", "prev"}


def encode_record(
    private_key: Ed25519PrivateKey, kid: str, writer: str, seq: int, prev: str | None, entry: Entry
) -> Record:
    body = {**_entry_body(entry), "writer": writer, "seq": seq, "prev": prev}
    _check_record_body(body)
    token = sign(private_key, kid, ENTRY_TYP, body)
    return Record(writer=writer, seq=seq, prev=prev, entry=entry, kid=kid, token=token)


def decode_record(token: object, kid_writers: Mapping[str, tuple[str, Ed25519PublicKey]]) -> Record | Refused:
    if not isinstance(token, str):
        return Refused("malformed", f"token must be str, got {type(token).__name__}")
    pinned = {kid: key for kid, (_, key) in kid_writers.items()}
    result = verify(token, pinned, ENTRY_TYP, RECORD_FIELDS)
    if isinstance(result, Refused):
        return result
    body = result.payload
    try:
        _check_record_body(body)
    except ValueError as exc:
        return Refused("invalid_field", str(exc))
    if kid_writers[result.kid][0] != body["writer"]:
        return Refused("unknown_writer", "key id is not pinned for this writer")
    entry_values = {name: body[name] for name in ENTRY_FIELDS}
    entry_values["links"] = tuple(entry_values["links"])
    return Record(
        writer=body["writer"],
        seq=body["seq"],
        prev=body["prev"],
        entry=Entry(**entry_values),
        kid=result.kid,
        token=token,
    )


def _entry_body(entry: Entry) -> dict[str, Any]:
    body = {item.name: getattr(entry, item.name) for item in fields(Entry)}
    body["links"] = list(entry.links)
    body["handles"] = dict(entry.handles)
    return body


def _check_record_body(body: Mapping[str, Any]) -> None:
    _require_text(body, "writer")
    seq = body["seq"]
    if not _is_int(seq) or seq < 1:
        raise ValueError("seq must be a positive integer")
    if seq == 1 and body["prev"] is not None:
        raise ValueError("prev must be null for the first entry of a writer")
    if seq > 1 and not _is_text(body["prev"]):
        raise ValueError("prev must be a non-empty str after the first entry")
    _check_entry_body(body)


def _check_entry_body(body: Mapping[str, Any]) -> None:
    for name in REQUIRED_STRINGS:
        _require_text(body, name)
    for name in NON_NEGATIVE_INTEGERS:
        if not _is_int(body[name]) or body[name] < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    for name in OPTIONAL_INTEGERS:
        if body[name] is not None and (not _is_int(body[name]) or body[name] < 0):
            raise ValueError(f"{name} must be a non-negative integer or null")
    if not isinstance(body["performed"], bool):
        raise ValueError("performed must be a bool")
    links = body["links"]
    if not isinstance(links, list | tuple) or not all(_is_text(link) for link in links):
        raise ValueError("links must be a list of non-empty str")
    _check_handles(body["handles"])
    tier = body["credential_tier"]
    if tier is not None and tier not in CREDENTIAL_TIERS:
        raise ValueError(f"credential_tier must be one of {', '.join(sorted(CREDENTIAL_TIERS))} or null")
    special = REQUIRED_STRINGS | NON_NEGATIVE_INTEGERS | OPTIONAL_INTEGERS | {"performed", "links", "handles"}
    for name in ENTRY_FIELDS - special:
        if body[name] is not None and not _is_text(body[name]):
            raise ValueError(f"{name} must be a non-empty str or null")


def _check_handles(handles: object) -> None:
    if not isinstance(handles, Mapping):
        raise ValueError("handles must be an object")
    unknown = sorted(set(handles) - HANDLE_LEVELS)
    if unknown:
        raise ValueError(f"unknown handle levels: {', '.join(map(str, unknown))}")
    if not all(_is_text(value) for value in handles.values()):
        raise ValueError("handle values must be non-empty str")


def _require_text(body: Mapping[str, Any], name: str) -> None:
    if not _is_text(body[name]):
        raise ValueError(f"{name} must be a non-empty str")


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
