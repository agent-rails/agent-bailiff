from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from typing import Any

from agent_warrant.encoding import b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bailiff.docket.grant import GRANT_FIELDS, GRANT_TYP, Grant, check_grant_body, grant_body
from agent_bailiff.signing import MAX_TOKEN_CHARS, Refused, sign, token_hash, verify
from agent_bailiff.strict_json import parse_strict_json

ENTRY_TYP = "agent-bailiff/docket-entry/v1"
HANDLE_LEVELS = frozenset({"agent_key", "link", "task", "tenant", "root"})
CREDENTIAL_TIERS = frozenset({"target-bound", "gateway-bound", "exposed", "effector"})
CREDENTIAL_EXCEPTIONS = frozenset({"broader", "unredactable"})


@dataclass(frozen=True)
class Head:
    seq: int
    hash: str | None


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
    credential_exceptions: tuple[str, ...] = ()
    reason: str | None = None
    latency_ms: int | None = None
    handles: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Record:
    writer: str
    seq: int
    prev: str | None
    entry: Entry | Grant
    kid: str
    token: str

    @property
    def hash(self) -> str:
        return token_hash(self.token)


@dataclass(frozen=True)
class WriterPin:
    writer: str
    key: Ed25519PublicKey
    typ: str


REQUIRED_STRINGS = frozenset({"entry_id", "trace_id", "hop", "component", "decision"})
NON_NEGATIVE_INTEGERS = frozenset({"at"})
OPTIONAL_INTEGERS = frozenset({"cost", "latency_ms"})
OPTIONAL_ENTRY_FIELDS = frozenset({"credential_exceptions"})
ENTRY_FIELDS = frozenset(item.name for item in fields(Entry)) - OPTIONAL_ENTRY_FIELDS
RECORD_BASE = frozenset({"writer", "seq", "prev"})
RECORD_FIELDS = {ENTRY_TYP: ENTRY_FIELDS | RECORD_BASE, GRANT_TYP: GRANT_FIELDS | RECORD_BASE}
RECORD_OPTIONAL_FIELDS = {ENTRY_TYP: OPTIONAL_ENTRY_FIELDS, GRANT_TYP: frozenset()}


def encode_record(
    private_key: Ed25519PrivateKey, kid: str, writer: str, seq: int, prev: str | None, entry: Entry | Grant
) -> Record:
    typ, item_body = (GRANT_TYP, grant_body(entry)) if isinstance(entry, Grant) else (ENTRY_TYP, _entry_body(entry))
    body = {**item_body, "writer": writer, "seq": seq, "prev": prev}
    _check_record_body(typ, body)
    token = sign(private_key, kid, typ, body)
    return Record(writer=writer, seq=seq, prev=prev, entry=entry, kid=kid, token=token)


def decode_record(token: object, kid_writers: Mapping[str, WriterPin]) -> Record | Refused:
    if not isinstance(token, str):
        return Refused("malformed", f"token must be str, got {type(token).__name__}")
    typ = _peek_typ(token)
    if isinstance(typ, Refused):
        return typ
    if typ not in RECORD_FIELDS:
        return Refused("wrong_typ", "record type is not known")
    pinned = {kid: pin.key for kid, pin in kid_writers.items()}
    result = verify(token, pinned, typ, RECORD_FIELDS[typ], optional_fields=RECORD_OPTIONAL_FIELDS[typ])
    if isinstance(result, Refused):
        return result
    body = result.payload
    try:
        _check_record_body(typ, body)
    except ValueError as exc:
        return Refused("invalid_field", str(exc))
    pin = kid_writers[result.kid]
    if pin.writer != body["writer"]:
        return Refused("unknown_writer", "key id is not pinned for this writer")
    if pin.typ != typ:
        return Refused("wrong_record_type", f"writer {pin.writer} is pinned for {pin.typ} records, not {typ}")
    return Record(
        writer=body["writer"],
        seq=body["seq"],
        prev=body["prev"],
        entry=_grant(body) if typ == GRANT_TYP else _entry(body),
        kid=result.kid,
        token=token,
    )


def _peek_typ(token: str) -> str | Refused:
    if len(token) > MAX_TOKEN_CHARS:
        return Refused("oversized", f"token is {len(token)} characters, over the {MAX_TOKEN_CHARS} limit")
    encoded_payload, separator, _ = token.partition(".")
    if not separator:
        return Refused("malformed", "expected exactly one '.' separator")
    try:
        payload = parse_strict_json(b64u_decode(encoded_payload))
    except (ValueError, RecursionError) as exc:
        return Refused("malformed", f"record type cannot be read: {exc}")
    typ = payload.get("typ") if isinstance(payload, dict) else None
    if not isinstance(typ, str):
        return Refused("malformed", "record type must be a str")
    return typ


def _entry(body: Mapping[str, Any]) -> Entry:
    values = {name: body[name] for name in ENTRY_FIELDS}
    values["links"] = tuple(values["links"])
    return Entry(**values, credential_exceptions=tuple(body.get("credential_exceptions", ())))


def _grant(body: Mapping[str, Any]) -> Grant:
    return Grant(**{name: body[name] for name in GRANT_FIELDS})


def _entry_body(entry: Entry) -> dict[str, Any]:
    body = {name: getattr(entry, name) for name in ENTRY_FIELDS}
    body["links"] = list(entry.links)
    body["handles"] = dict(entry.handles)
    if entry.credential_exceptions:
        body["credential_exceptions"] = list(entry.credential_exceptions)
    return body


def _check_record_body(typ: str, body: Mapping[str, Any]) -> None:
    _require_text(body, "writer")
    seq = body["seq"]
    if not _is_int(seq) or seq < 1:
        raise ValueError("seq must be a positive integer")
    if seq == 1 and body["prev"] is not None:
        raise ValueError("prev must be null for the first entry of a writer")
    if seq > 1 and not _is_text(body["prev"]):
        raise ValueError("prev must be a non-empty str after the first entry")
    if typ == GRANT_TYP:
        check_grant_body(body)
    else:
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
    if "credential_exceptions" in body:
        _check_credential_exceptions(body["credential_exceptions"])
    special = REQUIRED_STRINGS | NON_NEGATIVE_INTEGERS | OPTIONAL_INTEGERS | {"performed", "links", "handles"}
    for name in ENTRY_FIELDS - special:
        if body[name] is not None and not _is_text(body[name]):
            raise ValueError(f"{name} must be a non-empty str or null")


def _check_credential_exceptions(exceptions: object) -> None:
    if not isinstance(exceptions, list | tuple) or not exceptions:
        raise ValueError("credential_exceptions must be a non-empty list when present")
    if not all(isinstance(name, str) and name in CREDENTIAL_EXCEPTIONS for name in exceptions):
        raise ValueError(f"credential_exceptions may hold only {', '.join(sorted(CREDENTIAL_EXCEPTIONS))}")
    if list(exceptions) != sorted(set(exceptions)):
        raise ValueError("credential_exceptions must be sorted with no duplicates")


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
