from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from typing import Any

from agent_warrant.canonical import MAX_SAFE_INTEGER
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bailiff.signing import Refused, sign, verify

CLEARANCE_TYP = "agent-bailiff/clearance/v1"


@dataclass(frozen=True)
class Clearance:
    iss: str
    aud: str
    iat: int
    exp: int
    op_id: str
    tenant: str
    task: str
    root_binding: str
    leaf_binding: str
    request_digest: str
    tool: str
    resource: str
    args_digest: str
    cost: int
    credential_id: str
    target: str
    trace_id: str
    entry_id: str


CLEARANCE_FIELDS = frozenset(item.name for item in fields(Clearance))
INTEGER_FIELDS = frozenset({"iat", "exp", "cost"})


def encode_clearance(clearance: Clearance, private_key: Ed25519PrivateKey, kid: str) -> str:
    body = asdict(clearance)
    problem = _field_problem(body)
    if problem:
        raise ValueError(problem)
    return sign(private_key, kid, CLEARANCE_TYP, body)


def decode_clearance(
    token: object, pinned_keys: Mapping[str, Ed25519PublicKey], *, max_lifetime: int
) -> Clearance | Refused:
    if isinstance(max_lifetime, bool) or not isinstance(max_lifetime, int) or max_lifetime <= 0:
        raise ValueError("max_lifetime must be a positive integer")
    result = verify(token, pinned_keys, CLEARANCE_TYP, CLEARANCE_FIELDS)
    if isinstance(result, Refused):
        return result
    problem = _field_problem(result.payload)
    if problem:
        return Refused("invalid_field", problem)
    if result.payload["exp"] - result.payload["iat"] > max_lifetime:
        return Refused("lifetime_exceeded", f"lifetime exceeds {max_lifetime} seconds")
    return Clearance(**result.payload)


def verify_clearance(
    token: object,
    pinned_keys: Mapping[str, Ed25519PublicKey],
    *,
    now: int,
    expected_aud: str,
    expected_iss: str,
    skew_seconds: int,
    max_lifetime: int,
) -> Clearance | Refused:
    for name, value in (("now", now), ("skew_seconds", skew_seconds)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    for name, text in (("expected_aud", expected_aud), ("expected_iss", expected_iss)):
        if not isinstance(text, str) or not text:
            raise ValueError(f"{name} must be a non-empty str")
    clearance = decode_clearance(token, pinned_keys, max_lifetime=max_lifetime)
    if isinstance(clearance, Refused):
        return clearance
    if clearance.iss != expected_iss:
        return Refused("wrong_issuer", "clearance was issued by another decider")
    if clearance.aud != expected_aud:
        return Refused("wrong_audience", "clearance is addressed to another custodian")
    if clearance.iat > now + skew_seconds:
        return Refused("not_yet_valid", "clearance is issued in the future")
    if now >= clearance.exp:
        return Refused("expired", "clearance has expired")
    return clearance


def _field_problem(body: Mapping[str, Any]) -> str | None:
    for name in sorted(CLEARANCE_FIELDS):
        value = body[name]
        if name in INTEGER_FIELDS:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
                return f"{name} must be an integer between 0 and {MAX_SAFE_INTEGER}"
        elif not isinstance(value, str) or not value:
            return f"{name} must be a non-empty str"
    if body["exp"] <= body["iat"]:
        return "exp must be after iat"
    return None
