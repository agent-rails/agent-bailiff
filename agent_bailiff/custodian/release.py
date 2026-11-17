from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from typing import Any

from agent_warrant.canonical import MAX_SAFE_INTEGER
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bailiff.decide.clearance import Clearance
from agent_bailiff.signing import Refused, sign, verify

RELEASE_TYP = "agent-bailiff/release/v1"
RELEASE_HEADER = "bailiff-release"
RELEASE_LIFETIME = 10
MAX_RELEASE_BYTES = 16384


class ReleaseTooLarge(ValueError):
    pass


@dataclass(frozen=True)
class Release:
    iss: str
    aud: str
    iat: int
    exp: int
    op_id: str
    tenant: str
    task: str
    tool: str
    resource: str
    args_digest: str
    catalog: str
    clearance: str
    entry_id: str


RELEASE_FIELDS = frozenset(item.name for item in fields(Release))
INTEGER_FIELDS = frozenset({"iat", "exp"})


class ReleaseSigner:
    def __init__(self, issuer: str, private_key: Ed25519PrivateKey, kid: str) -> None:
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("issuer must be a non-empty str")
        self._issuer = issuer
        self._key = private_key
        self._kid = kid

    def sign(
        self, clearance: Clearance, clearance_token: str, audience: str, catalog: str, entry_id: str, now: int
    ) -> str:
        release = Release(
            iss=self._issuer,
            aud=audience,
            iat=now,
            exp=min(clearance.exp, now + RELEASE_LIFETIME),
            op_id=clearance.op_id,
            tenant=clearance.tenant,
            task=clearance.task,
            tool=clearance.tool,
            resource=clearance.resource,
            args_digest=clearance.args_digest,
            catalog=catalog,
            clearance=clearance_token,
            entry_id=entry_id,
        )
        body = asdict(release)
        problem = _field_problem(body)
        if problem:
            raise ValueError(problem)
        token = sign(self._key, self._kid, RELEASE_TYP, body)
        if len(token) > MAX_RELEASE_BYTES:
            raise ReleaseTooLarge(f"release is longer than {MAX_RELEASE_BYTES} characters")
        return token


def verify_release(
    token: object,
    pinned_keys: Mapping[str, Ed25519PublicKey],
    *,
    now: int,
    expected_aud: str,
    expected_iss: str,
    skew_seconds: int,
) -> Release | Refused:
    for name, value in (("now", now), ("skew_seconds", skew_seconds)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    if isinstance(token, str) and len(token) > MAX_RELEASE_BYTES:
        return Refused("oversized", f"release is longer than {MAX_RELEASE_BYTES} characters")
    result = verify(token, pinned_keys, RELEASE_TYP, RELEASE_FIELDS)
    if isinstance(result, Refused):
        return result
    problem = _field_problem(result.payload)
    if problem:
        return Refused("invalid_field", problem)
    release = Release(**result.payload)
    if release.iss != expected_iss:
        return Refused("wrong_issuer", "release was issued by another custodian")
    if release.aud != expected_aud:
        return Refused("wrong_audience", "release is addressed to another effector")
    if release.exp - release.iat > RELEASE_LIFETIME:
        return Refused("lifetime_exceeded", f"release lifetime exceeds {RELEASE_LIFETIME} seconds")
    if release.iat > now + skew_seconds:
        return Refused("not_yet_valid", "release is issued in the future")
    if now >= release.exp:
        return Refused("expired", "release has expired")
    return release


def _field_problem(body: Mapping[str, Any]) -> str | None:
    for name in sorted(RELEASE_FIELDS):
        value = body[name]
        if name in INTEGER_FIELDS:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
                return f"{name} must be an integer between 0 and {MAX_SAFE_INTEGER}"
        elif not isinstance(value, str) or not value:
            return f"{name} must be a non-empty str"
    if body["exp"] <= body["iat"]:
        return "exp must be after iat"
    return None
