from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agent_warrant.canonical import canonicalize, strict_decode
from agent_warrant.encoding import b64u, b64u_decode, sha256_b64u
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TOKEN_VERSION = 1
MAX_TOKEN_CHARS = 65536
SIGNATURE_BYTES = 64
RESERVED_FIELDS = frozenset({"typ", "v", "kid"})


@dataclass(frozen=True)
class Verified:
    payload: dict[str, Any]
    kid: str

    @property
    def ok(self) -> bool:
        return True


@dataclass(frozen=True)
class Refused:
    reason: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return False


VerifyResult = Verified | Refused


def sign(private_key: Ed25519PrivateKey, kid: str, typ: str, body: Mapping[str, Any]) -> str:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if not isinstance(kid, str) or not kid:
        raise ValueError("kid must be a non-empty str")
    if not isinstance(typ, str) or not typ:
        raise ValueError("typ must be a non-empty str")
    clashing = sorted(RESERVED_FIELDS & set(body))
    if clashing:
        raise ValueError(f"body must not set reserved fields: {', '.join(clashing)}")
    payload = {**body, "typ": typ, "v": TOKEN_VERSION, "kid": kid}
    encoded = canonicalize(payload)
    strict_decode(encoded, required=payload.keys(), max_bytes=MAX_TOKEN_CHARS)
    signature = private_key.sign(encoded)
    token = f"{b64u(encoded)}.{b64u(signature)}"
    if len(token) > MAX_TOKEN_CHARS:
        raise ValueError(f"token is {len(token)} characters, over the {MAX_TOKEN_CHARS} limit")
    return token


def verify(
    token: object,
    pinned_keys: Mapping[str, Ed25519PublicKey],
    expected_typ: str,
    allowed_fields: Iterable[str],
    *,
    max_chars: int = MAX_TOKEN_CHARS,
) -> VerifyResult:
    fields = _body_fields(allowed_fields)
    _check_pinned_keys(pinned_keys)
    if not isinstance(expected_typ, str) or not expected_typ:
        raise ValueError("expected_typ must be a non-empty str")
    if not isinstance(token, str):
        return Refused("malformed", f"token must be str, got {type(token).__name__}")
    if len(token) > max_chars:
        return Refused("oversized", f"token is {len(token)} characters, over the {max_chars} limit")
    encoded_payload, separator, encoded_signature = token.partition(".")
    if not separator or "." in encoded_signature:
        return Refused("malformed", "expected exactly one '.' separator")
    try:
        raw = b64u_decode(encoded_payload)
        signature = b64u_decode(encoded_signature)
    except ValueError as exc:
        return Refused("malformed", str(exc))
    try:
        payload = strict_decode(
            raw,
            required=RESERVED_FIELDS,
            optional=fields,
            integer_fields=("v",),
            max_bytes=max_chars,
        )
        canonical = canonicalize(payload)
    except ValueError as exc:
        return Refused("malformed", str(exc))
    if canonical != raw:
        return Refused("non_canonical", "payload is not canonical JSON")
    kid = payload["kid"]
    if not isinstance(kid, str) or kid not in pinned_keys:
        return Refused("unknown_kid", "key id is not pinned")
    if len(signature) != SIGNATURE_BYTES:
        return Refused("bad_signature", "signature has the wrong length")
    try:
        pinned_keys[kid].verify(signature, raw)
    except InvalidSignature:
        return Refused("bad_signature", "signature does not verify")
    if payload["typ"] != expected_typ:
        return Refused("wrong_typ", "record type does not match")
    if payload["v"] != TOKEN_VERSION:
        return Refused("unsupported_version", "token version is not supported")
    missing = sorted(fields - set(payload))
    if missing:
        return Refused("missing_fields", f"missing fields: {', '.join(missing)}")
    return Verified(payload={name: payload[name] for name in fields}, kid=kid)


def token_hash(token: str) -> str:
    return sha256_b64u(token.encode("ascii"))


def _body_fields(allowed_fields: Iterable[str]) -> frozenset[str]:
    if isinstance(allowed_fields, str):
        raise TypeError("allowed_fields must be a collection of field names, not a str")
    fields = frozenset(allowed_fields)
    if not all(isinstance(name, str) and name for name in fields):
        raise TypeError("allowed_fields must contain only non-empty str field names")
    clashing = sorted(RESERVED_FIELDS & fields)
    if clashing:
        raise ValueError(f"allowed_fields must not include reserved fields: {', '.join(clashing)}")
    return fields


def _check_pinned_keys(pinned_keys: Mapping[str, Ed25519PublicKey]) -> None:
    if not isinstance(pinned_keys, Mapping):
        raise TypeError("pinned_keys must be a Mapping of key ids to Ed25519PublicKey")
    for kid, key in pinned_keys.items():
        if not isinstance(kid, str) or not kid or not isinstance(key, Ed25519PublicKey):
            raise TypeError("pinned_keys must map non-empty str key ids to Ed25519PublicKey")
