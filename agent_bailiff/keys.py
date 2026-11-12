from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_warrant.encoding import sha256_b64u
from agent_warrant.identity import decode_public_key, encode_public_key, is_valid_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_bailiff.custodian.files import create_owned, read_owned

SEED_BYTES = 32
KEY_LABEL = "signing key file"
KID_DIGEST_CHARACTERS = 16
COMPONENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PUBLIC_KEY_FIELDS = frozenset({"component", "kid", "public_key"})


def key_id(component: str, public_key: Ed25519PublicKey) -> str:
    digest: str = sha256_b64u(public_key.public_bytes_raw())
    return f"{component}-{digest[:KID_DIGEST_CHARACTERS]}"


@dataclass(frozen=True)
class PublicKeyRecord:
    component: str
    kid: str
    public_key: Ed25519PublicKey

    def to_document(self) -> dict[str, str]:
        return {"component": self.component, "kid": self.kid, "public_key": encode_public_key(self.public_key)}

    @classmethod
    def from_document(cls, document: object) -> PublicKeyRecord:
        if not isinstance(document, dict) or set(document) != PUBLIC_KEY_FIELDS:
            raise ValueError(f"a public key record must have exactly the fields {', '.join(sorted(PUBLIC_KEY_FIELDS))}")
        component = check_component(document["component"])
        kid = document["kid"]
        pinned = parse_pinned_keys(component, {kid: document["public_key"]})
        return cls(component, kid, pinned[kid])


def check_component(name: object) -> str:
    if not isinstance(name, str) or not COMPONENT_NAME.fullmatch(name):
        raise ValueError(f"component names must match {COMPONENT_NAME.pattern}")
    return name


def generate_signing_key(path: Path, component: str) -> PublicKeyRecord:
    check_component(component)
    private_key = Ed25519PrivateKey.generate()
    create_owned(path, KEY_LABEL, private_key.private_bytes_raw())
    public_key = private_key.public_key()
    return PublicKeyRecord(component, key_id(component, public_key), public_key)


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    seed = read_owned(path, KEY_LABEL, SEED_BYTES)
    if len(seed) != SEED_BYTES:
        raise ValueError(f"the {KEY_LABEL} must hold exactly {SEED_BYTES} bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def parse_pinned_keys(component: str, document: object) -> dict[str, Ed25519PublicKey]:
    check_component(component)
    if not isinstance(document, Mapping) or not document:
        raise ValueError(f"pinned keys for {component} must be a non-empty object of key ids to public keys")
    pinned: dict[str, Ed25519PublicKey] = {}
    for kid, encoded in document.items():
        public_key = _public_key(encoded)
        if kid != key_id(component, public_key):
            raise ValueError(f"key id {kid!r} is not the key id of its {component} public key")
        pinned[kid] = public_key
    return pinned


def _public_key(encoded: Any) -> Ed25519PublicKey:
    if not is_valid_public_key(encoded):
        raise ValueError("public keys must be unpadded base64url Ed25519 keys")
    key: Ed25519PublicKey = decode_public_key(encoded)
    return key
