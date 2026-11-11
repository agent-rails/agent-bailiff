from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_bailiff.custodian.files import create_owned, read_owned

KEK_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
KEK_LABEL = "key encryption key file"


class BackendError(Exception):
    pass


class KeyBackend(Protocol):
    def wrap(self, dek: bytes, context: bytes) -> bytes: ...

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes: ...


class LocalBackend:
    def __init__(self, kek: bytes) -> None:
        if not isinstance(kek, bytes) or len(kek) != KEK_BYTES:
            raise ValueError(f"kek must be {KEK_BYTES} bytes")
        self._aead = AESGCM(kek)

    @classmethod
    def generate(cls, path: Path) -> LocalBackend:
        kek = os.urandom(KEK_BYTES)
        create_owned(path, KEK_LABEL, kek)
        return cls(kek)

    @classmethod
    def load(cls, path: Path) -> LocalBackend:
        kek = read_owned(path, KEK_LABEL, KEK_BYTES)
        if len(kek) != KEK_BYTES:
            raise BackendError(f"the {KEK_LABEL} must hold exactly {KEK_BYTES} bytes")
        return cls(kek)

    def wrap(self, dek: bytes, context: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, dek, context)

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        if not isinstance(wrapped, bytes) or len(wrapped) < NONCE_BYTES + TAG_BYTES:
            raise BackendError("wrapped key is malformed")
        try:
            return self._aead.decrypt(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], context)
        except InvalidTag:
            raise BackendError("wrapped key does not open under this context") from None
