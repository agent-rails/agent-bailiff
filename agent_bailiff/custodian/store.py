from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

from agent_warrant.canonical import canonicalize
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_bailiff.custodian.backend import BackendError, KeyBackend
from agent_bailiff.custodian.files import OwnedFileError, PinnedFile, connect_owned

DEK_BYTES = 32
NONCE_BYTES = 12
STORE_LABEL = "credential store"
SCHEMA = """
CREATE TABLE credentials (
    tenant TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    target TEXT NOT NULL,
    wrapped_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (tenant, credential_id, target)
);
"""


class CredentialUnavailable(Exception):
    pass


def credential_context(tenant: str, credential_id: str, target: str) -> bytes:
    for name, value in (("tenant", tenant), ("credential_id", credential_id), ("target", target)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty str")
    context: bytes = canonicalize({"tenant": tenant, "credential_id": credential_id, "target": target})
    return context


class CredentialStore:
    def __init__(self, connection: sqlite3.Connection, pinned: PinnedFile, backend: KeyBackend) -> None:
        self._connection = connection
        self._pinned = pinned
        self._backend = backend
        self._lock = threading.Lock()

    @classmethod
    def create(cls, path: Path, backend: KeyBackend) -> CredentialStore:
        return cls(*connect_owned(path, STORE_LABEL, SCHEMA), backend)

    @classmethod
    def open(cls, path: Path, backend: KeyBackend) -> CredentialStore:
        return cls(*connect_owned(path, STORE_LABEL, None), backend)

    def put(self, tenant: str, credential_id: str, target: str, secret: bytes) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret must be non-empty bytes")
        context = credential_context(tenant, credential_id, target)
        dek = os.urandom(DEK_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, secret, context)
        wrapped = self._backend.wrap(dek, context)
        with self._lock:
            self._pinned.check()
            self._connection.execute(
                "INSERT INTO credentials (tenant, credential_id, target, wrapped_dek, nonce, ciphertext) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant, credential_id, target) DO UPDATE SET "
                "wrapped_dek = excluded.wrapped_dek, nonce = excluded.nonce, ciphertext = excluded.ciphertext",
                (tenant, credential_id, target, wrapped, nonce, ciphertext),
            )

    def get(self, tenant: str, credential_id: str, target: str) -> bytes:
        context = credential_context(tenant, credential_id, target)
        try:
            with self._lock:
                self._pinned.check()
                row = self._connection.execute(
                    "SELECT wrapped_dek, nonce, ciphertext FROM credentials "
                    "WHERE tenant = ? AND credential_id = ? AND target = ?",
                    (tenant, credential_id, target),
                ).fetchone()
        except (sqlite3.Error, OwnedFileError):
            raise CredentialUnavailable("credential store is unreadable") from None
        if row is None:
            raise CredentialUnavailable("no credential is stored for this binding")
        wrapped, nonce, ciphertext = row
        try:
            dek = self._backend.unwrap(wrapped, context)
            plaintext: bytes = AESGCM(dek).decrypt(nonce, ciphertext, context)
        except (BackendError, InvalidTag, ValueError):
            raise CredentialUnavailable("credential does not decrypt under its binding") from None
        return plaintext

    def close(self) -> None:
        with self._lock:
            self._connection.close()
