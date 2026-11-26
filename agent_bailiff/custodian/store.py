from __future__ import annotations

import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path

from agent_warrant.canonical import canonicalize
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_bailiff.custodian.backend import BackendError, KeyBackend
from agent_bailiff.custodian.echo import redaction_problem
from agent_bailiff.custodian.files import OwnedFileError, PinnedFile, connect_owned

DEK_BYTES = 32
NONCE_BYTES = 12
STORE_LABEL = "credential store"
UNREDACTABLE = "unredactable"
EXCEPTIONS = frozenset({UNREDACTABLE})
SCHEMA = """
CREATE TABLE credentials (
    tenant TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    target TEXT NOT NULL,
    wrapped_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    exception TEXT,
    PRIMARY KEY (tenant, credential_id, target)
);
"""
ADD_EXCEPTION = "ALTER TABLE credentials ADD COLUMN exception TEXT"

logger = logging.getLogger(__name__)


class CredentialUnavailable(Exception):
    pass


class UnredactableCredential(ValueError):
    pass


@dataclass(frozen=True)
class StoredCredential:
    secret: bytes = field(repr=False)
    exception: str | None


@dataclass(frozen=True)
class CredentialProblem:
    tenant: str
    credential_id: str
    target: str
    problem: str


@dataclass(frozen=True)
class CredentialCheck:
    checked: int
    problems: tuple[CredentialProblem, ...]


def credential_context(tenant: str, credential_id: str, target: str, exception: str | None = None) -> bytes:
    for name, value in (("tenant", tenant), ("credential_id", credential_id), ("target", target)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty str")
    fields = {"tenant": tenant, "credential_id": credential_id, "target": target}
    if exception is not None:
        if exception not in EXCEPTIONS:
            raise ValueError(f"unknown credential exception {exception!r}")
        fields["exception"] = exception
    context: bytes = canonicalize(fields)
    return context


def header_value(secret: bytes) -> str | None:
    try:
        value = secret.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not value or value != value.strip(" \t"):
        return None
    if not all(character in " \t" or "!" <= character <= "~" for character in value):
        return None
    return value


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
        connection, pinned = connect_owned(path, STORE_LABEL, None)
        try:
            _add_exception_column(connection)
        except sqlite3.Error as exc:
            connection.close()
            raise OwnedFileError(f"the {STORE_LABEL} is not a usable database: {exc}") from None
        return cls(connection, pinned, backend)

    def put(
        self, tenant: str, credential_id: str, target: str, secret: bytes, *, accept_unredactable: bool = False
    ) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("secret must be non-empty bytes")
        value = header_value(secret)
        if value is None:
            raise ValueError("secret must be printable ASCII with no leading or trailing space or tab")
        problem = redaction_problem(value)
        if problem is not None and not accept_unredactable:
            raise UnredactableCredential(f"credential cannot be redacted from results: {problem}")
        if problem is None and accept_unredactable:
            raise ValueError("an unredactable exception was requested for a credential that can be redacted")
        exception = UNREDACTABLE if problem is not None else None
        context = credential_context(tenant, credential_id, target, exception)
        dek = os.urandom(DEK_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, secret, context)
        wrapped = self._backend.wrap(dek, context)
        with self._lock:
            self._pinned.check()
            self._connection.execute(
                "INSERT INTO credentials (tenant, credential_id, target, wrapped_dek, nonce, ciphertext, exception) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant, credential_id, target) DO UPDATE SET "
                "wrapped_dek = excluded.wrapped_dek, nonce = excluded.nonce, ciphertext = excluded.ciphertext, "
                "exception = excluded.exception",
                (tenant, credential_id, target, wrapped, nonce, ciphertext, exception),
            )
        if problem is not None:
            logger.warning(
                "stored credential %r for target %r with an accepted %s exception: %s",
                credential_id,
                target,
                UNREDACTABLE,
                problem,
            )

    def get(self, tenant: str, credential_id: str, target: str) -> StoredCredential:
        try:
            with self._lock:
                self._pinned.check()
                row = self._connection.execute(
                    "SELECT wrapped_dek, nonce, ciphertext, exception FROM credentials "
                    "WHERE tenant = ? AND credential_id = ? AND target = ?",
                    (tenant, credential_id, target),
                ).fetchone()
        except (sqlite3.Error, OwnedFileError):
            raise CredentialUnavailable("credential store is unreadable") from None
        if row is None:
            raise CredentialUnavailable("no credential is stored for this binding")
        return self._decrypt(tenant, credential_id, target, *row)

    def check(self) -> CredentialCheck:
        try:
            with self._lock:
                self._pinned.check()
                rows = self._connection.execute(
                    "SELECT tenant, credential_id, target, wrapped_dek, nonce, ciphertext, exception "
                    "FROM credentials ORDER BY tenant, credential_id, target"
                ).fetchall()
        except (sqlite3.Error, OwnedFileError):
            raise CredentialUnavailable("credential store is unreadable") from None
        problems = []
        for tenant, credential_id, target, *sealed in rows:
            problem = self._release_problem(tenant, credential_id, target, *sealed)
            if problem is not None:
                problems.append(CredentialProblem(tenant, credential_id, target, problem))
        return CredentialCheck(len(rows), tuple(problems))

    def _release_problem(
        self,
        tenant: str,
        credential_id: str,
        target: str,
        wrapped: bytes,
        nonce: bytes,
        ciphertext: bytes,
        exception: str | None,
    ) -> str | None:
        try:
            stored = self._decrypt(tenant, credential_id, target, wrapped, nonce, ciphertext, exception)
        except CredentialUnavailable as exc:
            return str(exc)
        value = header_value(stored.secret)
        if value is None:
            return "credential is not printable ASCII with no leading or trailing space or tab"
        problem = redaction_problem(value)
        if problem is not None and stored.exception is None:
            return f"credential cannot be redacted from results and has no accepted exception: {problem}"
        return None

    def _decrypt(
        self,
        tenant: str,
        credential_id: str,
        target: str,
        wrapped: bytes,
        nonce: bytes,
        ciphertext: bytes,
        exception: str | None,
    ) -> StoredCredential:
        try:
            context = credential_context(tenant, credential_id, target, exception)
            dek = self._backend.unwrap(wrapped, context)
            plaintext: bytes = AESGCM(dek).decrypt(nonce, ciphertext, context)
        except (BackendError, InvalidTag, ValueError):
            raise CredentialUnavailable("credential does not decrypt under its binding") from None
        return StoredCredential(plaintext, exception)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _add_exception_column(connection: sqlite3.Connection) -> None:
    if _has_exception_column(connection):
        return
    connection.execute("BEGIN IMMEDIATE")
    try:
        if not _has_exception_column(connection):
            connection.execute(ADD_EXCEPTION)
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _has_exception_column(connection: sqlite3.Connection) -> bool:
    return "exception" in {row[1] for row in connection.execute("PRAGMA table_info(credentials)")}
