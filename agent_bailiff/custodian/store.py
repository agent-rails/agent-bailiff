from __future__ import annotations

import logging
import os
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from agent_warrant.canonical import canonicalize
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_bailiff.custodian.backend import BackendError, KeyBackend
from agent_bailiff.custodian.echo import redaction_problem
from agent_bailiff.custodian.files import (
    OwnedFileError,
    PinnedFile,
    connect_owned,
    database_error_name,
    raise_database_error,
)

DEK_BYTES = 32
NONCE_BYTES = 12
STORE_LABEL = "credential store"
UNREDACTABLE = "unredactable"
BROADER = "broader"
EXCEPTIONS = frozenset({UNREDACTABLE, BROADER})
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
    exceptions: frozenset[str]


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


def encode_exceptions(exceptions: frozenset[str]) -> str | None:
    if not isinstance(exceptions, frozenset):
        raise ValueError("credential exceptions must be a frozenset")
    for name in exceptions:
        if name not in EXCEPTIONS:
            raise ValueError(f"unknown credential exception {name!r}")
    return ",".join(sorted(exceptions)) if exceptions else None


def decode_exceptions(value: str | None) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, str):
        raise ValueError("credential exceptions must be a str")
    names = value.split(",")
    exceptions = frozenset(name for name in names if name in EXCEPTIONS)
    if len(exceptions) != len(names) or encode_exceptions(exceptions) != value:
        raise ValueError("credential exceptions are not a canonical set of known names")
    return exceptions


def credential_context(tenant: str, credential_id: str, target: str, exceptions: frozenset[str] = frozenset()) -> bytes:
    for name, value in (("tenant", tenant), ("credential_id", credential_id), ("target", target)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must be a non-empty str")
    fields = {"tenant": tenant, "credential_id": credential_id, "target": target}
    encoded = encode_exceptions(exceptions)
    if encoded is not None:
        fields["exception"] = encoded
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
            raise_database_error(f"cannot open the {STORE_LABEL} at {path}", exc)
        return cls(connection, pinned, backend)

    def put(
        self,
        tenant: str,
        credential_id: str,
        target: str,
        secret: bytes,
        *,
        accept_unredactable: bool = False,
        accept_broader: bool = False,
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
        exceptions = frozenset(
            name for name, accepted in ((UNREDACTABLE, problem is not None), (BROADER, accept_broader)) if accepted
        )
        context = credential_context(tenant, credential_id, target, exceptions)
        dek = os.urandom(DEK_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, secret, context)
        wrapped = self._backend.wrap(dek, context)
        with self._lock:
            self._pinned.check()
            try:
                self._connection.execute(
                    "INSERT INTO credentials (tenant, credential_id, target, wrapped_dek, nonce, ciphertext, "
                    "exception) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant, credential_id, target) DO UPDATE SET "
                    "wrapped_dek = excluded.wrapped_dek, nonce = excluded.nonce, ciphertext = excluded.ciphertext, "
                    "exception = excluded.exception",
                    (tenant, credential_id, target, wrapped, nonce, ciphertext, encode_exceptions(exceptions)),
                )
            except sqlite3.Error as exc:
                raise_database_error(f"cannot write the {STORE_LABEL} at {self._pinned.path}", exc)
        if problem is not None:
            logger.warning(
                "stored credential %r for target %r with an accepted %s exception: %s",
                credential_id,
                target,
                UNREDACTABLE,
                problem,
            )
        if accept_broader:
            logger.warning(
                "stored credential %r for target %r with an accepted %s exception: "
                "its provider privilege may exceed the binding",
                credential_id,
                target,
                BROADER,
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

    def check(self, required: Iterable[tuple[str, str, str]] = ()) -> CredentialCheck:
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
        for row in rows:
            problem = self._row_problem(*row)
            if problem is not None:
                problems.append(problem)
        stored = {tuple(row[:3]) for row in rows}
        for key in sorted(set(required) - stored):
            problems.append(CredentialProblem(*key, "no credential is stored for this binding"))
        return CredentialCheck(len(rows), tuple(problems))

    def _row_problem(
        self,
        tenant: object,
        credential_id: object,
        target: object,
        wrapped: object,
        nonce: object,
        ciphertext: object,
        exception: object,
    ) -> CredentialProblem | None:
        if not (
            isinstance(tenant, str)
            and isinstance(credential_id, str)
            and isinstance(target, str)
            and isinstance(wrapped, bytes)
            and isinstance(nonce, bytes)
            and isinstance(ciphertext, bytes)
            and (exception is None or isinstance(exception, str))
        ):
            return CredentialProblem(
                _shown(tenant), _shown(credential_id), _shown(target), "credential row is malformed"
            )
        problem = self._release_problem(tenant, credential_id, target, wrapped, nonce, ciphertext, exception)
        return None if problem is None else CredentialProblem(tenant, credential_id, target, problem)

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
        if problem is not None and UNREDACTABLE not in stored.exceptions:
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
            exceptions = decode_exceptions(exception)
            context = credential_context(tenant, credential_id, target, exceptions)
            dek = self._backend.unwrap(wrapped, context)
            plaintext: bytes = AESGCM(dek).decrypt(nonce, ciphertext, context)
        except (BackendError, InvalidTag, ValueError):
            raise CredentialUnavailable("credential does not decrypt under its binding") from None
        return StoredCredential(plaintext, exceptions)

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
    except BaseException as exc:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error as rollback:
                exc.add_note(f"the rollback also failed ({database_error_name(rollback)})")
        raise


def _has_exception_column(connection: sqlite3.Connection) -> bool:
    return "exception" in {row[1] for row in connection.execute("PRAGMA table_info(credentials)")}


def _shown(value: object) -> str:
    return value if isinstance(value, str) else repr(value)
