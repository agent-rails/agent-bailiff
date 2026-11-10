from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from agent_bailiff.custodian.files import OwnedFileError, PinnedFile, connect_owned

CLAIMS_LABEL = "claims database"
SCHEMA = """
CREATE TABLE claims (op_id TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL);
CREATE TABLE denies (
    tenant TEXT NOT NULL,
    task TEXT NOT NULL,
    denied_at INTEGER NOT NULL,
    PRIMARY KEY (tenant, task)
);
"""


class ClaimsUnavailable(Exception):
    pass


class ClaimsStore:
    def __init__(self, connection: sqlite3.Connection, pinned: PinnedFile) -> None:
        self._connection = connection
        self._pinned = pinned
        self._lock = threading.Lock()

    @classmethod
    def create(cls, path: Path) -> ClaimsStore:
        return cls(*connect_owned(path, CLAIMS_LABEL, SCHEMA))

    @classmethod
    def open(cls, path: Path) -> ClaimsStore:
        return cls(*connect_owned(path, CLAIMS_LABEL, None))

    def claim(self, op_id: str, now: int) -> bool:
        try:
            with self._lock:
                self._pinned.check()
                self._connection.execute("INSERT INTO claims (op_id, claimed_at) VALUES (?, ?)", (op_id, now))
        except sqlite3.IntegrityError:
            return False
        except (sqlite3.Error, OwnedFileError):
            raise ClaimsUnavailable("claims database is unavailable") from None
        return True

    def deny(self, tenant: str, task: str, now: int) -> None:
        try:
            with self._lock:
                self._pinned.check()
                self._connection.execute(
                    "INSERT OR IGNORE INTO denies (tenant, task, denied_at) VALUES (?, ?, ?)", (tenant, task, now)
                )
        except (sqlite3.Error, OwnedFileError):
            raise ClaimsUnavailable("claims database is unavailable") from None

    def is_denied(self, tenant: str, task: str) -> bool:
        try:
            with self._lock:
                self._pinned.check()
                row = self._connection.execute(
                    "SELECT 1 FROM denies WHERE tenant = ? AND task = ?", (tenant, task)
                ).fetchone()
        except (sqlite3.Error, OwnedFileError):
            raise ClaimsUnavailable("claims database is unavailable") from None
        return row is not None

    def close(self) -> None:
        with self._lock:
            self._connection.close()
