from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from agent_warrant.ledger import TaskLedger

from agent_bailiff.custodian.custodian import ReservationReader

SHARED_LEDGER_RELEASE = "agent-warrant 0.2.0 or later"


class LedgerUnsupported(Exception):
    pass


class ReadOnlyLedger(ReservationReader, Protocol):
    def close(self) -> None: ...


def open_writer(path: Path, group: int) -> TaskLedger:
    opener: Callable[..., TaskLedger] = TaskLedger.open
    _require_shared_ledgers()
    return opener(path, shared_group=group)


def create_writer(path: Path, group: int) -> TaskLedger:
    creator: Callable[..., TaskLedger] = TaskLedger.create
    _require_shared_ledgers()
    return creator(path, shared_group=group)


def open_reader(path: Path, writer_uid: int, group: int) -> ReadOnlyLedger:
    opener: Callable[..., ReadOnlyLedger] | None = getattr(TaskLedger, "open_read_only", None)
    if opener is None:
        raise LedgerUnsupported(f"a read-only ledger needs {SHARED_LEDGER_RELEASE}")
    return opener(path, writer_uid, group)


def _require_shared_ledgers() -> None:
    if getattr(TaskLedger, "open_read_only", None) is None:
        raise LedgerUnsupported(f"a shared-group ledger needs {SHARED_LEDGER_RELEASE}")
