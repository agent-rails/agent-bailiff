from __future__ import annotations

from pathlib import Path
from typing import Protocol

from agent_warrant.ledger import TaskLedger

from agent_bailiff.custodian.custodian import ReservationReader


class ReadOnlyLedger(ReservationReader, Protocol):
    def close(self) -> None: ...


def open_writer(path: Path, group: int) -> TaskLedger:
    return TaskLedger.open(path, shared_group=group)


def create_writer(path: Path, group: int) -> TaskLedger:
    return TaskLedger.create(path, shared_group=group)


def open_reader(path: Path, writer_uid: int, group: int) -> ReadOnlyLedger:
    return TaskLedger.open_read_only(path, writer_uid, group)
