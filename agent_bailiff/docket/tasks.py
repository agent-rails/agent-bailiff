from __future__ import annotations

import json
from dataclasses import dataclass, field

from agent_bailiff.docket.report import printable, utc
from agent_bailiff.docket.sink import VerifiedLine

CONTROL_HOP = "control"
TASK_COLUMNS = ("tenant", "task", "principal", "first", "last", "allows", "releases", "refusals", "state")


@dataclass
class TaskRow:
    tenant: str
    task: str
    principal: str | None = None
    roots: set[str] = field(default_factory=set)
    first: int = 0
    last: int = 0
    allows: int = 0
    releases: int = 0
    refusals: int = 0
    revoked_by: str | None = None
    record: str | None = None
    record_line: int | None = None


class TaskList:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], TaskRow] = {}
        self._revocations: list[tuple[str, dict[str, str]]] = []

    def add(self, verified: VerifiedLine) -> None:
        entry = verified.record.entry
        if entry.hop == CONTROL_HOP:
            if entry.decision == "revoke":
                self._revocations.append((entry.entry_id, dict(entry.handles)))
            return
        tenant, task = entry.handles.get("tenant"), entry.handles.get("task")
        if tenant is None or task is None:
            return
        row = self._rows.get((tenant, task))
        if row is None:
            row = self._rows[(tenant, task)] = TaskRow(tenant, task, first=entry.at)
        row.first, row.last = min(row.first, entry.at), max(row.last, entry.at)
        row.principal = entry.principal or row.principal
        if "root" in entry.handles:
            row.roots.add(entry.handles["root"])
        if entry.decision == "refuse":
            row.refusals += 1
        elif entry.decision == "allow" and entry.hop == "custodian":
            row.releases += 1
        elif entry.decision == "allow":
            row.allows += 1
        row.record, row.record_line = verified.record.token, verified.line

    def rows(self) -> list[TaskRow]:
        rows = sorted(self._rows.values(), key=lambda row: (row.last, row.tenant, row.task))
        for row in rows:
            row.revoked_by = next((entry_id for entry_id, handles in self._revocations if _revokes(handles, row)), None)
        return rows


def _revokes(handles: dict[str, str], row: TaskRow) -> bool:
    if "task" in handles:
        return handles["task"] == row.task and handles.get("tenant") == row.tenant
    if "root" in handles:
        return handles["root"] in row.roots
    return handles.get("tenant") == row.tenant


def task_header() -> str:
    return "\t".join(column.upper() for column in TASK_COLUMNS)


def task_table_row(row: TaskRow) -> str:
    values = (
        row.tenant,
        row.task,
        row.principal,
        utc(row.first),
        utc(row.last),
        str(row.allows),
        str(row.releases),
        str(row.refusals),
        "revoked" if row.revoked_by else "-",
    )
    return "\t".join(printable(value) for value in values)


def task_json_row(row: TaskRow) -> str:
    document = {
        "tenant": row.tenant,
        "task": row.task,
        "principal": row.principal,
        "roots": sorted(row.roots),
        "first": row.first,
        "last": row.last,
        "allows": row.allows,
        "releases": row.releases,
        "refusals": row.refusals,
        "revoked_by": row.revoked_by,
        "record_line": row.record_line,
        "record": row.record,
    }
    return json.dumps(document, sort_keys=True)
