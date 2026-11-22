from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from agent_bailiff.docket.report import printable, utc
from agent_bailiff.docket.sink import VerifiedLine

CONTROL_HOP = "control"
DECIDE_HOP = "decide"
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
    def __init__(self, control_writers: frozenset[str]) -> None:
        if not control_writers:
            raise ValueError("at least one control writer is required")
        self._control_writers = control_writers
        self._rows: dict[tuple[str, str], TaskRow] = {}
        self._revoked_tasks: dict[tuple[str, str], str] = {}
        self._revoked_roots: dict[str, str] = {}
        self._revoked_tenants: dict[str, str] = {}

    def add(self, verified: VerifiedLine) -> None:
        entry = verified.record.entry
        if entry.hop == CONTROL_HOP:
            if entry.decision == "revoke" and verified.record.writer in self._control_writers:
                self._add_revocation(entry.entry_id, entry.handles)
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
        if entry.hop == DECIDE_HOP and entry.tenant == tenant:
            row.record, row.record_line = verified.record.token, verified.line

    def rows(self) -> list[TaskRow]:
        rows = sorted(self._rows.values(), key=lambda row: (row.last, row.tenant, row.task))
        for row in rows:
            row.revoked_by = self._revoked_by(row)
        return rows

    def _add_revocation(self, entry_id: str, handles: Mapping[str, str]) -> None:
        if "task" in handles and "tenant" in handles:
            self._revoked_tasks.setdefault((handles["tenant"], handles["task"]), entry_id)
        elif "root" in handles:
            self._revoked_roots.setdefault(handles["root"], entry_id)
        elif "tenant" in handles and "link" not in handles:
            self._revoked_tenants.setdefault(handles["tenant"], entry_id)

    def _revoked_by(self, row: TaskRow) -> str | None:
        task = self._revoked_tasks.get((row.tenant, row.task))
        if task is not None:
            return task
        root = next((self._revoked_roots[root] for root in sorted(row.roots) if root in self._revoked_roots), None)
        return root if root is not None else self._revoked_tenants.get(row.tenant)


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
