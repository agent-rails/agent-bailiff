from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from agent_bailiff.docket.grant import Grant
from agent_bailiff.docket.report import grant_root, printable, utc
from agent_bailiff.docket.sink import VerifiedLine

CONTROL_HOP = "control"
DECIDE_HOP = "decide"
TASK_COLUMNS = ("tenant", "task", "principal", "first", "last", "allows", "releases", "refusals", "state")
MAX_TRACKED_BYTES = 1 << 30
ROW_BYTES = 1024
KEY_BYTES = 256


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
    granted: bool = False
    expires_at: int | None = None
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
        self._tracked = 0
        self.undecodable_grants = 0

    def add(self, verified: VerifiedLine) -> None:
        entry = verified.record.entry
        if isinstance(entry, Grant):
            self._add_grant(verified, entry)
            return
        if entry.hop == CONTROL_HOP:
            if entry.decision == "revoke" and verified.record.writer in self._control_writers:
                self._add_revocation(entry.entry_id, entry.handles, verified.line)
            return
        tenant, task = entry.handles.get("tenant"), entry.handles.get("task")
        if tenant is None or task is None:
            return
        row = self._row(tenant, task, entry.at, verified.line)
        self._set_principal(row, entry.principal or row.principal, verified.line)
        if "root" in entry.handles:
            self._add_root(row, entry.handles["root"], verified.line)
        if entry.decision == "refuse":
            row.refusals += 1
        elif entry.decision == "allow" and entry.hop == "custodian":
            row.releases += 1
        elif entry.decision == "allow":
            row.allows += 1
        if entry.hop == DECIDE_HOP and entry.tenant == tenant:
            self._set_record(row, verified)

    def _add_grant(self, verified: VerifiedLine, grant: Grant) -> None:
        root = grant_root(grant)
        if root is None:
            self.undecodable_grants += 1
            return
        row = self._row(root.tenant_id, root.task_id, grant.at, verified.line)
        row.granted = True
        self._set_principal(row, row.principal or root.principal, verified.line)
        self._add_root(row, root.binding(), verified.line)
        row.expires_at = max(row.expires_at or 0, root.expires_at)
        if row.record is None:
            self._set_record(row, verified)

    def _row(self, tenant: str, task: str, at: int, line: int) -> TaskRow:
        row = self._rows.get((tenant, task))
        if row is None:
            self._charge(ROW_BYTES + len(tenant) + len(task), line)
            row = self._rows[(tenant, task)] = TaskRow(tenant, task, first=at)
        row.first, row.last = min(row.first, at), max(row.last, at)
        return row

    def rows(self) -> list[TaskRow]:
        rows = sorted(self._rows.values(), key=lambda row: (row.last, row.tenant, row.task))
        for row in rows:
            row.revoked_by = self._revoked_by(row)
        return rows

    def _set_principal(self, row: TaskRow, principal: str | None, line: int) -> None:
        self._charge(len(principal or "") - len(row.principal or ""), line)
        row.principal = principal

    def _add_root(self, row: TaskRow, root: str, line: int) -> None:
        if root in row.roots:
            return
        self._charge(KEY_BYTES + len(root), line)
        row.roots.add(root)

    def _set_record(self, row: TaskRow, verified: VerifiedLine) -> None:
        self._charge(len(verified.record.token) - len(row.record or ""), verified.line)
        row.record, row.record_line = verified.record.token, verified.line

    def _add_revocation(self, entry_id: str, handles: Mapping[str, str], line: int) -> None:
        if "task" in handles and "tenant" in handles:
            key = (handles["tenant"], handles["task"])
            if key not in self._revoked_tasks:
                self._charge(KEY_BYTES + len(entry_id) + len(key[0]) + len(key[1]), line)
                self._revoked_tasks[key] = entry_id
        elif "root" in handles:
            if handles["root"] not in self._revoked_roots:
                self._charge(KEY_BYTES + len(entry_id) + len(handles["root"]), line)
                self._revoked_roots[handles["root"]] = entry_id
        elif "tenant" in handles and "link" not in handles:
            if handles["tenant"] not in self._revoked_tenants:
                self._charge(KEY_BYTES + len(entry_id) + len(handles["tenant"]), line)
                self._revoked_tenants[handles["tenant"]] = entry_id

    def _charge(self, size: int, line: int) -> None:
        if self._tracked + size > MAX_TRACKED_BYTES:
            raise ValueError(
                f"the report tracks at most {MAX_TRACKED_BYTES} bytes of task state and line {line} adds more"
            )
        self._tracked += size

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
        "granted": row.granted,
        "expires_at": row.expires_at,
        "revoked_by": row.revoked_by,
        "record_line": row.record_line,
        "record": row.record,
    }
    return json.dumps(document, sort_keys=True)
