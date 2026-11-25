from __future__ import annotations

import json
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from agent_warrant.resolver import IssuerResolver
from agent_warrant.task_root import TaskRoot
from agent_warrant.trust import IssuerTrustPolicy

from agent_bailiff.docket.grant import Grant
from agent_bailiff.docket.grants import check_grant_root
from agent_bailiff.docket.report import grant_root, printable, utc
from agent_bailiff.docket.roles import WriterRoles
from agent_bailiff.docket.sink import VerifiedLine
from agent_bailiff.signing import Refused

CONTROL_HOP = "control"
CUSTODIAN_HOP = "custodian"
DECIDE_HOP = "decide"
TASK_HOPS = (DECIDE_HOP, CUSTODIAN_HOP, CONTROL_HOP)
VERIFIED = "verified"
UNVERIFIED = "unverified"
INVALID = "invalid"
TASK_COLUMNS = ("tenant", "task", "root", "principal", "first", "last", "allows", "releases", "refusals", "state")
MAX_TRACKED_BYTES = 1 << 30
ROW_BYTES = 1024
KEY_BYTES = 256


@dataclass
class TaskRow:
    tenant: str
    task: str
    principal: str | None = None
    principal_conflict: bool = False
    roots: set[str] = field(default_factory=set)
    root_status: str = UNVERIFIED
    root_reason: str | None = None
    invalid_grants: int = 0
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
    def __init__(self, roles: WriterRoles, resolver: IssuerResolver, trust_policy: IssuerTrustPolicy) -> None:
        missing = [hop for hop in TASK_HOPS if not roles.reads(hop)]
        if missing:
            raise ValueError(f"no writer is pinned for hop {missing[0]}")
        self._roles = roles
        self._resolver = resolver
        self._trust_policy = trust_policy
        self._rows: dict[tuple[str, str], TaskRow] = {}
        self._revoked_tasks: dict[tuple[str, str], str] = {}
        self._revoked_roots: dict[str, str] = {}
        self._revoked_tenants: dict[str, str] = {}
        self._tracked = 0
        self.undecodable_grants = 0
        self.role_mismatches = 0

    def add(self, verified: VerifiedLine) -> None:
        entry = verified.record.entry
        if isinstance(entry, Grant):
            self._add_grant(verified, entry)
            return
        if not self._roles.reads(entry.hop):
            return
        if not self._roles.holds(verified.record.writer, entry.hop):
            self.role_mismatches += 1
            return
        if entry.hop == CONTROL_HOP:
            if entry.decision == "revoke":
                self._add_revocation(entry.entry_id, entry.handles, verified.line)
            return
        tenant, task = entry.handles.get("tenant"), entry.handles.get("task")
        if tenant is None or task is None:
            return
        row = self._row(tenant, task, entry.at, verified.line)
        if entry.decision == "refuse":
            row.refusals += 1
        elif entry.decision == "allow" and entry.hop == CUSTODIAN_HOP:
            row.releases += 1
        elif entry.decision == "allow":
            row.allows += 1
        if entry.hop != DECIDE_HOP:
            return
        if "root" in entry.handles:
            self._add_root(row, entry.handles["root"], verified.line)
        if entry.tenant == tenant and entry.principal is not None:
            self._set_source(row, entry.principal, verified)

    def _add_grant(self, verified: VerifiedLine, grant: Grant) -> None:
        root = grant_root(grant)
        if root is None:
            self.undecodable_grants += 1
            return
        row = self._row(root.tenant_id, root.task_id, grant.at, verified.line)
        self._add_root(row, root.binding(), verified.line)
        refusal = check_grant_root(root, self._resolver, self._trust_policy)
        if refusal is None:
            self._accept_grant(row, root, verified)
        else:
            self._reject_grant(row, refusal)

    def _accept_grant(self, row: TaskRow, root: TaskRoot, verified: VerifiedLine) -> None:
        row.root_status, row.root_reason = VERIFIED, None
        row.granted = True
        row.expires_at = max(row.expires_at or 0, root.expires_at)
        if row.record is None:
            self._set_record(row, verified)

    def _reject_grant(self, row: TaskRow, refusal: Refused) -> None:
        row.invalid_grants += 1
        if row.root_status == UNVERIFIED:
            row.root_status, row.root_reason = INVALID, refusal.reason

    def _row(self, tenant: str, task: str, at: int, line: int) -> TaskRow:
        row = self._rows.get((tenant, task))
        if row is None:
            self._charge(ROW_BYTES + text_bytes(tenant) + text_bytes(task), line)
            row = self._rows[(tenant, task)] = TaskRow(tenant, task, first=at)
        row.first, row.last = min(row.first, at), max(row.last, at)
        return row

    def rows(self) -> list[TaskRow]:
        rows = sorted(self._rows.values(), key=lambda row: (row.last, row.tenant, row.task))
        for row in rows:
            row.revoked_by = self._revoked_by(row)
        return rows

    def _set_source(self, row: TaskRow, principal: str, verified: VerifiedLine) -> None:
        if row.principal is not None and row.principal != principal:
            row.principal_conflict = True
        self._charge(text_bytes(principal) - text_bytes(row.principal), verified.line)
        row.principal = principal
        self._set_record(row, verified)

    def _add_root(self, row: TaskRow, root: str, line: int) -> None:
        if root in row.roots:
            return
        self._charge(KEY_BYTES + text_bytes(root), line)
        row.roots.add(root)

    def _set_record(self, row: TaskRow, verified: VerifiedLine) -> None:
        self._charge(text_bytes(verified.record.token) - text_bytes(row.record), verified.line)
        row.record, row.record_line = verified.record.token, verified.line

    def _add_revocation(self, entry_id: str, handles: Mapping[str, str], line: int) -> None:
        if "task" in handles and "tenant" in handles:
            key = (handles["tenant"], handles["task"])
            if key not in self._revoked_tasks:
                self._charge(KEY_BYTES + text_bytes(entry_id) + text_bytes(key[0]) + text_bytes(key[1]), line)
                self._revoked_tasks[key] = entry_id
        elif "root" in handles:
            if handles["root"] not in self._revoked_roots:
                self._charge(KEY_BYTES + text_bytes(entry_id) + text_bytes(handles["root"]), line)
                self._revoked_roots[handles["root"]] = entry_id
        elif "tenant" in handles and "link" not in handles:
            if handles["tenant"] not in self._revoked_tenants:
                self._charge(KEY_BYTES + text_bytes(entry_id) + text_bytes(handles["tenant"]), line)
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


def text_bytes(text: str | None) -> int:
    return 0 if text is None else sys.getsizeof(text)


def task_header() -> str:
    return "\t".join(column.upper() for column in TASK_COLUMNS)


def task_table_row(row: TaskRow) -> str:
    values = (
        row.tenant,
        row.task,
        row.root_status,
        row.principal,
        utc(row.first),
        utc(row.last),
        str(row.allows),
        str(row.releases),
        str(row.refusals),
        "revoked" if row.revoked_by else "-",
    )
    return "\t".join(printable(value) for value in values)


def task_json_chunks(row: TaskRow) -> Iterator[str]:
    document = {
        "tenant": row.tenant,
        "task": row.task,
        "principal": row.principal,
        "principal_conflict": row.principal_conflict,
        "roots": sorted(row.roots),
        "root_status": row.root_status,
        "root_reason": row.root_reason,
        "invalid_grants": row.invalid_grants,
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
    return json.JSONEncoder(sort_keys=True).iterencode(document)
