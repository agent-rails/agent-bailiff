from __future__ import annotations

import binascii
import json
from dataclasses import dataclass, field, replace

from agent_warrant.encoding import b64u_decode
from agent_warrant.exceptions import UnresolvableIssuer
from agent_warrant.resolver import IssuerResolver
from agent_warrant.scope import Permission, entry_covers
from agent_warrant.task_root import TaskRoot
from agent_warrant.trust import IssuerTrustPolicy
from cryptography.exceptions import InvalidSignature

from agent_bailiff.docket.entry import Entry
from agent_bailiff.docket.grant import Grant
from agent_bailiff.docket.report import printable
from agent_bailiff.docket.sink import VerifiedLine
from agent_bailiff.signing import Refused

GRANTED = "granted"
UNGRANTED = "ungranted"
INVALID_GRANT = "invalid_grant"
MALFORMED = "malformed"
UNKNOWN_ISSUER = "unknown_issuer"
BAD_SIGNATURE = "bad_signature"
ISSUER_NOT_ALLOWED = "issuer_not_allowed"
NEGATIVE = "negative"
AFTER_EXPIRY = "after_expiry"
DUPLICATE_ROOTS = "duplicate_roots"
PAIRS_TRUNCATED = "pairs_truncated"
COST_INEXACT = "cost_inexact"
WILDCARD_NAMES_CAP = 20
MAX_PAIRS_PER_ROOT = 4096
MAX_OPS_PER_ROOT = 65536
CONTROL_HOP = "control"
DECIDE_HOP = "decide"
GRANT_COLUMNS = ("tenant", "task", "root", "status", "reason", "unused", "wildcards", "cost", "ttl", "flags")


@dataclass(frozen=True)
class WildcardUse:
    permission: int
    kind: str
    pattern: str
    used: tuple[str, ...]
    truncated: int


@dataclass(frozen=True)
class UnusedPair:
    permission: int
    tool: str
    resource: str


@dataclass(frozen=True)
class GrantRow:
    status: str
    tenant: str | None
    task: str | None
    root: str | None
    reason: str | None = None
    detail: str | None = None
    issuer: str | None = None
    grant_id: str | None = None
    grant_line: int | None = None
    grant_records: int = 0
    unused: tuple[UnusedPair, ...] = ()
    wildcards: tuple[WildcardUse, ...] = ()
    pairs_truncated: int = 0
    budget: int | None = None
    authorized_cost: int = 0
    authorized_cost_exact: bool = True
    allows: int = 0
    ttl: int | None = None
    ttl_used: int | None = None
    ttl_flags: tuple[str, ...] = ()
    duplicate_roots: tuple[str, ...] = ()


@dataclass
class RootUse:
    tenant: str
    task: str
    root: TaskRoot | None = None
    grant_id: str | None = None
    grant_line: int | None = None
    grant_records: int = 0
    pairs: set[tuple[str, str]] = field(default_factory=set)
    pairs_truncated: int = 0
    ops: set[str] = field(default_factory=set)
    authorized_cost: int = 0
    authorized_cost_exact: bool = True
    allows: int = 0
    first_use: int | None = None
    last_use: int | None = None

    def add_allow(self, entry: Entry, line: int) -> None:
        if entry.op_id is None or entry.cost is None or entry.tool is None or entry.resource is None:
            raise ValueError(f"the decide allow on line {line} lacks an op_id, cost, tool or resource")
        if entry.op_id in self.ops:
            return
        if len(self.ops) < MAX_OPS_PER_ROOT:
            self.ops.add(entry.op_id)
        else:
            self.authorized_cost_exact = False
        self.allows += 1
        self.authorized_cost += entry.cost
        self.first_use = entry.at if self.first_use is None else min(self.first_use, entry.at)
        self.last_use = entry.at if self.last_use is None else max(self.last_use, entry.at)
        pair = (entry.tool, entry.resource)
        if pair in self.pairs:
            return
        if len(self.pairs) < MAX_PAIRS_PER_ROOT:
            self.pairs.add(pair)
        else:
            self.pairs_truncated += 1


class GrantReport:
    def __init__(self, resolver: IssuerResolver, trust_policy: IssuerTrustPolicy) -> None:
        self._resolver = resolver
        self._trust_policy = trust_policy
        self._roots: dict[str, RootUse] = {}
        self._granted: dict[tuple[str, str], set[str]] = {}
        self._invalid: list[GrantRow] = []

    def add(self, verified: VerifiedLine) -> None:
        entry = verified.record.entry
        if isinstance(entry, Grant):
            self._add_grant(entry, verified.line)
            return
        if entry.hop == CONTROL_HOP:
            return
        binding, tenant, task = (entry.handles.get(level) for level in ("root", "tenant", "task"))
        if binding is None or tenant is None or task is None:
            return
        use = self._roots.get(binding)
        if use is None:
            use = self._roots[binding] = RootUse(tenant, task)
        if entry.hop == DECIDE_HOP and entry.decision == "allow":
            use.add_allow(entry, verified.line)

    def rows(self) -> list[GrantRow]:
        rows = [self._row(binding, use) for binding, use in self._roots.items()] + self._invalid
        return sorted(rows, key=lambda row: (row.tenant or "", row.task or "", row.root or "", row.grant_line or 0))

    def _add_grant(self, grant: Grant, line: int) -> None:
        root = decode_grant_root(grant.root_token)
        if isinstance(root, Refused):
            self._invalid.append(_invalid_row(grant, line, None, root))
            return
        refusal = check_grant_root(root, self._resolver, self._trust_policy)
        if refusal is not None:
            self._invalid.append(_invalid_row(grant, line, root, refusal))
            return
        binding = root.binding()
        use = self._roots.get(binding)
        if use is None:
            use = self._roots[binding] = RootUse(root.tenant_id, root.task_id)
        use.grant_records += 1
        if use.root is None:
            use.tenant, use.task = root.tenant_id, root.task_id
            use.root, use.grant_id, use.grant_line = root, grant.grant_id, line
            self._granted.setdefault((root.tenant_id, root.task_id), set()).add(binding)

    def _row(self, binding: str, use: RootUse) -> GrantRow:
        usage = GrantRow(
            UNGRANTED,
            use.tenant,
            use.task,
            binding,
            pairs_truncated=use.pairs_truncated,
            authorized_cost=use.authorized_cost,
            authorized_cost_exact=use.authorized_cost_exact,
            allows=use.allows,
        )
        root = use.root
        if root is None:
            return usage
        flags = []
        if use.first_use is not None and use.first_use < root.issued_at:
            flags.append(NEGATIVE)
        if use.last_use is not None and use.last_use >= root.expires_at:
            flags.append(AFTER_EXPIRY)
        return replace(
            usage,
            status=GRANTED,
            issuer=root.issuer,
            grant_id=use.grant_id,
            grant_line=use.grant_line,
            grant_records=use.grant_records,
            unused=_unused(root.permissions, use.pairs),
            wildcards=_wildcards(root.permissions, use.pairs),
            budget=root.budget,
            ttl=root.expires_at - root.issued_at,
            ttl_used=None if use.last_use is None else use.last_use - root.issued_at,
            ttl_flags=tuple(flags),
            duplicate_roots=tuple(sorted(self._granted[(use.tenant, use.task)] - {binding})),
        )


def decode_grant_root(token: str) -> TaskRoot | Refused:
    try:
        return TaskRoot.decode(token)
    except (ValueError, TypeError) as exc:
        return Refused(MALFORMED, str(exc))


def check_grant_root(root: TaskRoot, resolver: IssuerResolver, trust_policy: IssuerTrustPolicy) -> Refused | None:
    refusal = trust_policy.check_issuer(root.issuer)
    if refusal is not None:
        return Refused(UNKNOWN_ISSUER, refusal)
    try:
        key = resolver.resolve(root.issuer)
    except UnresolvableIssuer as exc:
        return Refused(UNKNOWN_ISSUER, str(exc))
    try:
        key.verify(b64u_decode(root.proof), root.signing_bytes())
    except (InvalidSignature, ValueError, binascii.Error):
        return Refused(BAD_SIGNATURE, "the issuer signature does not verify")
    refusal = trust_policy.check_claims(root)
    return None if refusal is None else Refused(ISSUER_NOT_ALLOWED, refusal)


def _invalid_row(grant: Grant, line: int, root: TaskRoot | None, refusal: Refused) -> GrantRow:
    return GrantRow(
        INVALID_GRANT,
        None if root is None else root.tenant_id,
        None if root is None else root.task_id,
        None if root is None else root.binding(),
        reason=refusal.reason,
        detail=refusal.detail,
        issuer=None if root is None else root.issuer,
        grant_id=grant.grant_id,
        grant_line=line,
        grant_records=1,
    )


def _covered(permission: Permission, pairs: set[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(tool, resource) for tool, resource in pairs if permission.covers(tool, resource)]


def _unused(permissions: tuple[Permission, ...], pairs: set[tuple[str, str]]) -> tuple[UnusedPair, ...]:
    unused = []
    for index, permission in enumerate(permissions):
        covered = _covered(permission, pairs)
        for tool in permission.tools:
            for resource in permission.resources:
                if not any(entry_covers(tool, name) and entry_covers(resource, used) for name, used in covered):
                    unused.append(UnusedPair(index, tool, resource))
    return tuple(unused)


def _wildcards(permissions: tuple[Permission, ...], pairs: set[tuple[str, str]]) -> tuple[WildcardUse, ...]:
    wildcards = []
    for index, permission in enumerate(permissions):
        covered = _covered(permission, pairs)
        for kind, patterns, position in (("tool", permission.tools, 0), ("resource", permission.resources, 1)):
            for pattern in patterns:
                if not pattern.endswith("*"):
                    continue
                names = sorted({pair[position] for pair in covered if entry_covers(pattern, pair[position])})
                truncated = max(0, len(names) - WILDCARD_NAMES_CAP)
                wildcards.append(WildcardUse(index, kind, pattern, tuple(names[:WILDCARD_NAMES_CAP]), truncated))
    return tuple(wildcards)


def grant_header() -> str:
    return "\t".join(column.upper() for column in GRANT_COLUMNS)


def grant_table_row(row: GrantRow) -> str:
    cost = str(row.authorized_cost) if row.budget is None else f"{row.authorized_cost}/{row.budget}"
    ttl = None if row.ttl is None else f"{'-' if row.ttl_used is None else row.ttl_used}/{row.ttl}"
    flags = [*row.ttl_flags]
    flags += [DUPLICATE_ROOTS] if row.duplicate_roots else []
    flags += [PAIRS_TRUNCATED] if row.pairs_truncated else []
    flags += [] if row.authorized_cost_exact else [COST_INEXACT]
    values = (
        row.tenant,
        row.task,
        row.root,
        row.status,
        row.reason,
        str(len(row.unused)),
        str(len(row.wildcards)),
        cost,
        ttl,
        ",".join(flags) or None,
    )
    return "\t".join(printable(value) for value in values)


def grant_json_row(row: GrantRow) -> str:
    document = {
        "status": row.status,
        "reason": row.reason,
        "detail": row.detail,
        "tenant": row.tenant,
        "task": row.task,
        "root": row.root,
        "issuer": row.issuer,
        "grant_id": row.grant_id,
        "grant_line": row.grant_line,
        "grant_records": row.grant_records,
        "unused": [
            {"permission": pair.permission, "tool": pair.tool, "resource": pair.resource} for pair in row.unused
        ],
        "wildcards": [
            {
                "permission": wildcard.permission,
                "kind": wildcard.kind,
                "pattern": wildcard.pattern,
                "used": list(wildcard.used),
                "truncated": wildcard.truncated,
            }
            for wildcard in row.wildcards
        ],
        "pairs_truncated": row.pairs_truncated,
        "budget": row.budget,
        "authorized_cost": row.authorized_cost,
        "authorized_cost_exact": row.authorized_cost_exact,
        "allows": row.allows,
        "ttl": row.ttl,
        "ttl_used": row.ttl_used,
        "ttl_flags": list(row.ttl_flags),
        "duplicate_roots": list(row.duplicate_roots),
    }
    return json.dumps(document, sort_keys=True)
