from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

from agent_warrant.canonical import MAX_SAFE_INTEGER
from agent_warrant.encoding import b64u_decode
from agent_warrant.exceptions import UnresolvableIssuer
from agent_warrant.ledger import LedgerError
from agent_warrant.resolver import IssuerResolver
from agent_warrant.task_root import TaskRoot
from agent_warrant.trust import IssuerTrustPolicy
from cryptography.exceptions import InvalidSignature

from agent_bailiff.control.suspension import SuspensionError
from agent_bailiff.decide.decider import DocketWriter
from agent_bailiff.docket.entry import Entry, Record, decode_record
from agent_bailiff.docket.grant import Grant
from agent_bailiff.docket.sink import Writers, build_kid_index
from agent_bailiff.signing import Refused

HOP = "control"
LEVELS = ("link", "task", "tenant", "root")
MAX_ACTOR_CHARACTERS = 128


class RevocationWriter(Protocol):
    def revoke(self, binding: str, now: int) -> None: ...

    def revoke_task(self, tenant_id: str, task_id: str, now: int) -> None: ...

    def revoke_tenant(self, tenant_id: str, now: int) -> None: ...


class SuspensionSwitch(Protocol):
    def suspend(self, record: Mapping[str, Any]) -> bool: ...

    def resume(self) -> bool: ...


@dataclass(frozen=True)
class Outcome:
    action: str
    reason: str
    trace_id: str
    entry_id: str
    handles: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _Origin:
    trace_id: str
    parent_entry: str
    op_id: str | None
    tenant: str | None


class ControlRefused(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class ControlUnrecorded(Exception):
    def __init__(self, outcome: Outcome) -> None:
        super().__init__(f"{outcome.action} was applied but its docket entry was not acknowledged")
        self.outcome = outcome


class Control:
    def __init__(
        self,
        component: str,
        writers: Writers,
        ledger: RevocationWriter,
        suspension: SuspensionSwitch,
        docket: DocketWriter,
        docket_writer: str,
        *,
        resolver: IssuerResolver,
        trust_policy: IssuerTrustPolicy,
        grant_writers: Iterable[str] = (),
    ) -> None:
        for name, value in (("component", component), ("docket_writer", docket_writer)):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty str")
        if not writers:
            raise ValueError("writers must pin at least one docket writer")
        if docket_writer in writers:
            raise ValueError("control must not accept records from its own docket writer")
        self._component = component
        self._index = build_kid_index(writers, grant_writers)
        self._resolver = resolver
        self._trust_policy = trust_policy
        self._ledger = ledger
        self._suspension = suspension
        self._docket = docket
        self._docket_writer = docket_writer

    def revoke(self, record_token: object, level: object, actor: object, now: int) -> Outcome:
        _check_now(now)
        source = self._verified(record_token)
        actor_name = _actor(actor)
        if level not in LEVELS:
            raise ControlRefused("unknown_level", f"level must be one of {', '.join(LEVELS)}")
        if isinstance(source, Grant):
            origin, handles = self._grant_target(source, str(level))
        else:
            origin, handles = _origin(source), _revocation_handles(source, str(level))
        try:
            self._apply_revocation(handles, now)
        except LedgerError as exc:
            raise ControlRefused("ledger_unavailable", str(exc)) from None
        except ValueError as exc:
            raise ControlRefused("invalid_handle", str(exc)) from None
        entry = self._entry(origin, "revoke", str(level), actor_name, now, handles)
        return self._record(entry)

    def suspend(self, record_token: object, actor: object, now: int) -> Outcome:
        _check_now(now)
        source = self._verified(record_token)
        if isinstance(source, Grant):
            raise ControlRefused("record_not_suspendable", "a grant joins no trace; suspend from an entry")
        actor_name = _actor(actor)
        state = {"actor": actor_name, "at": now, "trace_id": source.trace_id, "entry_id": source.entry_id}
        try:
            changed = self._suspension.suspend(state)
        except (SuspensionError, OSError) as exc:
            raise ControlRefused("suspension_unavailable", str(exc)) from None
        reason = "suspended" if changed else "already_suspended"
        return self._record(self._entry(_origin(source), "suspend", reason, actor_name, now, {}))

    def resume(self, actor: object, now: int) -> Outcome:
        _check_now(now)
        actor_name = _actor(actor)
        try:
            changed = self._suspension.resume()
        except (SuspensionError, OSError) as exc:
            raise ControlRefused("suspension_unavailable", str(exc)) from None
        entry = Entry(
            entry_id=uuid.uuid4().hex,
            trace_id=uuid.uuid4().hex,
            hop=HOP,
            component=self._component,
            decision="resume",
            at=now,
            principal=actor_name,
            reason="resumed" if changed else "not_suspended",
        )
        return self._record(entry)

    def _verified(self, record_token: object) -> Entry | Grant:
        if not isinstance(record_token, str):
            raise ControlRefused("record_malformed", "record must be a str")
        record = decode_record(record_token, self._index)
        if isinstance(record, Refused):
            raise ControlRefused(f"record_{record.reason}", record.detail)
        return record.entry

    def _grant_target(self, grant: Grant, level: str) -> tuple[_Origin, dict[str, str]]:
        if level == "link":
            raise ControlRefused("no_handle", "a grant has no link handle; revoke a link from an entry")
        root = self._trusted_root(grant)
        if level == "task":
            handles = {"tenant": root.tenant_id, "task": root.task_id}
        elif level == "tenant":
            handles = {"tenant": root.tenant_id}
        else:
            handles = {"root": root.binding()}
        return _Origin(grant.grant_id, grant.grant_id, None, root.tenant_id), handles

    def _trusted_root(self, grant: Grant) -> TaskRoot:
        try:
            root = TaskRoot.decode(grant.root_token)
        except (ValueError, TypeError) as exc:
            raise ControlRefused("record_invalid_field", f"the grant's task root does not decode: {exc}") from None
        refusal = self._trust_policy.check_issuer(root.issuer)
        if refusal is not None:
            raise ControlRefused("root_unknown_issuer", refusal)
        try:
            key = self._resolver.resolve(root.issuer)
        except UnresolvableIssuer as exc:
            raise ControlRefused("root_unknown_issuer", str(exc)) from None
        try:
            key.verify(b64u_decode(root.proof), root.signing_bytes())
        except (InvalidSignature, ValueError):
            raise ControlRefused("root_bad_signature", f"issuer {root.issuer!r} did not sign the task root") from None
        refusal = self._trust_policy.check_claims(root)
        if refusal is not None:
            raise ControlRefused("root_not_allowed", refusal)
        return root

    def _apply_revocation(self, handles: Mapping[str, str], now: int) -> None:
        if "task" in handles:
            self._ledger.revoke_task(handles["tenant"], handles["task"], now)
        elif "tenant" in handles:
            self._ledger.revoke_tenant(handles["tenant"], now)
        else:
            binding = handles.get("link") or handles["root"]
            self._ledger.revoke(binding, now)

    def _entry(
        self, origin: _Origin, action: str, reason: str, actor: str, now: int, handles: Mapping[str, str]
    ) -> Entry:
        return Entry(
            entry_id=uuid.uuid4().hex,
            trace_id=origin.trace_id,
            hop=HOP,
            component=self._component,
            decision=action,
            at=now,
            op_id=origin.op_id,
            parent_entry=origin.parent_entry,
            principal=actor,
            tenant=origin.tenant,
            reason=reason,
            handles=dict(handles),
        )

    def _record(self, entry: Entry) -> Outcome:
        outcome = Outcome(
            action=entry.decision,
            reason=entry.reason or "",
            trace_id=entry.trace_id,
            entry_id=entry.entry_id,
            handles=MappingProxyType(dict(entry.handles)),
        )
        try:
            record = self._docket.append(entry)
        except Exception:
            raise ControlUnrecorded(outcome) from None
        if not (
            isinstance(record, Record)
            and record.entry == entry
            and record.writer == self._docket_writer
            and isinstance(record.token, str)
            and bool(record.token)
        ):
            raise ControlUnrecorded(outcome)
        return outcome


def _origin(source: Entry) -> _Origin:
    return _Origin(source.trace_id, source.entry_id, source.op_id, source.tenant)


def _revocation_handles(source: Entry, level: str) -> dict[str, str]:
    names = ("tenant", "task") if level == "task" else (level,)
    handles = _require(source.handles, names)
    if "tenant" in handles and handles["tenant"] != source.tenant:
        raise ControlRefused("handle_mismatch", "the record's tenant handle does not match its tenant")
    return handles


def _require(handles: Mapping[str, str], names: tuple[str, ...]) -> dict[str, str]:
    missing = [name for name in names if name not in handles]
    if missing:
        raise ControlRefused("no_handle", f"the record has no {', '.join(missing)} handle")
    return {name: handles[name] for name in names}


def _actor(actor: object) -> str:
    if (
        not isinstance(actor, str)
        or not 0 < len(actor) <= MAX_ACTOR_CHARACTERS
        or not all("!" <= character <= "~" for character in actor)
    ):
        raise ControlRefused(
            "invalid_actor", f"actor must be 1 to {MAX_ACTOR_CHARACTERS} ASCII printable characters without spaces"
        )
    return actor


def _check_now(now: object) -> None:
    if isinstance(now, bool) or not isinstance(now, int) or not 0 <= now <= MAX_SAFE_INTEGER:
        raise ValueError(f"now must be an integer between 0 and {MAX_SAFE_INTEGER}")
