from __future__ import annotations

import hashlib
import logging
import threading
import uuid
from dataclasses import dataclass, replace
from typing import Any, Protocol

from agent_guard.audit import MemoryAuditSink
from agent_guard.decision import Decision as PolicyDecision
from agent_guard.guard import Guard
from agent_warrant.chain import ChainLink, verify_chain
from agent_warrant.ledger import LedgerUnavailable, Operation, TaskLedger
from agent_warrant.ledger import Refused as LedgerRefused
from agent_warrant.resolver import IssuerResolver
from agent_warrant.scope import covers
from agent_warrant.task_root import TaskRoot, TaskRootResult
from agent_warrant.trust import IssuerTrustPolicy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.decide.clearance import Clearance, encode_clearance
from agent_bailiff.decide.config import DeciderConfig, PolicyRef
from agent_bailiff.decide.costs import CostError, CostTable
from agent_bailiff.decide.identity import ArgsError, ArgsSnapshot, derive_op_id, request_digest, snapshot_args
from agent_bailiff.decide.refusals import RefusalBudget, capped_reason
from agent_bailiff.decide.request import OperationRequest
from agent_bailiff.docket.client import UNACKNOWLEDGED, DocketError
from agent_bailiff.docket.entry import Entry, Record
from agent_bailiff.scope_pattern import is_bounded
from agent_bailiff.signing import token_hash

HOP = "decide"
MAX_RECONCILE_BATCH = 100
MAX_TRACE_ID_CHARACTERS = 128
OUTCOMES = frozenset({"done", "outcome_unknown"})

logger = logging.getLogger(__name__)


class SuspensionCheck(Protocol):
    @property
    def suspended(self) -> bool: ...


class DocketWriter(Protocol):
    def append(self, entry: Entry) -> Record: ...


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    clearance: str | None = None
    entry_id: str | None = None
    op_id: str | None = None


@dataclass(frozen=True)
class _Issued:
    tenant: str
    task: str
    exp: int
    entry: Entry


class _Refusal(Exception):
    def __init__(self, reason: str, entry: Entry) -> None:
        super().__init__(reason)
        self.reason = reason
        self.entry = entry


class Decider:
    def __init__(
        self,
        config: DeciderConfig,
        ledger: TaskLedger,
        resolver: IssuerResolver,
        trust_policy: IssuerTrustPolicy,
        policy: PolicyRef,
        suspension: SuspensionCheck,
        docket: DocketWriter,
        signing_key: Ed25519PrivateKey,
        costs: CostTable,
        refusal_budget: RefusalBudget | None = None,
    ) -> None:
        self._config = config
        self._ledger = ledger
        self._resolver = resolver
        self._trust_policy = trust_policy
        self._policy = policy
        self._suspension = suspension
        self._docket = docket
        self._signing_key = signing_key
        self._costs = costs
        self._refusal_budget = refusal_budget or RefusalBudget()
        self._issued: dict[str, _Issued] = {}
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()

    def check(self, request: OperationRequest, now: int) -> Decision:
        entry = Entry(
            entry_id=HOP,
            trace_id=_trace_id(getattr(request, "trace_id", None)),
            hop=HOP,
            component=self._config.decider_id,
            decision="refuse",
            at=now if isinstance(now, int) and not isinstance(now, bool) and now >= 0 else 0,
        )
        try:
            return self._check(request, now, entry)
        except _Refusal as refusal:
            return self._refuse(refusal.reason, refusal.entry)
        except Exception:
            logger.exception("decide failed with an internal error")
            return self._refuse("internal_error", entry)

    def record_outcome(self, op_id: str, outcome: str, receipt_digest: str | None = None, *, now: int) -> str:
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {', '.join(sorted(OUTCOMES))}")
        with self._lock:
            issued = self._issued.get(op_id)
        if issued is None:
            raise ValueError("op_id has no issued clearance in this decider")
        if outcome == "done":
            self._ledger.mark_done(issued.tenant, issued.task, op_id, now)
        else:
            self._ledger.mark_outcome_unknown(issued.tenant, issued.task, op_id, now)
        with self._lock:
            self._issued.pop(op_id, None)
        return self._append(
            replace(
                issued.entry,
                decision="outcome",
                at=now,
                performed=outcome == "done",
                outcome=outcome,
                receipt_digest=receipt_digest,
                reason=None,
            )
        )

    def reconcile(self, now: int) -> tuple[str, ...]:
        with self._lock:
            expired = [(op_id, issued) for op_id, issued in self._issued.items() if issued.exp <= now]
        reconciled = []
        for op_id, issued in expired:
            try:
                self._ledger.mark_outcome_unknown(issued.tenant, issued.task, op_id, now)
            except LedgerRefused as refused:
                logger.warning("reconcile skipped %s: %s", op_id, refused)
                with self._lock:
                    self._issued.pop(op_id, None)
                continue
            with self._lock:
                self._issued.pop(op_id, None)
            reconciled.append(op_id)
            self._append(
                replace(
                    issued.entry,
                    decision="reconcile",
                    at=now,
                    outcome="outcome_unknown",
                    reason="clearance_expired",
                )
            )
        for reservation in self._ledger.issued_expired(now)[:MAX_RECONCILE_BATCH]:
            with self._lock:
                if reservation.op_id in self._issued or reservation.op_id in self._in_flight:
                    continue
            self._append(
                Entry(
                    entry_id="",
                    trace_id=_reconcile_trace_id(reservation.op_id),
                    hop=HOP,
                    component=self._config.decider_id,
                    decision="reconcile",
                    at=now,
                    op_id=reservation.op_id,
                    tenant=reservation.tenant_id,
                    cost=reservation.cost,
                    outcome="outcome_unknown",
                    reason="untracked_issued_expired",
                    handles={"tenant": reservation.tenant_id, "task": reservation.task_id},
                )
            )
            try:
                self._ledger.mark_outcome_unknown(reservation.tenant_id, reservation.task_id, reservation.op_id, now)
            except LedgerRefused as refused:
                logger.warning("reconcile skipped %s after recording it: %s", reservation.op_id, refused)
                continue
            reconciled.append(reservation.op_id)
        return tuple(reconciled)

    def _check(self, request: OperationRequest, now: int, entry: Entry) -> Decision:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise ValueError("now must be a non-negative integer")
        try:
            snapshot = snapshot_args(request.args)
        except ArgsError:
            raise _Refusal("malformed_request", entry) from None
        if request.refusal() is not None:
            raise _Refusal("malformed_request", entry)
        operation_args_digest = snapshot.digest
        entry = replace(entry, tool=request.tool, resource=request.resource, args_digest=operation_args_digest)
        digest = request_digest(request.tool, request.resource, snapshot.thaw(), request.nonce)
        chain = verify_chain(
            request.task_root,
            list(request.links),
            request.leaf_proof,
            self._resolver,
            self._trust_policy,
            self._ledger,
            now,
            expected_audience=self._config.decider_id,
            expected_request_digest=digest,
            max_proof_age_seconds=self._config.max_proof_age,
        )
        if not chain.valid or chain.root is None or chain.leaf_scope is None or chain.leaf_subject is None:
            raise _Refusal("chain_invalid", entry)
        entry = _with_who(entry, chain.root, chain.links, chain.leaf_subject)
        try:
            return self._decide(
                request, now, entry, snapshot, digest, chain.root, chain.links, chain.leaf_scope, chain.leaf_subject
            )
        except _Refusal:
            raise
        except Exception:
            logger.exception("decide failed with an internal error")
            raise _Refusal("internal_error", entry) from None

    def _decide(
        self,
        request: OperationRequest,
        now: int,
        entry: Entry,
        snapshot: ArgsSnapshot,
        digest: str,
        root: TaskRoot,
        links: tuple[ChainLink, ...],
        scope: dict[str, Any],
        agent_key: str,
    ) -> Decision:
        operation_args_digest = snapshot.digest
        leaf_binding = links[-1].binding() if links else root.binding()
        if not all(is_bounded(pattern) for pattern in scope["resources"]):
            raise _Refusal("unbounded_scope", entry)
        if not covers(scope, request.tool, request.resource):
            raise _Refusal("out_of_scope", entry)
        try:
            cost = self._costs.cost(request.tool, snapshot.value)
        except CostError:
            raise _Refusal("unknown_cost", entry) from None
        entry = replace(entry, cost=cost)
        if cost > scope["max_cost_per_call"]:
            raise _Refusal("cost_over_call_cap", entry)
        binding = self._config.binding(root.tenant_id, request.tool, request.resource)
        if binding is None:
            raise _Refusal("no_binding", entry)
        allowed, verdict = Guard(self._policy.policy, MemoryAuditSink(), agent_id=agent_key).decide(
            request.tool, snapshot.thaw()
        )
        entry = replace(
            entry,
            policy_id=self._policy.policy_id,
            policy_version=self._policy.version,
            policy_digest=self._policy.digest,
            rule=verdict.rule_id,
            verdict=verdict.decision.value,
        )
        if not allowed:
            reason = "needs_approval" if verdict.decision is PolicyDecision.REQUIRE_HUMAN else "policy_denied"
            raise _Refusal(reason, entry)
        if self._suspension.suspended is not False:
            raise _Refusal("suspended", entry)
        op_id = derive_op_id(root.tenant_id, root.task_id, leaf_binding, digest)
        entry = replace(entry, op_id=op_id)
        with self._lock:
            self._in_flight.add(op_id)
        try:
            expires_at = self._reserve_and_issue(
                root, links, leaf_binding, op_id, request, operation_args_digest, cost, now, entry
            )
            with self._lock:
                self._issued[op_id] = _Issued(root.tenant_id, root.task_id, expires_at, entry)
        finally:
            with self._lock:
                self._in_flight.discard(op_id)
        entry_id = uuid.uuid4().hex
        clearance = Clearance(
            iss=self._config.decider_id,
            aud=binding.custodian,
            iat=now,
            exp=expires_at,
            op_id=op_id,
            tenant=root.tenant_id,
            task=root.task_id,
            root_binding=root.binding(),
            leaf_binding=leaf_binding,
            request_digest=digest,
            tool=request.tool,
            resource=request.resource,
            args_digest=operation_args_digest,
            cost=cost,
            credential_id=binding.credential_id,
            target=binding.target,
            trace_id=entry.trace_id,
            entry_id=entry_id,
        )
        token = encode_clearance(clearance, self._signing_key, self._config.kid)
        linked = replace(entry, parent_entry=entry_id)
        with self._lock:
            self._issued[op_id] = _Issued(root.tenant_id, root.task_id, expires_at, linked)
        allow_entry = replace(
            entry, entry_id=entry_id, decision="allow", reason="ok", clearance_digest=token_hash(token)
        )
        try:
            record = self._docket.append(allow_entry)
        except Exception:
            logger.exception("docket entry for an issued operation was not acknowledged")
            raise _Refusal("docket_unavailable", linked) from None
        if not self._acknowledges(record, allow_entry):
            logger.error("docket acknowledgement does not match the allow entry")
            raise _Refusal("docket_unavailable", linked)
        return Decision(allowed=True, reason="ok", clearance=token, entry_id=entry_id, op_id=op_id)

    def _reserve_and_issue(
        self,
        root: TaskRoot,
        links: tuple[ChainLink, ...],
        leaf_binding: str,
        op_id: str,
        request: OperationRequest,
        operation_args_digest: str,
        cost: int,
        now: int,
        entry: Entry,
    ) -> int:
        try:
            self._ledger.open_task(TaskRootResult(valid=True, reason="ok", root=root, checked_at=now), now)
            stored = self._ledger.reservation(root.tenant_id, root.task_id, op_id, now)
            if stored is not None and stored.state != "reserved":
                raise _Refusal(f"already_{stored.state}", entry)
            expires_at = (
                stored.expires_at
                if stored is not None
                else min(now + self._config.max_proof_age, root.expires_at, *(link.expires_at for link in links))
            )
            operation = Operation(
                op_id=op_id,
                tenant_id=root.tenant_id,
                task_id=root.task_id,
                leaf_binding=leaf_binding,
                tool=request.tool,
                resource=request.resource,
                args_digest=operation_args_digest,
                cost=cost,
                verdict_allowed=True,
                expires_at=expires_at,
            )
            reservation = self._ledger.reserve(operation, links, now)
            if reservation.state != "reserved":
                raise _Refusal(f"already_{reservation.state}", entry)
            issued = self._ledger.mark_issued(root.tenant_id, root.task_id, op_id, now)
        except LedgerRefused:
            raise _Refusal("reservation_refused", entry) from None
        except LedgerUnavailable:
            raise _Refusal("ledger_unavailable", entry) from None
        return issued.expires_at

    def _acknowledges(self, record: object, entry: Entry) -> bool:
        return (
            isinstance(record, Record)
            and record.entry == entry
            and record.writer == self._config.docket_writer
            and isinstance(record.token, str)
            and bool(record.token)
        )

    def _refuse(self, reason: str, entry: Entry) -> Decision:
        tenant, task = entry.handles.get("tenant"), entry.handles.get("task")
        if tenant is None or task is None:
            logger.info("unverified refusal %s not docketed (trace %s)", reason, entry.trace_id)
            return Decision(allowed=False, reason=reason, entry_id=None, op_id=entry.op_id)
        root = entry.handles.get("root", "")
        admission = self._refusal_budget.admit(tenant, task, root, reason)
        if admission.verdict == "drop":
            logger.info(
                "refusal %s of %s for tenant %s task %s agent %s over the record budget, not docketed (trace %s)",
                reason,
                entry.tool,
                tenant,
                task,
                entry.agent_key,
                entry.trace_id,
            )
            return Decision(allowed=False, reason=reason, entry_id=None, op_id=entry.op_id)
        recorded = reason
        if admission.verdict == "capped":
            recorded = capped_reason(reason, admission)
            logger.warning(
                "tenant %s task %s passed the refusal record budget; recording %s for refusal %s (trace %s)",
                tenant,
                task,
                recorded,
                reason,
                entry.trace_id,
            )
        entry_id: str | None
        try:
            entry_id = self._append(replace(entry, decision="refuse", reason=recorded))
        except Exception as error:
            logger.warning("docket entry for a refusal may not have been written", exc_info=True)
            if isinstance(error, DocketError) and error.reason not in UNACKNOWLEDGED:
                self._refusal_budget.refund(tenant, task, root, reason, admission)
            entry_id = None
        return Decision(allowed=False, reason=reason, entry_id=entry_id, op_id=entry.op_id)

    def _append(self, entry: Entry) -> str:
        entry_id = uuid.uuid4().hex
        self._docket.append(replace(entry, entry_id=entry_id))
        return entry_id


def _reconcile_trace_id(op_id: str) -> str:
    return hashlib.sha256(f"reconcile:{op_id}".encode()).hexdigest()[:32]


def _with_who(entry: Entry, root: TaskRoot, links: tuple[ChainLink, ...], agent_key: str) -> Entry:
    root_binding = root.binding()
    link_bindings = tuple(link.binding() for link in links)
    handles = {"agent_key": agent_key, "task": root.task_id, "tenant": root.tenant_id, "root": root_binding}
    if link_bindings:
        handles["link"] = link_bindings[-1]
    return replace(
        entry,
        principal=root.principal,
        tenant=root.tenant_id,
        task_root=root_binding,
        links=link_bindings,
        agent_key=agent_key,
        handles=handles,
    )


def _trace_id(value: object) -> str:
    if (
        isinstance(value, str)
        and 0 < len(value) <= MAX_TRACE_ID_CHARACTERS
        and all("!" <= character <= "~" for character in value)
    ):
        return value
    return uuid.uuid4().hex
