from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field, replace
from typing import Protocol

from agent_warrant.chain import ChainContext, ChainLink, verify_chain
from agent_warrant.ledger import LedgerError, Operation, Reservation
from agent_warrant.resolver import IssuerResolver
from agent_warrant.scope import covers
from agent_warrant.task_root import TaskRoot
from agent_warrant.trust import IssuerTrustPolicy

from agent_bailiff.custodian.bindings import BindingTable, CredentialBinding
from agent_bailiff.custodian.claims import ClaimsStore, ClaimsUnavailable
from agent_bailiff.custodian.config import CustodianConfig
from agent_bailiff.custodian.ratelimit import TaskRateLimiter
from agent_bailiff.custodian.store import CredentialStore, CredentialUnavailable
from agent_bailiff.decide.clearance import Clearance, verify_clearance
from agent_bailiff.decide.decider import DocketWriter
from agent_bailiff.decide.identity import ArgsError, ArgsSnapshot, derive_op_id, request_digest, snapshot_args
from agent_bailiff.decide.request import OperationRequest
from agent_bailiff.docket.entry import Entry, Record
from agent_bailiff.signing import Refused as SigningRefused
from agent_bailiff.signing import token_hash

HOP = "custodian"
TIER = "gateway-bound"
CLEARANCE_REFUSALS = {
    "wrong_issuer": "clearance_wrong_issuer",
    "wrong_audience": "clearance_wrong_audience",
    "expired": "clearance_expired",
    "not_yet_valid": "clearance_not_yet_valid",
}

logger = logging.getLogger(__name__)


class ReservationReader(Protocol):
    def reservation_readonly(self, tenant_id: str, task_id: str, op_id: str) -> Reservation | None: ...

    def is_revoked(self, context: ChainContext) -> bool: ...


@dataclass(frozen=True)
class Released:
    header_name: str
    header_value: str = field(repr=False)
    tier: str = TIER
    op_id: str = ""
    entry_id: str = ""

    @property
    def ok(self) -> bool:
        return True


@dataclass(frozen=True)
class Refused:
    reason: str

    @property
    def ok(self) -> bool:
        return False


ReleaseResult = Released | Refused


@dataclass(frozen=True)
class _Verified:
    clearance: Clearance
    root: TaskRoot
    links: tuple[ChainLink, ...]
    agent_key: str
    leaf_binding: str
    snapshot: ArgsSnapshot
    token: str


class _Refusal(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Custodian:
    def __init__(
        self,
        config: CustodianConfig,
        bindings: BindingTable,
        store: CredentialStore,
        claims: ClaimsStore,
        ledger: ReservationReader,
        resolver: IssuerResolver,
        trust_policy: IssuerTrustPolicy,
        docket: DocketWriter,
    ) -> None:
        self._config = config
        self._bindings = bindings
        self._store = store
        self._claims = claims
        self._ledger = ledger
        self._resolver = resolver
        self._trust_policy = trust_policy
        self._docket = docket
        self._limiter = TaskRateLimiter(config.rate_limit, config.rate_window)

    def release(self, clearance_token: object, request: object, now: int) -> ReleaseResult:
        try:
            return self._release(clearance_token, request, now)
        except _Refusal as refusal:
            return Refused(refusal.reason)
        except Exception:
            logger.exception("custodian release failed with an internal error")
            return Refused("internal_error")

    def _release(self, clearance_token: object, request: object, now: int) -> Released:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise ValueError("now must be a non-negative integer")
        verified = self._verify(clearance_token, request, now)
        clearance = verified.clearance
        binding = self._binding(verified)
        self._check_reservation(verified, now)
        entry = self._entry(verified, now)
        if binding.canary:
            self._trip_canary(clearance.tenant, clearance.task, entry, now)
            raise _Refusal("canary")
        if not self._limiter.allow(clearance.tenant, clearance.task, now):
            raise _Refusal("rate_limited")
        self._claim(clearance, now)
        header_value = self._decrypt(binding)
        release_entry = replace(
            entry,
            entry_id=uuid.uuid4().hex,
            decision="release",
            reason="ok",
            performed=True,
            credential_tier=TIER,
            clearance_digest=token_hash(verified.token),
        )
        self._record(release_entry)
        return Released(binding.header_name, header_value, TIER, clearance.op_id, release_entry.entry_id)

    def _verify(self, clearance_token: object, request: object, now: int) -> _Verified:
        if clearance_token is None or clearance_token == "":
            raise _Refusal("clearance_missing")
        if not isinstance(clearance_token, str):
            raise _Refusal("clearance_invalid")
        config = self._config
        clearance = verify_clearance(
            clearance_token,
            config.decide_keys,
            now=now,
            expected_aud=config.custodian_id,
            expected_iss=config.decider_id,
            skew_seconds=config.skew_seconds,
            max_lifetime=config.max_clearance_lifetime,
        )
        if isinstance(clearance, SigningRefused):
            raise _Refusal(CLEARANCE_REFUSALS.get(clearance.reason, "clearance_invalid"))
        if not isinstance(request, OperationRequest):
            raise _Refusal("malformed_request")
        try:
            snapshot = snapshot_args(request.args)
        except ArgsError:
            raise _Refusal("malformed_request") from None
        if request.refusal() is not None:
            raise _Refusal("malformed_request")
        digest = request_digest(request.tool, request.resource, snapshot.thaw(), request.nonce)
        chain = verify_chain(
            request.task_root,
            list(request.links),
            request.leaf_proof,
            self._resolver,
            self._trust_policy,
            self._ledger,
            now,
            expected_audience=config.decider_id,
            expected_request_digest=digest,
            max_proof_age_seconds=config.max_proof_age,
        )
        if not chain.valid or chain.root is None or chain.leaf_scope is None or chain.leaf_subject is None:
            raise _Refusal("chain_invalid")
        if not covers(chain.leaf_scope, request.tool, request.resource):
            raise _Refusal("out_of_scope")
        root = chain.root
        leaf_binding = chain.links[-1].binding() if chain.links else root.binding()
        expected = {
            "op_id": derive_op_id(root.tenant_id, root.task_id, leaf_binding, digest),
            "tenant": root.tenant_id,
            "task": root.task_id,
            "root_binding": root.binding(),
            "leaf_binding": leaf_binding,
            "request_digest": digest,
            "tool": request.tool,
            "resource": request.resource,
            "args_digest": snapshot.digest,
        }
        if any(getattr(clearance, name) != value for name, value in expected.items()):
            raise _Refusal("clearance_mismatch")
        return _Verified(clearance, root, chain.links, chain.leaf_subject, leaf_binding, snapshot, clearance_token)

    def _binding(self, verified: _Verified) -> CredentialBinding:
        clearance = verified.clearance
        binding = self._bindings.resolve(clearance.tenant, clearance.tool, clearance.resource)
        if binding is None:
            raise _Refusal("no_binding")
        if (binding.credential_id, binding.target) != (clearance.credential_id, clearance.target):
            raise _Refusal("binding_mismatch")
        return binding

    def _check_reservation(self, verified: _Verified, now: int) -> None:
        clearance = verified.clearance
        operation = Operation(
            op_id=clearance.op_id,
            tenant_id=clearance.tenant,
            task_id=clearance.task,
            leaf_binding=verified.leaf_binding,
            tool=clearance.tool,
            resource=clearance.resource,
            args_digest=verified.snapshot.digest,
            cost=clearance.cost,
            verdict_allowed=True,
            expires_at=clearance.exp,
        )
        try:
            reservation = self._ledger.reservation_readonly(clearance.tenant, clearance.task, clearance.op_id)
        except LedgerError:
            raise _Refusal("ledger_unavailable") from None
        if reservation is None:
            raise _Refusal("reservation_missing")
        if reservation.state != "issued":
            raise _Refusal("reservation_not_issued")
        if reservation.digest != operation.digest():
            raise _Refusal("reservation_mismatch")
        if now >= reservation.expires_at:
            raise _Refusal("reservation_expired")

    def _entry(self, verified: _Verified, now: int) -> Entry:
        clearance = verified.clearance
        root = verified.root
        link_bindings = tuple(link.binding() for link in verified.links)
        handles = {
            "agent_key": verified.agent_key,
            "task": root.task_id,
            "tenant": root.tenant_id,
            "root": root.binding(),
        }
        if link_bindings:
            handles["link"] = link_bindings[-1]
        return Entry(
            entry_id=HOP,
            trace_id=clearance.trace_id,
            hop=HOP,
            component=self._config.custodian_id,
            decision="refuse",
            at=now,
            op_id=clearance.op_id,
            parent_entry=clearance.entry_id,
            principal=root.principal,
            tenant=root.tenant_id,
            task_root=root.binding(),
            links=link_bindings,
            agent_key=verified.agent_key,
            tool=clearance.tool,
            resource=clearance.resource,
            args_digest=clearance.args_digest,
            cost=clearance.cost,
            handles=handles,
        )

    def _trip_canary(self, tenant: str, task: str, entry: Entry, now: int) -> None:
        try:
            self._claims.deny(tenant, task, now)
        except ClaimsUnavailable:
            logger.error("canary deny for a task is held in memory only; it was not written to the claims database")
        try:
            self._docket.append(replace(entry, entry_id=uuid.uuid4().hex, decision="alert", reason="canary"))
        except Exception:
            logger.exception("canary alert entry was not acknowledged")

    def _claim(self, clearance: Clearance, now: int) -> None:
        try:
            result = self._claims.claim(clearance.op_id, clearance.tenant, clearance.task, now)
        except ClaimsUnavailable:
            raise _Refusal("claims_unavailable") from None
        if result != "claimed":
            raise _Refusal(result)

    def _decrypt(self, binding: CredentialBinding) -> str:
        try:
            secret = self._store.get(binding.tenant, binding.credential_id, binding.target)
        except CredentialUnavailable:
            raise _Refusal("credential_unavailable") from None
        value = _header_value(secret)
        if value is None:
            raise _Refusal("credential_unavailable")
        return value

    def _record(self, entry: Entry) -> None:
        try:
            record = self._docket.append(entry)
        except Exception:
            logger.exception("docket entry for a release was not acknowledged")
            raise _Refusal("docket_unavailable") from None
        if not (
            isinstance(record, Record)
            and record.entry == entry
            and record.writer == self._config.docket_writer
            and isinstance(record.token, str)
            and bool(record.token)
        ):
            logger.error("docket acknowledgement does not match the release entry")
            raise _Refusal("docket_unavailable")


def _header_value(secret: bytes) -> str | None:
    try:
        value = secret.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not value or value != value.strip(" \t"):
        return None
    if not all(character in " \t" or "!" <= character <= "~" for character in value):
        return None
    return value
