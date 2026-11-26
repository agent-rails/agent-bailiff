from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Protocol

from agent_warrant.chain import ChainContext, ChainLink, verify_chain
from agent_warrant.ledger import LedgerError, Operation, Reservation
from agent_warrant.resolver import IssuerResolver
from agent_warrant.task_root import TaskRoot
from agent_warrant.trust import IssuerTrustPolicy

from agent_bailiff.custodian.bindings import Binding, BindingTable, CredentialBinding, EffectorBinding
from agent_bailiff.custodian.claims import ClaimsStore, ClaimsUnavailable
from agent_bailiff.custodian.config import CustodianConfig
from agent_bailiff.custodian.echo import Oversize, UnreadableResult, needles, redact, redaction_problem
from agent_bailiff.custodian.inflight import InflightFull, InflightRelease, InflightReleases
from agent_bailiff.custodian.inflight import Reservation as InflightReservation
from agent_bailiff.custodian.ratelimit import TaskRateLimiter
from agent_bailiff.custodian.release import RELEASE_HEADER, ReleaseSigner, ReleaseTooLarge
from agent_bailiff.custodian.store import CredentialStore, CredentialUnavailable, header_value
from agent_bailiff.decide.clearance import Clearance, verify_clearance
from agent_bailiff.decide.decider import DocketWriter, SuspensionCheck
from agent_bailiff.decide.identity import ArgsError, ArgsSnapshot, derive_op_id, request_digest, snapshot_args
from agent_bailiff.decide.request import OperationRequest
from agent_bailiff.docket.client import UNACKNOWLEDGED, DocketError
from agent_bailiff.docket.entry import Entry, Record
from agent_bailiff.scope_pattern import scope_refusal
from agent_bailiff.signing import Refused as SigningRefused
from agent_bailiff.signing import token_hash

HOP = "custodian"
TIER = "gateway-bound"
EFFECTOR_TIER = "effector"
CLEARANCE_REFUSALS = {
    "wrong_issuer": "clearance_wrong_issuer",
    "wrong_audience": "clearance_wrong_audience",
    "expired": "clearance_expired",
    "not_yet_valid": "clearance_not_yet_valid",
}
ONCE_REFUSALS = frozenset({"already_issued", "task_denied", "chain_refused"})
RESPONSE_REASONS = frozenset(
    {
        "response_unmatched",
        "response_unreadable",
        "response_oversize",
        "response_clearance_missing",
        "response_internal_error",
    }
)
MAX_RECORDED_REFUSALS = 65536
REFUSAL_ENTRY = "docket entry for custodian refusal (tenant %r, task %r, op %r, reason %s)"

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
class ResponseChecked:
    result: bytes | None


@dataclass(frozen=True)
class ResponseRefused:
    reason: str


ResponseResult = ResponseChecked | ResponseRefused


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


class _ChainRefused(_Refusal):
    def __init__(self, clearance: Clearance, token: str, library_reason: str) -> None:
        super().__init__("chain_invalid")
        self.clearance = clearance
        self.token = token
        self.library_reason = library_reason


class _UnacknowledgedRelease(_Refusal):
    def __init__(self) -> None:
        super().__init__("docket_unavailable")


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
        suspension: SuspensionCheck,
        release_signer: ReleaseSigner | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self._config = config
        self._bindings = bindings
        self._store = store
        self._claims = claims
        self._ledger = ledger
        self._resolver = resolver
        self._trust_policy = trust_policy
        self._docket = docket
        self._suspension = suspension
        self._release_signer = release_signer
        self._monotonic_ns = monotonic_ns
        self._limiter = TaskRateLimiter(config.rate_limit, config.rate_window)
        self._inflight = InflightReleases(
            max_entries=config.inflight_max,
            max_bytes=config.inflight_max_bytes,
            per_tenant=config.inflight_per_tenant,
            ttl_ns=config.inflight_ttl * 1_000_000_000,
            monotonic_ns=monotonic_ns,
        )
        self._admit_lock = threading.Lock()
        self._recorded_refusals: dict[tuple[str, str, str, str], None] = {}
        self._refusals_lock = threading.Lock()
        logger.info("custodian %s effective scope_v1_cutoff=%d", config.custodian_id, config.scope_v1_cutoff)

    def release(self, clearance_token: object, request: object, now: int) -> ReleaseResult:
        started = self._monotonic_ns()
        try:
            return self._release(clearance_token, request, now, started)
        except _Refusal as refusal:
            return Refused(refusal.reason)
        except Exception:
            logger.exception("custodian release failed with an internal error")
            return Refused("internal_error")

    def check_response(self, clearance_token: object, result: bytes, now: int) -> ResponseResult:
        try:
            return self._check_response(clearance_token, result, now)
        except Exception:
            logger.exception("custodian response check failed with an internal error")
            return ResponseRefused("response_internal_error")

    def _check_response(self, clearance_token: object, result: bytes, now: int) -> ResponseResult:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise ValueError("now must be a non-negative integer")
        if not isinstance(clearance_token, str) or not clearance_token:
            return ResponseRefused("response_clearance_missing")
        release = self._inflight.take(token_hash(clearance_token)) if clearance_token.isascii() else None
        if release is None:
            logger.warning("no in-flight release matches a call result")
            return ResponseRefused("response_unmatched")
        op_id = release.entry.op_id
        try:
            redaction = redact(result, needles(release.header_value))
        except UnreadableResult:
            logger.warning("call result for op %s is not a readable JSON object", op_id)
            return ResponseRefused("response_unreadable")
        except Oversize:
            logger.warning("redacted call result for op %s is over the size cap", op_id)
            return ResponseRefused("response_oversize")
        if redaction is None:
            return ResponseChecked(None)
        logger.error(
            "redacted %d echoes of the released credential from the call result for op %s", redaction.hits, op_id
        )
        self._alert_echo(release, now)
        return ResponseChecked(redaction.result)

    def _alert_echo(self, release: InflightRelease, now: int) -> None:
        alert = replace(
            release.entry,
            entry_id=uuid.uuid4().hex,
            decision="alert",
            reason="credential_echo",
            parent_entry=release.release_entry_id,
            at=now,
        )
        try:
            self._docket.append(alert)
        except Exception:
            logger.exception("credential echo alert entry for op %s was not acknowledged", release.entry.op_id)

    def _release(self, clearance_token: object, request: object, now: int, started: int) -> Released:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise ValueError("now must be a non-negative integer")
        try:
            verified = self._verify(clearance_token, request, now)
        except _ChainRefused as refusal:
            logger.warning("custodian refused the chain of a verified clearance: %s", refusal.library_reason)
            self._record_chain_refusal(refusal, now, started)
            raise
        except _Refusal as refusal:
            logger.warning("custodian refused an unverified request: %s", refusal.reason)
            raise
        entry = self._entry(verified, now)
        try:
            return self._release_verified(verified, entry, now, started)
        except _UnacknowledgedRelease:
            raise
        except _Refusal as refusal:
            self._record_refusal(verified.clearance, entry, refusal.reason, started)
            raise
        except Exception:
            logger.exception("custodian release failed with an internal error")
            self._record_refusal(verified.clearance, entry, "internal_error", started)
            raise _Refusal("internal_error") from None

    def _release_verified(self, verified: _Verified, entry: Entry, now: int, started: int) -> Released:
        clearance = verified.clearance
        _check_scope(verified)
        binding = self._binding(verified)
        self._check_reservation(verified, now)
        if isinstance(binding, EffectorBinding):
            return self._release_to_effector(verified, binding, entry, now, started)
        if binding.canary:
            self._trip_canary(clearance.tenant, clearance.task, entry, now)
            raise _Refusal("canary")
        self._precheck(clearance, now)
        header_value = self._decrypt(binding)
        if self._suspension.suspended is not False:
            raise _Refusal("suspended")
        _warn_unredactable(header_value)
        reservation = self._reserve(verified, header_value)
        try:
            self._admit(clearance, now)
            release_entry = replace(
                entry,
                entry_id=uuid.uuid4().hex,
                decision="release",
                reason="ok",
                performed=True,
                credential_tier=TIER,
                latency_ms=self._elapsed_ms(started),
            )
            self._record(release_entry)
        except BaseException:
            self._inflight.discard(reservation)
            raise
        self._inflight.commit(reservation, release_entry.entry_id, entry)
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
        _match_clearance(clearance, request, digest, snapshot)
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
            scope_v1_cutoff=config.scope_v1_cutoff,
        )
        if not chain.valid or chain.root is None or chain.leaf_subject is None:
            raise _ChainRefused(clearance, clearance_token, chain.reason)
        root = chain.root
        leaf_binding = chain.links[-1].binding() if chain.links else root.binding()
        return _Verified(clearance, root, chain.links, chain.leaf_subject, leaf_binding, snapshot, clearance_token)

    def _release_to_effector(
        self, verified: _Verified, binding: EffectorBinding, entry: Entry, now: int, started: int
    ) -> Released:
        clearance = verified.clearance
        if self._release_signer is None:
            raise _Refusal("release_unavailable")
        self._precheck(clearance, now)
        if self._suspension.suspended is not False:
            raise _Refusal("suspended")
        release_entry = replace(
            entry,
            entry_id=uuid.uuid4().hex,
            decision="release",
            reason="ok",
            performed=True,
            credential_tier=EFFECTOR_TIER,
            latency_ms=self._elapsed_ms(started),
        )
        try:
            token = self._release_signer.sign(
                clearance, verified.token, binding.credential_id, binding.catalog, release_entry.entry_id, now
            )
        except ReleaseTooLarge:
            raise _Refusal("release_too_large") from None
        reservation = self._reserve(verified, token)
        try:
            self._admit(clearance, now)
            self._record(release_entry)
        except BaseException:
            self._inflight.discard(reservation)
            raise
        self._inflight.commit(reservation, release_entry.entry_id, entry)
        return Released(RELEASE_HEADER, token, EFFECTOR_TIER, clearance.op_id, release_entry.entry_id)

    def _binding(self, verified: _Verified) -> Binding:
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
        except LedgerError as err:
            logger.warning("reservation for op %s could not be read: %r", clearance.op_id, str(err))
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
            clearance_digest=token_hash(verified.token),
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

    def _precheck(self, clearance: Clearance, now: int) -> None:
        try:
            if self._claims.is_denied(clearance.tenant, clearance.task):
                raise _Refusal("task_denied")
            if self._claims.is_claimed(clearance.op_id):
                raise _Refusal("already_issued")
        except ClaimsUnavailable:
            raise _Refusal("claims_unavailable") from None
        if self._limiter.exhausted(clearance.tenant, clearance.task, now):
            raise _Refusal("rate_limited")

    def _reserve(self, verified: _Verified, header_value: str) -> InflightReservation:
        try:
            return self._inflight.reserve(token_hash(verified.token), verified.clearance.tenant, header_value)
        except InflightFull:
            raise _Refusal("inflight_full") from None
        except ValueError:
            raise _Refusal("already_issued") from None

    def _admit(self, clearance: Clearance, now: int) -> None:
        with self._admit_lock:
            if self._limiter.exhausted(clearance.tenant, clearance.task, now):
                raise _Refusal("rate_limited")
            try:
                result = self._claims.claim(clearance.op_id, clearance.tenant, clearance.task, now)
            except ClaimsUnavailable:
                raise _Refusal("claims_unavailable") from None
            if result != "claimed":
                raise _Refusal(result)
            self._limiter.record(clearance.tenant, clearance.task, now)

    def _decrypt(self, binding: CredentialBinding) -> str:
        try:
            stored = self._store.get(binding.tenant, binding.credential_id, binding.target)
        except CredentialUnavailable:
            raise _Refusal("credential_unavailable") from None
        value = header_value(stored.secret)
        if value is None:
            raise _Refusal("credential_unavailable")
        problem = redaction_problem(value)
        if problem is not None and stored.exception is None:
            logger.warning(
                "stored credential %r for target %r cannot be redacted from results and has no accepted exception: %s",
                binding.credential_id,
                binding.target,
                problem,
            )
            raise _Refusal("credential_unredactable")
        return value

    def _record_refusal(self, clearance: Clearance, entry: Entry, reason: str, started: int) -> None:
        key = (clearance.tenant, clearance.task, clearance.op_id, reason)
        if reason in ONCE_REFUSALS and not self._mark_refusal(key):
            return
        try:
            self._docket.append(
                replace(
                    entry,
                    entry_id=uuid.uuid4().hex,
                    decision="refuse",
                    reason=reason,
                    latency_ms=self._elapsed_ms(started),
                )
            )
        except DocketError as exc:
            if exc.reason == "state_write_failed":
                logger.warning(f"{REFUSAL_ENTRY} was recorded but its head was not saved", *key, exc_info=True)
                return
            if exc.reason in UNACKNOWLEDGED:
                logger.warning(f"{REFUSAL_ENTRY} was not acknowledged and may be recorded", *key, exc_info=True)
            else:
                logger.warning(f"{REFUSAL_ENTRY} was not written", *key, exc_info=True)
            self._forget_refusal(key)
        except Exception:
            logger.warning(f"{REFUSAL_ENTRY} was not written", *key, exc_info=True)
            self._forget_refusal(key)

    def _forget_refusal(self, key: tuple[str, str, str, str]) -> None:
        with self._refusals_lock:
            self._recorded_refusals.pop(key, None)

    def _record_chain_refusal(self, refusal: _ChainRefused, now: int, started: int) -> None:
        clearance = refusal.clearance
        handles = {"task": clearance.task, "tenant": clearance.tenant, "root": clearance.root_binding}
        if clearance.leaf_binding != clearance.root_binding:
            handles["link"] = clearance.leaf_binding
        entry = Entry(
            entry_id=HOP,
            trace_id=clearance.trace_id,
            hop=HOP,
            component=self._config.custodian_id,
            decision="refuse",
            at=now,
            op_id=clearance.op_id,
            parent_entry=clearance.entry_id,
            tenant=clearance.tenant,
            task_root=clearance.root_binding,
            tool=clearance.tool,
            resource=clearance.resource,
            args_digest=clearance.args_digest,
            cost=clearance.cost,
            clearance_digest=token_hash(refusal.token),
            handles=handles,
        )
        self._record_refusal(clearance, entry, "chain_refused", started)

    def _elapsed_ms(self, started: int) -> int:
        return max(0, (self._monotonic_ns() - started) // 1_000_000)

    def _mark_refusal(self, key: tuple[str, str, str, str]) -> bool:
        with self._refusals_lock:
            if key in self._recorded_refusals:
                return False
            if len(self._recorded_refusals) >= MAX_RECORDED_REFUSALS:
                del self._recorded_refusals[next(iter(self._recorded_refusals))]
            self._recorded_refusals[key] = None
            return True

    def _record(self, entry: Entry) -> None:
        try:
            record = self._docket.append(entry)
        except Exception:
            logger.exception("docket entry for a release was not acknowledged")
            raise _UnacknowledgedRelease from None
        if not (
            isinstance(record, Record)
            and record.entry == entry
            and record.writer == self._config.docket_writer
            and isinstance(record.token, str)
            and bool(record.token)
        ):
            logger.error("docket acknowledgement does not match the release entry")
            raise _UnacknowledgedRelease


def _match_clearance(clearance: Clearance, request: OperationRequest, digest: str, snapshot: ArgsSnapshot) -> None:
    try:
        root = TaskRoot.decode(request.task_root)
        leaf_binding = ChainLink.decode(request.links[-1]).binding() if request.links else root.binding()
    except ValueError:
        raise _Refusal("clearance_mismatch") from None
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


def _check_scope(verified: _Verified) -> None:
    clearance = verified.clearance
    refusal = scope_refusal((verified.root, *verified.links), clearance.tool, clearance.resource, clearance.cost)
    if refusal is not None:
        raise _Refusal(refusal)


def _warn_unredactable(value: str) -> None:
    problem = redaction_problem(value)
    if problem is not None:
        logger.warning("released credential has an accepted exception and cannot be redacted from results: %s", problem)
