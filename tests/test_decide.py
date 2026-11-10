import asyncio
import os
import shutil
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from agent_warrant.chain import delegate, prove_leaf
from agent_warrant.encoding import b64u, b64u_decode
from agent_warrant.identity import encode_public_key
from agent_warrant.ledger import LedgerUnavailable, Operation, TaskLedger
from agent_warrant.ledger import Refused as LedgerRefused
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import issue_task_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.decide import (
    CostTable,
    Decider,
    DeciderConfig,
    OperationRequest,
    PolicyRef,
    TargetBinding,
    args_digest,
    decode_clearance,
    derive_op_id,
    request_digest,
    snapshot_args,
)
from agent_bailiff.docket import DocketClient, DocketSink, decode_record
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.signing import Refused

NOW = 1_800_000_000
DECIDER_ID = "decide.example"
CUSTODIAN_ID = "custodian.example"
ISSUER_ID = "issuer.example"
TENANT = "tenant-a"
PRINCIPAL = "user:alice"
MAX_PROOF_AGE = 60
DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
AGENT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
CHILD_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
WRITERS = {"decide": {"decide-1": DECIDE_KEY.public_key()}}
PINNED = {"decide-1": DECIDE_KEY.public_key()}
SCOPE = {
    "tools": ["deploy.*", "signer.withdraw"],
    "resources": ["env/staging/*", "wallet/*"],
    "max_cost_per_call": 5,
}
POLICY = {
    "default": "allow",
    "rules": [
        {"id": "no-delete", "decision": "deny", "tools": ["deploy.delete"]},
        {"id": "withdraw-needs-human", "decision": "require_human", "tools": ["signer.withdraw"]},
    ],
}
COSTS = CostTable(
    1,
    {
        "deploy.service": 1,
        "deploy.delete": 1,
        "deploy.rollback": 50,
        "deploy.scale": 1,
        "signer.withdraw": "amount",
    },
)
BINDINGS = (
    TargetBinding(TENANT, "deploy.service", "env/staging/*", "deploy-api", "deploy.example"),
    TargetBinding(TENANT, "deploy.delete", "env/staging/*", "deploy-api", "deploy.example"),
    TargetBinding(TENANT, "deploy.rollback", "env/staging/*", "deploy-api", "deploy.example"),
    TargetBinding(TENANT, "signer.withdraw", "wallet/*", "signer", "signer.example"),
)
ARGS = {"service": "api", "replicas": 2}


class Suspension:
    def __init__(self, suspended=False):
        self.suspended = suspended


class ExplodingSuspension:
    @property
    def suspended(self):
        raise RuntimeError("suspension state unreadable")


class MutatingSuspension:
    def __init__(self, args):
        self.args = args

    @property
    def suspended(self):
        self.args["replicas"] = 99
        return False


def mutating_costs(args):
    class MutatingCosts(CostTable):
        def cost(self, tool, call_args):
            args["replicas"] = 99
            return super().cost(tool, call_args)

    return MutatingCosts(COSTS.version, COSTS.tools)


class UnavailableLedger(TaskLedger):
    def open_task(self, result, now):
        raise LedgerUnavailable("disk gone")


class RunningSink:
    def __init__(self, sink):
        self.sink = sink
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        asyncio.run_coroutine_threadsafe(sink.start(), self.loop).result(5)

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.sink.close(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bd-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


@pytest.fixture
def docket_paths(workdir):
    return workdir / "docket.log", workdir / "s" / "docket.sock"


@pytest.fixture
def sink(docket_paths):
    running = RunningSink(DocketSink(docket_paths[0], docket_paths[1], WRITERS, {os.getuid()}))
    yield running
    if running.thread.is_alive():
        running.stop()


@pytest.fixture
def ledger(workdir):
    ledger = TaskLedger.create(workdir / "ledger.db")
    yield ledger
    ledger.close()


@pytest.fixture
def make_decider(workdir, docket_paths, sink, ledger):
    def make(**overrides):
        options = {
            "config": DeciderConfig(DECIDER_ID, "decide-1", frozenset({CUSTODIAN_ID}), MAX_PROOF_AGE, BINDINGS),
            "ledger": ledger,
            "resolver": PinnedResolver({ISSUER_ID: ISSUER_KEY.public_key()}),
            "trust_policy": IssuerTrustPolicy(
                {
                    ISSUER_ID: IssuerAllowance(
                        tenants={TENANT: TenantAllowance(principals={PRINCIPAL})}, max_budget=100, max_depth=4
                    )
                }
            ),
            "policy": PolicyRef.from_dict("default", "1", POLICY),
            "suspension": Suspension(),
            "docket": DocketClient(docket_paths[1], "decide", "decide-1", DECIDE_KEY),
            "signing_key": DECIDE_KEY,
            "costs": COSTS,
        }
        options.update(overrides)
        return Decider(**options)

    return make


def make_root(*, budget=100, ttl=3600, scope=None, task_id="task-1"):
    return issue_task_root(
        ISSUER_KEY,
        issuer=ISSUER_ID,
        task_id=task_id,
        tenant_id=TENANT,
        principal=PRINCIPAL,
        purpose="release-bot",
        budget=budget,
        max_depth=4,
        issued_at=NOW,
        expires_at=NOW + ttl,
        scope=scope or SCOPE,
        subject=encode_public_key(AGENT_KEY.public_key()),
    )


def make_request(
    root=None,
    links=(),
    holder=AGENT_KEY,
    *,
    tool="deploy.service",
    resource="env/staging/api",
    args=ARGS,
    nonce="n-1",
    audience=CUSTODIAN_ID,
    proof_audience=DECIDER_ID,
    proof_args=None,
    at=NOW,
    trace_id="trace-1",
):
    root = root or make_root()
    leaf = links[-1] if links else root
    digest = request_digest(tool, resource, proof_args if proof_args is not None else args, nonce)
    proof = prove_leaf(leaf, holder, at, audience=proof_audience, request_digest=digest)
    return OperationRequest(
        tool=tool,
        resource=resource,
        args=args,
        nonce=nonce,
        task_root=root.encode(),
        links=tuple(link.encode() for link in links),
        leaf_proof=proof.encode(),
        trace_id=trace_id,
        audience=audience,
    )


def docket_entries(docket_paths):
    index = build_kid_index(WRITERS)
    records = [decode_record(line, index) for line in docket_paths[0].read_text().splitlines()]
    assert all(not isinstance(record, Refused) for record in records)
    return [record.entry for record in records]


def op_id_for(request, root, leaf_binding=None):
    return derive_op_id(TENANT, root.task_id, leaf_binding or root.binding(), request.digest())


def test_allowed_request_gets_a_clearance_that_decodes_to_the_operation(make_decider, ledger, docket_paths):
    root = make_root()
    request = make_request(root)
    decision = make_decider().check(request, NOW)
    assert (decision.allowed, decision.reason) == (True, "ok")
    clearance = decode_clearance(decision.clearance, PINNED, max_lifetime=MAX_PROOF_AGE)
    assert not isinstance(clearance, Refused)
    op_id = op_id_for(request, root)
    assert decision.op_id == op_id
    assert clearance.iss == DECIDER_ID
    assert clearance.aud == CUSTODIAN_ID
    assert clearance.iat == NOW
    assert clearance.exp == NOW + MAX_PROOF_AGE
    assert clearance.op_id == op_id
    assert (clearance.tenant, clearance.task) == (TENANT, "task-1")
    assert clearance.root_binding == root.binding()
    assert clearance.leaf_binding == root.binding()
    assert clearance.request_digest == request.digest()
    assert (clearance.tool, clearance.resource) == ("deploy.service", "env/staging/api")
    assert clearance.args_digest == args_digest(ARGS)
    assert clearance.cost == 1
    assert (clearance.credential_id, clearance.target) == ("deploy-api", "deploy.example")
    assert clearance.trace_id == "trace-1"
    assert clearance.entry_id == decision.entry_id
    assert ledger.reservation(TENANT, "task-1", op_id, NOW).state == "issued"


def test_allow_entry_records_who_what_policy_and_how(make_decider, docket_paths):
    root = make_root()
    decision = make_decider().check(make_request(root), NOW)
    [entry] = docket_entries(docket_paths)
    assert entry.entry_id == decision.entry_id
    assert (entry.decision, entry.reason, entry.hop, entry.component) == ("allow", "ok", "decide", DECIDER_ID)
    assert (entry.op_id, entry.trace_id, entry.at) == (decision.op_id, "trace-1", NOW)
    assert (entry.principal, entry.tenant, entry.task_root) == (PRINCIPAL, TENANT, root.binding())
    assert entry.agent_key == encode_public_key(AGENT_KEY.public_key())
    assert entry.links == ()
    assert (entry.tool, entry.resource, entry.args_digest, entry.cost) == (
        "deploy.service",
        "env/staging/api",
        args_digest(ARGS),
        1,
    )
    assert (entry.policy_id, entry.policy_version) == ("default", "1")
    assert entry.policy_digest == PolicyRef.from_dict("default", "1", POLICY).digest
    assert entry.verdict == "allow"
    assert entry.performed is False
    assert dict(entry.handles) == {
        "agent_key": entry.agent_key,
        "task": "task-1",
        "tenant": TENANT,
        "root": root.binding(),
    }


def test_delegated_request_binds_the_leaf_link(make_decider, docket_paths):
    root = make_root()
    link = delegate(
        root,
        root,
        AGENT_KEY,
        child_subject=encode_public_key(CHILD_KEY.public_key()),
        scope={"tools": ["deploy.service"], "resources": ["env/staging/*"], "max_cost_per_call": 2},
        budget=10,
        ttl=600,
        now=NOW,
    )
    request = make_request(root, (link,), CHILD_KEY)
    decision = make_decider().check(request, NOW)
    assert decision.allowed
    clearance = decode_clearance(decision.clearance, PINNED, max_lifetime=MAX_PROOF_AGE)
    assert clearance.leaf_binding == link.binding()
    assert clearance.op_id == op_id_for(request, root, link.binding())
    [entry] = docket_entries(docket_paths)
    assert entry.links == (link.binding(),)
    assert entry.agent_key == encode_public_key(CHILD_KEY.public_key())
    assert entry.handles["link"] == link.binding()


@pytest.mark.parametrize(
    ("reason", "request_options"),
    [
        ("malformed_request", {"nonce": "has space"}),
        ("malformed_request", {"tool": "deploy.*"}),
        ("malformed_request", {"args": {"replicas": 1.5}, "proof_args": ARGS}),
        ("malformed_request", {"args": {"replicas": 2**53}, "proof_args": ARGS}),
        ("unknown_audience", {"audience": "elsewhere.example"}),
        ("chain_invalid", {"proof_audience": "other-decider.example"}),
        ("chain_invalid", {"proof_args": {"service": "web", "replicas": 2}}),
        ("chain_invalid", {"at": NOW - MAX_PROOF_AGE - 1}),
        ("out_of_scope", {"resource": "env/prod/api"}),
        ("unknown_cost", {"tool": "deploy.restart"}),
        ("unknown_cost", {"tool": "signer.withdraw", "resource": "wallet/w1", "args": {"amount": "1"}}),
        ("cost_over_call_cap", {"tool": "deploy.rollback"}),
        ("no_binding", {"tool": "deploy.scale"}),
        ("policy_denied", {"tool": "deploy.delete"}),
        ("needs_approval", {"tool": "signer.withdraw", "resource": "wallet/w1", "args": {"amount": 2}}),
    ],
)
def test_refusals_return_no_clearance_reserve_nothing_and_write_an_entry(
    make_decider, ledger, docket_paths, reason, request_options
):
    root = make_root()
    request = make_request(root, **request_options)
    decision = make_decider().check(request, NOW)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, reason, None)
    [entry] = docket_entries(docket_paths)
    assert (entry.entry_id, entry.decision, entry.reason) == (decision.entry_id, "refuse", reason)
    with pytest.raises(LedgerRefused, match="unknown task"):
        ledger.task_budget(TENANT, "task-1", NOW)


def test_policy_refusal_entry_names_the_rule(make_decider, docket_paths):
    make_decider().check(make_request(tool="deploy.delete"), NOW)
    [entry] = docket_entries(docket_paths)
    assert (entry.rule, entry.verdict, entry.policy_id) == ("no-delete", "deny", "default")


def test_suspended_decider_refuses(make_decider, docket_paths):
    decision = make_decider(suspension=Suspension(True)).check(make_request(), NOW)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "suspended", None)


def test_revoked_task_is_refused_as_chain_invalid(make_decider, ledger):
    ledger.revoke_task(TENANT, "task-1", NOW)
    decision = make_decider().check(make_request(), NOW)
    assert (decision.reason, decision.clearance) == ("chain_invalid", None)


def test_exhausted_budget_is_refused_by_the_ledger(make_decider):
    root = make_root(budget=1)
    decider = make_decider()
    assert decider.check(make_request(root, nonce="n-1"), NOW).allowed
    decision = decider.check(make_request(root, nonce="n-2"), NOW)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "reservation_refused", None)


def test_unavailable_ledger_is_refused(make_decider, workdir):
    path = workdir / "other.db"
    TaskLedger.create(path).close()
    unavailable = UnavailableLedger(path)
    decision = make_decider(ledger=unavailable).check(make_request(), NOW)
    unavailable.close()
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "ledger_unavailable", None)


def test_unexpected_error_is_refused_as_internal_error(make_decider, docket_paths):
    decision = make_decider(suspension=ExplodingSuspension()).check(make_request(), NOW)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "internal_error", None)
    [entry] = docket_entries(docket_paths)
    assert entry.reason == "internal_error"


def test_error_after_issue_returns_no_clearance_and_leaves_the_reservation_issued(make_decider, ledger):
    root = make_root()
    request = make_request(root)
    decider = make_decider(signing_key=object())
    decision = decider.check(request, NOW)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "internal_error", None)
    op_id = op_id_for(request, root)
    assert ledger.reservation(TENANT, "task-1", op_id, NOW).state == "issued"
    assert decider.reconcile(NOW + MAX_PROOF_AGE) == (op_id,)
    assert ledger.reservation(TENANT, "task-1", op_id, NOW + MAX_PROOF_AGE).state == "outcome_unknown"


def test_no_clearance_when_the_docket_does_not_acknowledge(make_decider, ledger, sink, docket_paths):
    root = make_root()
    request = make_request(root)
    decider = make_decider()
    sink.stop()
    decision = decider.check(request, NOW)
    assert (decision.allowed, decision.reason, decision.clearance, decision.entry_id) == (
        False,
        "docket_unavailable",
        None,
        None,
    )
    op_id = op_id_for(request, root)
    assert decision.op_id == op_id
    assert ledger.reservation(TENANT, "task-1", op_id, NOW).state == "issued"
    assert decider.check(request, NOW).reason == "already_issued"


def test_refusal_stands_when_its_entry_cannot_be_written(make_decider, sink):
    sink.stop()
    decision = make_decider().check(make_request(resource="env/prod/api"), NOW)
    assert (decision.allowed, decision.reason, decision.clearance, decision.entry_id) == (
        False,
        "out_of_scope",
        None,
        None,
    )


def test_docket_failure_is_reconciled_to_outcome_unknown(make_decider, ledger, sink, docket_paths, workdir):
    root = make_root()
    request = make_request(root)
    decider = make_decider()
    sink.stop()
    decider.check(request, NOW)
    restarted = RunningSink(DocketSink(docket_paths[0], docket_paths[1], WRITERS, {os.getuid()}))
    try:
        op_id = op_id_for(request, root)
        assert decider.reconcile(NOW + MAX_PROOF_AGE) == (op_id,)
        assert ledger.reservation(TENANT, "task-1", op_id, NOW + MAX_PROOF_AGE).state == "outcome_unknown"
        entry = docket_entries(docket_paths)[-1]
        assert (entry.decision, entry.outcome, entry.op_id) == ("reconcile", "outcome_unknown", op_id)
    finally:
        restarted.stop()


def test_reconcile_waits_for_clearance_expiry(make_decider, ledger, docket_paths):
    root = make_root()
    request = make_request(root)
    decider = make_decider()
    decision = decider.check(request, NOW)
    assert decider.reconcile(NOW + MAX_PROOF_AGE - 1) == ()
    assert ledger.reservation(TENANT, "task-1", decision.op_id, NOW).state == "issued"
    assert decider.reconcile(NOW + MAX_PROOF_AGE) == (decision.op_id,)
    assert ledger.reservation(TENANT, "task-1", decision.op_id, NOW + MAX_PROOF_AGE).state == "outcome_unknown"
    entries = docket_entries(docket_paths)
    assert [entry.decision for entry in entries] == ["allow", "reconcile"]
    assert entries[1].parent_entry == decision.entry_id
    assert entries[1].reason == "clearance_expired"
    assert decider.reconcile(NOW + MAX_PROOF_AGE + 1) == ()


def test_record_outcome_marks_done_and_writes_an_entry(make_decider, ledger, docket_paths):
    decider = make_decider()
    decision = decider.check(make_request(), NOW)
    entry_id = decider.record_outcome(decision.op_id, "done", "receipt-1", now=NOW + 1)
    assert ledger.reservation(TENANT, "task-1", decision.op_id, NOW + 1).state == "done"
    entry = docket_entries(docket_paths)[-1]
    assert (entry.entry_id, entry.decision, entry.outcome, entry.performed) == (entry_id, "outcome", "done", True)
    assert (entry.receipt_digest, entry.parent_entry, entry.op_id) == ("receipt-1", decision.entry_id, decision.op_id)
    assert decider.reconcile(NOW + MAX_PROOF_AGE) == ()


def test_record_outcome_refuses_an_unknown_op_id_or_outcome(make_decider):
    decider = make_decider()
    decision = decider.check(make_request(), NOW)
    with pytest.raises(ValueError, match="no issued clearance"):
        decider.record_outcome("unknown-op", "done", now=NOW)
    with pytest.raises(ValueError, match="outcome must be one of"):
        decider.record_outcome(decision.op_id, "released", now=NOW)


@pytest.mark.parametrize(
    ("finish", "state"),
    [
        (lambda decider, op_id: None, "issued"),
        (lambda decider, op_id: decider.record_outcome(op_id, "done", now=NOW + 1), "done"),
        (lambda decider, op_id: decider.record_outcome(op_id, "outcome_unknown", now=NOW + 1), "outcome_unknown"),
    ],
)
def test_identical_request_replay_is_refused_with_the_stored_state(make_decider, docket_paths, finish, state):
    root = make_root()
    request = make_request(root)
    decider = make_decider()
    first = decider.check(request, NOW)
    finish(decider, first.op_id)
    replay = decider.check(request, NOW + 2)
    assert (replay.allowed, replay.reason, replay.clearance, replay.op_id) == (
        False,
        f"already_{state}",
        None,
        first.op_id,
    )
    entry = docket_entries(docket_paths)[-1]
    assert (entry.decision, entry.reason, entry.op_id) == ("refuse", f"already_{state}", first.op_id)


def test_replay_after_restart_is_refused_from_the_ledger(make_decider):
    request = make_request()
    first = make_decider().check(request, NOW)
    replay = make_decider().check(request, NOW + 1)
    assert first.allowed
    assert (replay.reason, replay.clearance) == ("already_issued", None)


def test_clearance_expiry_is_bounded_by_the_proof_age(make_decider):
    decision = make_decider().check(make_request(make_root(ttl=3600)), NOW)
    clearance = decode_clearance(decision.clearance, PINNED, max_lifetime=MAX_PROOF_AGE)
    assert clearance.exp - clearance.iat == MAX_PROOF_AGE


def test_clearance_expiry_is_clamped_to_the_chain(make_decider):
    decision = make_decider().check(make_request(make_root(ttl=20)), NOW)
    clearance = decode_clearance(decision.clearance, PINNED, max_lifetime=MAX_PROOF_AGE)
    assert clearance.exp == NOW + 20


def test_tampered_clearance_is_detected(make_decider):
    decision = make_decider().check(make_request(), NOW)
    body, _, signature = decision.clearance.partition(".")
    raw = b64u_decode(body).replace(b'"deploy-api"', b'"signer-key"')
    result = decode_clearance(f"{b64u(raw)}.{signature}", PINNED, max_lifetime=MAX_PROOF_AGE)
    assert isinstance(result, Refused)
    assert result.reason == "bad_signature"


def test_invalid_trace_id_is_replaced(make_decider, docket_paths):
    decision = make_decider().check(replace(make_request(), trace_id="bad trace"), NOW)
    clearance = decode_clearance(decision.clearance, PINNED, max_lifetime=MAX_PROOF_AGE)
    assert clearance.trace_id != "bad trace"
    assert len(clearance.trace_id) == 32


@pytest.mark.parametrize("hook", ["suspension", "costs"])
def test_args_mutated_during_check_change_no_digest(make_decider, ledger, docket_paths, hook):
    args = dict(ARGS)
    root = make_root()
    request = make_request(root, args=args)
    expected_request = request.digest()
    expected_args = args_digest(args)
    override = {"suspension": MutatingSuspension(args)} if hook == "suspension" else {"costs": mutating_costs(args)}
    decision = make_decider(**override).check(request, NOW)
    assert args["replicas"] == 99
    assert decision.allowed
    clearance = decode_clearance(decision.clearance, PINNED, max_lifetime=MAX_PROOF_AGE)
    op_id = derive_op_id(TENANT, "task-1", root.binding(), expected_request)
    assert (clearance.request_digest, clearance.args_digest) == (expected_request, expected_args)
    assert decision.op_id == clearance.op_id == op_id
    [entry] = docket_entries(docket_paths)
    assert (entry.args_digest, entry.op_id) == (expected_args, op_id)
    operation = Operation(
        op_id=op_id,
        tenant_id=TENANT,
        task_id="task-1",
        leaf_binding=root.binding(),
        tool="deploy.service",
        resource="env/staging/api",
        args_digest=expected_args,
        cost=1,
        verdict_allowed=True,
        expires_at=clearance.exp,
    )
    assert ledger.reservation(TENANT, "task-1", op_id, NOW).digest == operation.digest()


def test_args_snapshot_is_deeply_frozen():
    snapshot = snapshot_args({"a": {"b": [1, {"c": 2}]}})
    with pytest.raises(TypeError):
        snapshot.value["a"]["x"] = 1
    with pytest.raises(TypeError):
        snapshot.value["a"]["b"][1]["c"] = 3
    assert isinstance(snapshot.value["a"]["b"], tuple)
    thawed = snapshot.thaw()
    thawed["a"]["b"].append(3)
    assert snapshot.thaw() == {"a": {"b": [1, {"c": 2}]}}
