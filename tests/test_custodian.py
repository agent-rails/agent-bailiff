import os
import shutil
import sqlite3
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from agent_warrant.identity import encode_public_key
from agent_warrant.ledger import TaskLedger
from agent_warrant.resolver import PinnedResolver
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_decide import (
    AGENT_KEY,
    BINDINGS,
    CUSTODIAN_ID,
    DECIDE_KEY,
    DECIDER_ID,
    ISSUER_ID,
    ISSUER_KEY,
    MAX_PROOF_AGE,
    NOW,
    POLICY,
    PRINCIPAL,
    SIGNER_CUSTODIAN_ID,
    TENANT,
    RunningSink,
    Suspension,
    make_request,
    make_root,
)

from agent_bailiff.custodian import (
    BindingTable,
    ClaimsStore,
    CredentialBinding,
    CredentialStore,
    Custodian,
    CustodianConfig,
    LocalBackend,
    Refused,
    Released,
)
from agent_bailiff.decide import (
    Clearance,
    CostTable,
    Decider,
    DeciderConfig,
    PolicyRef,
    TargetBinding,
    args_digest,
    decode_clearance,
    derive_op_id,
    encode_clearance,
)
from agent_bailiff.docket import DocketClient, DocketSink, decode_record
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.signing import Refused as SigningRefused
from agent_bailiff.signing import token_hash

pytestmark = pytest.mark.skipif(
    not hasattr(TaskLedger, "open_read_only"),
    reason="needs agent-warrant with TaskLedger.open_read_only (unreleased PR #15); move the pin after its release",
)

UID = os.geteuid()
GID = os.getegid()
CUSTODIAN_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(4, 36)))
FORGER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(5, 37)))
WRITERS = {
    "decide": {"decide-1": DECIDE_KEY.public_key()},
    "custodian": {"custodian-1": CUSTODIAN_KEY.public_key()},
}
DEPLOY_SECRET = b"Bearer deploy-secret"
SIGNER_SECRET = b"Bearer signer-secret"
CANARY_SECRET = b"Bearer canary-secret"
COSTS = CostTable(1, {"deploy.service": 1, "deploy.canary": 1})
DECIDE_BINDINGS = (
    *BINDINGS,
    TargetBinding(TENANT, "deploy.canary", "env/staging/*", "canary-key", "deploy.example", CUSTODIAN_ID),
)
CUSTODIAN_BINDINGS = (
    CredentialBinding(
        TENANT, "deploy.service", "env/staging/*", "deploy-api", "deploy.example", "Authorization", False
    ),
    CredentialBinding(TENANT, "deploy.canary", "env/staging/*", "canary-key", "deploy.example", "Authorization", True),
)
RATE_LIMIT = 3


class AckDocket:
    def __init__(self, inner, ack):
        self.inner = inner
        self.ack = ack

    def append(self, entry):
        return self.ack(self.inner.append(entry))


class ShiftedExpiryReader:
    def __init__(self, inner, shift):
        self.inner = inner
        self.shift = shift

    def is_revoked(self, context):
        return self.inner.is_revoked(context)

    def reservation_readonly(self, tenant_id, task_id, op_id):
        reservation = self.inner.reservation_readonly(tenant_id, task_id, op_id)
        return replace(reservation, expires_at=reservation.expires_at - self.shift)


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bc-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


@pytest.fixture
def private(workdir):
    def make(name):
        directory = workdir / name
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
        return directory

    return make


@pytest.fixture
def sink(workdir):
    running = RunningSink(DocketSink(workdir / "docket.log", workdir / "s" / "docket.sock", WRITERS, {UID}))
    yield running
    if running.thread.is_alive():
        running.stop()


@pytest.fixture
def ledger_path(workdir):
    directory = workdir / "ledger"
    directory.mkdir(mode=0o750)
    os.chown(directory, -1, GID)
    os.chmod(directory, 0o750)
    return directory / "ledger.db"


@pytest.fixture
def writer(ledger_path):
    ledger = TaskLedger.create(ledger_path, shared_group=GID)
    yield ledger
    ledger.close()


@pytest.fixture
def reader(writer, ledger_path):
    ledger = TaskLedger.open_read_only(ledger_path, UID, GID)
    yield ledger
    ledger.close()


@pytest.fixture
def state(private):
    directory = private("custodian")
    backend = LocalBackend.generate(directory / "kek")
    store = CredentialStore.create(directory / "credentials.db", backend)
    store.put(TENANT, "deploy-api", "deploy.example", DEPLOY_SECRET)
    store.put(TENANT, "signer", "signer.example", SIGNER_SECRET)
    store.put(TENANT, "signer", "deploy.example", SIGNER_SECRET)
    store.put(TENANT, "canary-key", "deploy.example", CANARY_SECRET)
    ClaimsStore.create(directory / "claims.db").close()
    store.close()
    return directory


def docket_client(workdir, private, writer_name, kid, key):
    state_dir = workdir / f"{writer_name}-state"
    if not state_dir.exists():
        state_dir = private(f"{writer_name}-state")
    return DocketClient(workdir / "s" / "docket.sock", writer_name, kid, key, sink_uid=UID, state_dir=state_dir)


def trust_policy():
    return IssuerTrustPolicy(
        {
            ISSUER_ID: IssuerAllowance(
                tenants={TENANT: TenantAllowance(principals={PRINCIPAL})}, max_budget=100, max_depth=4
            )
        }
    )


@pytest.fixture
def make_decider(workdir, private, sink, writer):
    def make(bindings=DECIDE_BINDINGS):
        return Decider(
            config=DeciderConfig(
                DECIDER_ID,
                "decide-1",
                frozenset({CUSTODIAN_ID, SIGNER_CUSTODIAN_ID}),
                MAX_PROOF_AGE,
                bindings,
                "decide",
            ),
            ledger=writer,
            resolver=PinnedResolver({ISSUER_ID: ISSUER_KEY.public_key()}),
            trust_policy=trust_policy(),
            policy=PolicyRef.from_dict("default", "1", POLICY),
            suspension=Suspension(),
            docket=docket_client(workdir, private, "decide", "decide-1", DECIDE_KEY),
            signing_key=DECIDE_KEY,
            costs=COSTS,
        )

    return make


@pytest.fixture
def make_custodian(workdir, private, sink, reader, state):
    opened = []

    def make(docket=None, ledger=None, claims=None, **config):
        options = {
            "custodian_id": CUSTODIAN_ID,
            "decider_id": DECIDER_ID,
            "decide_keys": {"decide-1": DECIDE_KEY.public_key()},
            "docket_writer": "custodian",
            "max_proof_age": MAX_PROOF_AGE,
            "max_clearance_lifetime": MAX_PROOF_AGE,
            "skew_seconds": 5,
            "rate_limit": RATE_LIMIT,
            "rate_window": 60,
        }
        options.update(config)
        store = CredentialStore.open(state / "credentials.db", LocalBackend.load(state / "kek"))
        claims = claims or ClaimsStore.open(state / "claims.db")
        opened.extend((store, claims))
        return Custodian(
            config=CustodianConfig(**options),
            bindings=BindingTable(CUSTODIAN_BINDINGS),
            store=store,
            claims=claims,
            ledger=ledger or reader,
            resolver=PinnedResolver({ISSUER_ID: ISSUER_KEY.public_key()}),
            trust_policy=trust_policy(),
            docket=docket or docket_client(workdir, private, "custodian", "custodian-1", CUSTODIAN_KEY),
        )

    yield make
    for item in opened:
        item.close()


@pytest.fixture
def issue(make_decider):
    decider = make_decider()

    def run(root=None, **options):
        request = make_request(root or make_root(), **options)
        decision = decider.check(request, NOW)
        assert decision.allowed, decision.reason
        return request, decision.clearance

    return run


def docket_entries(workdir):
    index = build_kid_index(WRITERS)
    records = [decode_record(line, index) for line in (workdir / "docket.log").read_text().splitlines()]
    assert all(not isinstance(record, SigningRefused) for record in records)
    return [record.entry for record in records]


def custodian_entries(workdir):
    return [entry for entry in docket_entries(workdir) if entry.hop == "custodian"]


def clearance_for(request, root, **overrides):
    fields = {
        "iss": DECIDER_ID,
        "aud": CUSTODIAN_ID,
        "iat": NOW,
        "exp": NOW + MAX_PROOF_AGE,
        "op_id": derive_op_id(TENANT, root.task_id, root.binding(), request.digest()),
        "tenant": TENANT,
        "task": root.task_id,
        "root_binding": root.binding(),
        "leaf_binding": root.binding(),
        "request_digest": request.digest(),
        "tool": request.tool,
        "resource": request.resource,
        "args_digest": args_digest(request.args),
        "cost": 1,
        "credential_id": "deploy-api",
        "target": "deploy.example",
        "trace_id": "trace-1",
        "entry_id": "entry-1",
    }
    fields.update(overrides)
    return Clearance(**fields)


def sign_clearance(clearance, key=DECIDE_KEY):
    return encode_clearance(clearance, key, "decide-1")


def test_valid_release_returns_the_secret_and_records_a_release_entry(make_custodian, issue, workdir):
    request, token = issue()
    result = make_custodian().release(token, request, NOW + 1)
    assert isinstance(result, Released)
    assert (result.header_name, result.header_value, result.tier) == (
        "Authorization",
        DEPLOY_SECRET.decode(),
        "gateway-bound",
    )
    assert DEPLOY_SECRET.decode() not in repr(result)
    clearance = decode_clearance(token, WRITERS["decide"], max_lifetime=MAX_PROOF_AGE)
    [entry] = custodian_entries(workdir)
    assert (entry.entry_id, entry.decision, entry.reason, entry.performed) == (result.entry_id, "release", "ok", True)
    assert (entry.credential_tier, entry.clearance_digest) == ("gateway-bound", token_hash(token))
    assert (entry.op_id, entry.trace_id, entry.parent_entry) == (clearance.op_id, "trace-1", clearance.entry_id)
    assert (entry.component, entry.tenant, entry.principal) == (CUSTODIAN_ID, TENANT, PRINCIPAL)
    assert result.op_id == clearance.op_id
    assert DEPLOY_SECRET not in (workdir / "docket.log").read_bytes()


@pytest.mark.parametrize("token", [None, ""])
def test_missing_clearance_is_refused(make_custodian, issue, token):
    request, _ = issue()
    assert make_custodian().release(token, request, NOW + 1) == Refused("clearance_missing")


@pytest.mark.parametrize(("token", "request_value"), [(123, None), ("x.y", object()), ("a" * 70000, 5)])
def test_garbage_input_is_refused_without_raising(make_custodian, issue, token, request_value):
    request, _ = issue()
    result = make_custodian().release(token, request_value if request_value is not None else request, NOW + 1)
    assert isinstance(result, Refused)
    assert result.reason in {"clearance_invalid", "malformed_request"}


def test_clearance_with_a_valid_token_but_garbage_request_is_refused(make_custodian, issue):
    _, token = issue()
    assert make_custodian().release(token, object(), NOW + 1) == Refused("malformed_request")


def test_forged_clearance_is_refused(make_custodian, issue):
    root = make_root()
    request, token = issue(root)
    clearance = decode_clearance(token, WRITERS["decide"], max_lifetime=MAX_PROOF_AGE)
    forged = sign_clearance(clearance, FORGER_KEY)
    assert make_custodian().release(forged, request, NOW + 1) == Refused("clearance_invalid")


def test_tampered_clearance_is_refused(make_custodian, issue):
    request, token = issue()
    body, _, signature = token.partition(".")
    tampered = f"{body[:-2]}{'A' if body[-2] != 'A' else 'B'}{body[-1]}.{signature}"
    assert make_custodian().release(tampered, request, NOW + 1) == Refused("clearance_invalid")


def test_expired_clearance_is_refused(make_custodian, issue):
    request, token = issue()
    assert make_custodian().release(token, request, NOW + MAX_PROOF_AGE) == Refused("clearance_expired")


def test_clearance_for_another_custodian_is_refused(make_custodian, issue):
    request, token = issue()
    custodian = make_custodian(custodian_id=SIGNER_CUSTODIAN_ID)
    assert custodian.release(token, request, NOW + 1) == Refused("clearance_wrong_audience")


def test_clearance_from_another_decider_is_refused(make_custodian, issue):
    request, token = issue()
    custodian = make_custodian(decider_id="other-decide.example")
    assert custodian.release(token, request, NOW + 1) == Refused("clearance_wrong_issuer")


def test_clearance_naming_another_credential_of_the_tenant_is_refused(make_custodian, make_decider, state):
    bindings = (TargetBinding(TENANT, "deploy.service", "env/staging/*", "signer", "deploy.example", CUSTODIAN_ID),)
    request = make_request(make_root())
    decision = make_decider(bindings).check(request, NOW)
    assert decision.allowed
    result = make_custodian().release(decision.clearance, request, NOW + 1)
    assert result == Refused("binding_mismatch")


def test_mutated_args_fail_the_leaf_proof(make_custodian, issue):
    request, token = issue()
    mutated = replace(request, args={"service": "api", "replicas": 99})
    assert make_custodian().release(token, mutated, NOW + 1) == Refused("chain_invalid")


def test_clearance_for_another_request_of_the_same_task_is_refused(make_custodian, issue):
    root = make_root()
    _, first_token = issue(root, nonce="n-1")
    second_request, _ = issue(root, nonce="n-2")
    assert make_custodian().release(first_token, second_request, NOW + 1) == Refused("clearance_mismatch")


def test_request_outside_the_chain_scope_is_refused(make_custodian):
    root = make_root(scope={"tools": ["deploy.service"], "resources": ["env/staging/web"], "max_cost_per_call": 5})
    request = make_request(root)
    token = sign_clearance(clearance_for(request, root))
    assert make_custodian().release(token, request, NOW + 1) == Refused("out_of_scope")


def test_revoked_chain_is_refused(make_custodian, issue, writer):
    request, token = issue()
    writer.revoke_task(TENANT, "task-1", NOW)
    assert make_custodian().release(token, request, NOW + 1) == Refused("chain_invalid")


def test_clearance_without_a_reservation_is_refused(make_custodian):
    root = make_root()
    request = make_request(root)
    token = sign_clearance(clearance_for(request, root))
    assert make_custodian().release(token, request, NOW + 1) == Refused("reservation_missing")


def test_reservation_that_is_no_longer_issued_is_refused(make_custodian, issue, writer):
    request, token = issue()
    clearance = decode_clearance(token, WRITERS["decide"], max_lifetime=MAX_PROOF_AGE)
    writer.mark_done(TENANT, "task-1", clearance.op_id, NOW)
    assert make_custodian().release(token, request, NOW + 1) == Refused("reservation_not_issued")


def test_clearance_that_disagrees_with_the_reservation_is_refused(make_custodian, issue):
    request, token = issue()
    clearance = decode_clearance(token, WRITERS["decide"], max_lifetime=MAX_PROOF_AGE)
    resigned = sign_clearance(replace(clearance, cost=2))
    assert make_custodian().release(resigned, request, NOW + 1) == Refused("reservation_mismatch")


def test_expired_reservation_is_refused(make_custodian, issue, reader):
    request, token = issue()
    custodian = make_custodian(ledger=ShiftedExpiryReader(reader, MAX_PROOF_AGE - 1))
    assert custodian.release(token, request, NOW + 1) == Refused("reservation_expired")


def test_second_release_of_an_op_id_is_refused_also_after_a_restart(make_custodian, issue):
    request, token = issue()
    assert isinstance(make_custodian().release(token, request, NOW + 1), Released)
    custodian = make_custodian()
    assert custodian.release(token, request, NOW + 2) == Refused("already_issued")
    assert custodian.release(token, request, NOW + 3) == Refused("already_issued")


def test_releases_per_task_are_rate_limited(make_custodian, issue):
    root = make_root()
    custodian = make_custodian()
    issued = [issue(root, nonce=f"n-{index}") for index in range(RATE_LIMIT + 1)]
    results = [custodian.release(token, request, NOW + 1) for request, token in issued]
    assert all(isinstance(result, Released) for result in results[:RATE_LIMIT])
    assert results[RATE_LIMIT] == Refused("rate_limited")


def test_canary_release_records_a_deny_and_an_alert_and_later_calls_are_refused(make_custodian, issue, workdir, state):
    root = make_root()
    canary_request, canary_token = issue(root, tool="deploy.canary")
    later_request, later_token = issue(root, nonce="n-2")
    custodian = make_custodian()
    assert custodian.release(canary_token, canary_request, NOW + 1) == Refused("canary")
    [alert] = custodian_entries(workdir)
    assert (alert.decision, alert.reason, alert.performed, alert.credential_tier) == ("alert", "canary", False, None)
    assert dict(alert.handles)["task"] == "task-1"
    claims = ClaimsStore.open(state / "claims.db")
    try:
        assert claims.is_denied(TENANT, "task-1")
    finally:
        claims.close()
    assert custodian.release(later_token, later_request, NOW + 1) == Refused("task_denied")
    assert make_custodian().release(later_token, later_request, NOW + 2) == Refused("task_denied")
    assert CANARY_SECRET not in (workdir / "docket.log").read_bytes()


def test_ciphertext_moved_onto_the_binding_does_not_decrypt(make_custodian, issue, state):
    request, token = issue()
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute(
        "UPDATE credentials SET (wrapped_dek, nonce, ciphertext) = "
        "(SELECT wrapped_dek, nonce, ciphertext FROM credentials WHERE credential_id = 'signer' "
        "AND target = 'deploy.example') WHERE credential_id = 'deploy-api'"
    )
    connection.commit()
    connection.close()
    assert make_custodian().release(token, request, NOW + 1) == Refused("credential_unavailable")


def test_no_secret_without_a_docket_acknowledgement_and_the_claim_stays(make_custodian, issue, sink, workdir):
    request, token = issue()
    custodian = make_custodian()
    sink.stop()
    assert custodian.release(token, request, NOW + 1) == Refused("docket_unavailable")
    restarted = RunningSink(DocketSink(workdir / "docket.log", workdir / "s" / "docket.sock", WRITERS, {UID}))
    try:
        assert make_custodian().release(token, request, NOW + 2) == Refused("already_issued")
    finally:
        restarted.stop()


@pytest.mark.parametrize(
    "ack",
    [
        lambda record: None,
        lambda record: replace(record, entry=replace(record.entry, op_id="other-op")),
        lambda record: replace(record, writer="decide"),
        lambda record: replace(record, token=""),
    ],
)
def test_mismatched_docket_acknowledgement_returns_no_secret(make_custodian, issue, workdir, private, ack):
    request, token = issue()
    inner = docket_client(workdir, private, "custodian", "custodian-1", CUSTODIAN_KEY)
    custodian = make_custodian(docket=AckDocket(inner, ack))
    assert custodian.release(token, request, NOW + 1) == Refused("docket_unavailable")


def test_refusal_reasons_carry_no_secret_or_path(make_custodian, issue, state):
    request, token = issue()
    custodian = make_custodian()
    custodian.release(token, request, NOW + 1)
    result = custodian.release(token, request, NOW + 2)
    assert isinstance(result, Refused)
    assert str(state) not in repr(result)
    assert "secret" not in repr(result)


def test_agent_key_holder_is_recorded(make_custodian, issue, workdir):
    request, token = issue()
    make_custodian().release(token, request, NOW + 1)
    [entry] = custodian_entries(workdir)
    assert entry.agent_key == encode_public_key(AGENT_KEY.public_key())


def claims_with_a_deny_landing_before_the_claim(path):
    class DenyLandsBeforeClaim(ClaimsStore):
        def claim(self, *args):
            other = ClaimsStore.open(path)
            try:
                other.deny(TENANT, "task-1", NOW)
            finally:
                other.close()
            return super().claim(*args)

    return DenyLandsBeforeClaim.open(path)


def test_deny_committed_before_the_claim_stops_the_release(make_custodian, issue, state):
    request, token = issue()
    custodian = make_custodian(claims=claims_with_a_deny_landing_before_the_claim(state / "claims.db"))
    assert custodian.release(token, request, NOW + 1) == Refused("task_denied")


def test_canary_deny_that_fails_to_persist_still_stops_later_releases(make_custodian, issue, state):
    root = make_root()
    canary_request, canary_token = issue(root, tool="deploy.canary")
    later_request, later_token = issue(root, nonce="n-2")
    connection = sqlite3.connect(state / "claims.db")
    connection.execute("CREATE TRIGGER fail_deny BEFORE INSERT ON denies BEGIN SELECT RAISE(ABORT, 'disk'); END")
    connection.commit()
    custodian = make_custodian()
    assert custodian.release(canary_token, canary_request, NOW + 1) == Refused("canary")
    connection.execute("DROP TRIGGER fail_deny")
    connection.commit()
    connection.close()
    assert custodian.release(later_token, later_request, NOW + 2) == Refused("task_denied")


def test_canary_hit_by_a_rate_limited_task_still_denies_and_alerts(make_custodian, issue, workdir, state):
    root = make_root()
    custodian = make_custodian()
    for index in range(RATE_LIMIT):
        request, token = issue(root, nonce=f"n-{index}")
        assert isinstance(custodian.release(token, request, NOW + 1), Released)
    canary_request, canary_token = issue(root, tool="deploy.canary")
    assert custodian.release(canary_token, canary_request, NOW + 1) == Refused("canary")
    assert [entry.reason for entry in custodian_entries(workdir) if entry.decision == "alert"] == ["canary"]
    claims = ClaimsStore.open(state / "claims.db")
    try:
        assert claims.is_denied(TENANT, "task-1")
    finally:
        claims.close()


def test_credential_failure_before_the_claim_leaves_the_op_id_releasable(make_custodian, issue, state):
    request, token = issue()
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute("DELETE FROM credentials WHERE credential_id = 'deploy-api'")
    connection.commit()
    connection.close()
    custodian = make_custodian()
    assert custodian.release(token, request, NOW + 1) == Refused("credential_unavailable")
    store = CredentialStore.open(state / "credentials.db", LocalBackend.load(state / "kek"))
    try:
        store.put(TENANT, "deploy-api", "deploy.example", DEPLOY_SECRET)
    finally:
        store.close()
    result = custodian.release(token, request, NOW + 2)
    assert isinstance(result, Released)
    assert result.header_value == DEPLOY_SECRET.decode()
