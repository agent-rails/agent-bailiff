import json
import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from agent_warrant.canonical import canonicalize
from agent_warrant.chain import delegate
from agent_warrant.encoding import b64u, b64u_decode
from agent_warrant.identity import encode_public_key
from agent_warrant.ledger import LedgerUnavailable, TaskLedger
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import issue_task_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_control_suspension import shared_suspension
from test_decide import (
    AGENT_KEY,
    BINDINGS,
    CHILD_KEY,
    COSTS,
    CUSTODIAN_ID,
    DECIDE_KEY,
    DECIDER_ID,
    ISSUER_ID,
    ISSUER_KEY,
    MAX_PROOF_AGE,
    NOW,
    POLICY,
    PRINCIPAL,
    SCOPE,
    SIGNER_CUSTODIAN_ID,
    TENANT,
    RunningSink,
    make_request,
    make_root,
)

from agent_bailiff.control import Control, ControlRefused, ControlUnrecorded, Suspension
from agent_bailiff.decide import Decider, DeciderConfig, PolicyRef
from agent_bailiff.docket import DocketClient, DocketSink, Grant, Record, decode_record, encode_record
from agent_bailiff.docket.entry import Entry
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.signing import Refused

CUSTODIAN_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(4, 36)))
CONTROL_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(6, 38)))
FORGER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(7, 39)))
GRANTER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(8, 40)))
OTHER_ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
OTHER_ISSUER_ID = "issuer.other"
OTHER_TENANT = "tenant-b"
VERIFIED_WRITERS = {
    "decide": {"decide-1": DECIDE_KEY.public_key()},
    "custodian": {"custodian-1": CUSTODIAN_KEY.public_key()},
}
GRANT_WRITERS = {**VERIFIED_WRITERS, "issuer": {"issuer-1": GRANTER_KEY.public_key()}}
SINK_WRITERS = {**VERIFIED_WRITERS, "control": {"control-1": CONTROL_KEY.public_key()}}
RESOLVER = PinnedResolver({ISSUER_ID: ISSUER_KEY.public_key(), OTHER_ISSUER_ID: OTHER_ISSUER_KEY.public_key()})
TRUST_POLICY = IssuerTrustPolicy(
    {
        ISSUER_ID: IssuerAllowance(
            tenants={TENANT: TenantAllowance(principals={PRINCIPAL})}, max_budget=100, max_depth=4
        ),
        OTHER_ISSUER_ID: IssuerAllowance(
            tenants={OTHER_TENANT: TenantAllowance(principals={PRINCIPAL})}, max_budget=100, max_depth=4
        ),
    }
)
LINK_SCOPE = {"permissions": [{"tools": ["deploy.service"], "resources": ["env/staging/*"], "max_cost_per_call": 2}]}
LEVELS = ("link", "task", "tenant", "root")


class FailingDocket:
    def append(self, entry):
        raise OSError("docket sink is down")


class MemoryDocket:
    def __init__(self, ack=None):
        self.entries = []
        self.ack = ack

    def append(self, entry):
        self.entries.append(entry)
        record = Record("control", len(self.entries), None, entry, "control-1", "token")
        return self.ack(record) if self.ack else record


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bk-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


def private_dir(workdir, name):
    path = workdir / name
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


@pytest.fixture
def sink(workdir):
    running = RunningSink(
        DocketSink(workdir / "docket.log", workdir / "s" / "docket.sock", SINK_WRITERS, {os.getuid()})
    )
    yield running
    if running.thread.is_alive():
        running.stop()


@pytest.fixture
def ledger(workdir):
    ledger = TaskLedger.create(workdir / "ledger.db")
    yield ledger
    ledger.close()


@pytest.fixture
def suspension(workdir):
    return Suspension(shared_suspension(workdir), os.getegid())


def client(workdir, writer, kid, key):
    state = workdir / f"{writer}-state"
    if not state.exists():
        private_dir(workdir, f"{writer}-state")
    return DocketClient(workdir / "s" / "docket.sock", writer, kid, key, sink_uid=os.getuid(), state_dir=state)


@pytest.fixture
def decider(workdir, sink, ledger, suspension):
    return Decider(
        config=DeciderConfig(
            DECIDER_ID, "decide-1", frozenset({CUSTODIAN_ID, SIGNER_CUSTODIAN_ID}), MAX_PROOF_AGE, BINDINGS, "decide"
        ),
        ledger=ledger,
        resolver=RESOLVER,
        trust_policy=TRUST_POLICY,
        policy=PolicyRef.from_dict("default", "1", POLICY),
        suspension=suspension,
        docket=client(workdir, "decide", "decide-1", DECIDE_KEY),
        signing_key=DECIDE_KEY,
        costs=COSTS,
    )


@pytest.fixture
def make_control(workdir, sink, ledger, suspension):
    def make(docket=None, writers=VERIFIED_WRITERS, **overrides):
        options = {
            "component": "control.example",
            "writers": writers,
            "ledger": ledger,
            "suspension": suspension,
            "docket": docket or client(workdir, "control", "control-1", CONTROL_KEY),
            "docket_writer": "control",
            "resolver": RESOLVER,
            "trust_policy": TRUST_POLICY,
        }
        options.update(overrides)
        return Control(**options)

    return make


@pytest.fixture
def grant_control(make_control):
    def make(**overrides):
        return make_control(writers=GRANT_WRITERS, grant_writers={"issuer"}, **overrides)

    return make


def signed_root(key=ISSUER_KEY, *, issuer=ISSUER_ID, tenant=TENANT, ttl=3600, task_id="task-1"):
    return issue_task_root(
        key,
        issuer=issuer,
        task_id=task_id,
        tenant_id=tenant,
        principal=PRINCIPAL,
        purpose="release-bot",
        budget=100,
        max_depth=4,
        issued_at=NOW,
        expires_at=NOW + ttl,
        scope=SCOPE,
        subject=encode_public_key(AGENT_KEY.public_key()),
    )


def grant_token(root_token, grant_id="g-1"):
    grant = Grant(grant_id=grant_id, at=NOW, root_token=root_token)
    return encode_record(GRANTER_KEY, "issuer-1", "issuer", 1, None, grant).token


def delegated_root_and_link():
    root = make_root()
    link = delegate(
        root,
        root,
        AGENT_KEY,
        child_subject=encode_public_key(CHILD_KEY.public_key()),
        scope=LINK_SCOPE,
        budget=10,
        ttl=600,
        now=NOW,
    )
    return root, link


def records(workdir):
    index = build_kid_index(SINK_WRITERS)
    lines = (workdir / "docket.log").read_text().splitlines()
    decoded = [decode_record(line, index) for line in lines]
    assert not [record for record in decoded if isinstance(record, Refused)]
    return list(zip(lines, decoded, strict=True))


def record_line(workdir, decision="allow", hop="decide"):
    return next(
        line for line, record in records(workdir) if (record.entry.hop, record.entry.decision) == (hop, decision)
    )


def control_entries(workdir):
    return [record.entry for _, record in records(workdir) if record.writer == "control"]


def allowed_delegated_call(decider, workdir, nonce="n-1"):
    root, link = delegated_root_and_link()
    decision = decider.check(make_request(root, (link,), CHILD_KEY, nonce=nonce, trace_id="trace-7"), NOW)
    assert decision.allowed, decision
    return root, link


def next_delegated_call(decider, root, link):
    return decider.check(make_request(root, (link,), CHILD_KEY, nonce="n-2", trace_id="trace-8"), NOW + 1)


@pytest.mark.parametrize("level", LEVELS)
def test_revoke_at_each_level_stops_the_next_call(decider, make_control, workdir, level):
    root, link = allowed_delegated_call(decider, workdir)
    make_control().revoke(record_line(workdir), level, "ops@example", NOW + 1)
    decision = next_delegated_call(decider, root, link)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "chain_invalid", None)


@pytest.mark.parametrize(
    ("level", "applied"),
    [
        ("link", lambda root, link: {"link": link.binding()}),
        ("task", lambda root, link: {"tenant": TENANT, "task": root.task_id}),
        ("tenant", lambda root, link: {"tenant": TENANT}),
        ("root", lambda root, link: {"root": root.binding()}),
    ],
)
def test_the_control_entry_joins_the_trace_of_the_record(decider, make_control, workdir, level, applied):
    root, link = allowed_delegated_call(decider, workdir)
    source = decode_record(record_line(workdir), build_kid_index(SINK_WRITERS)).entry
    outcome = make_control().revoke(record_line(workdir), level, "ops@example", NOW + 1)
    [entry] = control_entries(workdir)
    assert entry.entry_id == outcome.entry_id
    assert (entry.trace_id, entry.parent_entry, entry.op_id) == ("trace-7", source.entry_id, source.op_id)
    assert (entry.hop, entry.component, entry.decision, entry.reason) == ("control", "control.example", "revoke", level)
    assert (entry.principal, entry.tenant, entry.at) == ("ops@example", TENANT, NOW + 1)
    assert dict(entry.handles) == applied(root, link) == dict(outcome.handles)


@pytest.mark.parametrize("level", ["task", "tenant"])
def test_a_tenant_handle_that_does_not_match_the_record_is_refused(decider, make_control, workdir, level):
    root, link = allowed_delegated_call(decider, workdir)
    token = resign(record_line(workdir), DECIDE_KEY, "decide-1", lambda body: body["handles"].update(tenant="tenant-y"))
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(token, level, "ops", NOW + 1)
    assert refused.value.reason == "handle_mismatch"
    assert next_delegated_call(decider, root, link).allowed
    assert control_entries(workdir) == []


def test_an_invalid_binding_handle_is_refused_without_an_entry(decider, make_control, workdir):
    allowed_delegated_call(decider, workdir)
    token = resign(
        record_line(workdir), DECIDE_KEY, "decide-1", lambda body: body["handles"].update(root="not-a-digest")
    )
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(token, "root", "ops", NOW + 1)
    assert refused.value.reason == "invalid_handle"
    assert control_entries(workdir) == []


GRANT_LEVELS = ("task", "tenant", "root")


@pytest.mark.parametrize("level", GRANT_LEVELS)
def test_revoke_from_a_grant_stops_a_task_that_never_called(decider, grant_control, workdir, level):
    root, link = delegated_root_and_link()
    grant_control().revoke(grant_token(root.encode()), level, "ops@example", NOW + 1)
    decision = next_delegated_call(decider, root, link)
    assert (decision.allowed, decision.reason, decision.clearance) == (False, "chain_invalid", None)


@pytest.mark.parametrize(
    ("level", "applied"),
    [
        ("task", lambda root: {"tenant": TENANT, "task": root.task_id}),
        ("tenant", lambda root: {"tenant": TENANT}),
        ("root", lambda root: {"root": root.binding()}),
    ],
)
def test_the_control_entry_of_a_grant_revoke_names_the_grant(grant_control, workdir, level, applied):
    root = signed_root()
    outcome = grant_control().revoke(grant_token(root.encode(), "grant-7"), level, "ops@example", NOW + 1)
    [entry] = control_entries(workdir)
    assert entry.entry_id == outcome.entry_id
    assert (entry.trace_id, entry.parent_entry, entry.op_id) == ("grant-7", "grant-7", None)
    assert (entry.hop, entry.component, entry.decision, entry.reason) == ("control", "control.example", "revoke", level)
    assert (entry.principal, entry.tenant, entry.at) == ("ops@example", TENANT, NOW + 1)
    assert dict(entry.handles) == applied(root) == dict(outcome.handles)
    assert outcome.trace_id == "grant-7"


def test_an_expired_task_can_be_revoked_from_its_grant(grant_control, workdir):
    root = signed_root(ttl=60)
    grant_control().revoke(grant_token(root.encode()), "task", "ops", NOW + 3600)
    [entry] = control_entries(workdir)
    assert dict(entry.handles) == {"tenant": TENANT, "task": root.task_id}


@pytest.mark.parametrize(
    ("root_token", "overrides", "reason"),
    [
        (lambda: "root.token", {}, "record_invalid_field"),
        (lambda: signed_root(FORGER_KEY).encode(), {}, "root_bad_signature"),
        (lambda: signed_root(OTHER_ISSUER_KEY).encode(), {}, "root_bad_signature"),
        (lambda: signed_root(FORGER_KEY, issuer="issuer.unknown").encode(), {}, "root_unknown_issuer"),
        (lambda: signed_root().encode(), {"resolver": PinnedResolver({})}, "root_unknown_issuer"),
        (
            lambda: signed_root(FORGER_KEY, issuer="issuer.unknown").encode(),
            {"resolver": PinnedResolver({"issuer.unknown": FORGER_KEY.public_key()})},
            "root_unknown_issuer",
        ),
        (lambda: signed_root(OTHER_ISSUER_KEY, issuer=OTHER_ISSUER_ID).encode(), {}, "root_not_allowed"),
    ],
    ids=["undecodable", "forged", "other_issuer_key", "unknown_issuer", "unresolvable", "untrusted", "cross_tenant"],
)
@pytest.mark.parametrize("level", GRANT_LEVELS)
def test_a_grant_whose_root_is_not_trusted_revokes_nothing(
    decider, grant_control, workdir, root_token, overrides, reason, level
):
    root, link = allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlRefused) as refused:
        grant_control(**overrides).revoke(grant_token(root_token()), level, "ops", NOW + 1)
    assert refused.value.reason == reason
    assert next_delegated_call(decider, root, link).allowed
    assert control_entries(workdir) == []


def test_a_grant_revokes_only_in_a_tenant_its_issuer_is_allowed(grant_control, workdir):
    root = signed_root(OTHER_ISSUER_KEY, issuer=OTHER_ISSUER_ID, tenant=OTHER_TENANT)
    outcome = grant_control().revoke(grant_token(root.encode()), "tenant", "ops", NOW + 1)
    assert dict(outcome.handles) == {"tenant": OTHER_TENANT}


def test_link_level_from_a_grant_is_refused(decider, grant_control, workdir):
    root, link = allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlRefused) as refused:
        grant_control().revoke(grant_token(root.encode()), "link", "ops", NOW + 1)
    assert refused.value.reason == "no_handle"
    assert "grant has no link handle" in str(refused.value)
    assert next_delegated_call(decider, root, link).allowed
    assert control_entries(workdir) == []


def test_suspend_from_a_grant_is_refused(decider, grant_control, workdir, suspension):
    root, link = allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlRefused) as refused:
        grant_control().suspend(grant_token(root.encode()), "ops", NOW + 1)
    assert refused.value.reason == "record_not_suspendable"
    assert suspension.suspended is False
    assert next_delegated_call(decider, root, link).allowed
    assert control_entries(workdir) == []


def test_a_grant_from_an_entry_writer_is_refused(decider, grant_control, workdir):
    grant = Grant(grant_id="g-1", at=NOW, root_token=signed_root().encode())
    token = encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, grant).token
    with pytest.raises(ControlRefused) as refused:
        grant_control().revoke(token, "task", "ops", NOW + 1)
    assert refused.value.reason == "record_wrong_record_type"
    assert control_entries(workdir) == []


def test_a_custodian_record_can_be_used(decider, make_control, workdir, ledger):
    root, link = allowed_delegated_call(decider, workdir)
    source = decode_record(record_line(workdir), build_kid_index(SINK_WRITERS)).entry
    custodian_entry = replace(source, hop="custodian", decision="alert", reason="canary")
    token = encode_record(CUSTODIAN_KEY, "custodian-1", "custodian", 1, None, custodian_entry).token
    make_control().revoke(token, "task", "ops", NOW + 1)
    assert next_delegated_call(decider, root, link).reason == "chain_invalid"


def resign(token, key, kid, change):
    payload = json.loads(b64u_decode(token.split(".")[0]))
    change(payload)
    payload["kid"] = kid
    encoded = canonicalize(payload)
    return f"{b64u(encoded)}.{b64u(key.sign(encoded))}"


def swap_payload(token, change):
    payload = json.loads(b64u_decode(token.split(".")[0]))
    change(payload)
    return f"{b64u(canonicalize(payload))}.{token.split('.')[1]}"


def flip_signature(token):
    payload, signature = token.split(".")
    raw = bytearray(b64u_decode(signature))
    raw[0] ^= 1
    return f"{payload}.{b64u(bytes(raw))}"


TAMPERED = {
    "other_task_in_handles": (
        lambda token: swap_payload(token, lambda body: body["handles"].update(task="task-2")),
        "record_bad_signature",
    ),
    "other_tenant": (
        lambda token: swap_payload(token, lambda body: body.update(tenant="tenant-b")),
        "record_bad_signature",
    ),
    "flipped_signature": (flip_signature, "record_bad_signature"),
    "unpinned_key": (lambda token: resign(token, FORGER_KEY, "decide-1", lambda body: None), "record_bad_signature"),
    "unknown_kid": (lambda token: resign(token, FORGER_KEY, "forger-1", lambda body: None), "record_unknown_kid"),
    "control_key": (lambda token: resign(token, CONTROL_KEY, "control-1", lambda body: None), "record_unknown_kid"),
    "writer_mismatch": (
        lambda token: resign(token, CUSTODIAN_KEY, "custodian-1", lambda body: None),
        "record_unknown_writer",
    ),
    "trailing_garbage": (lambda token: token + ".x", "record_malformed"),
    "not_a_token": (lambda token: "not-a-record", "record_malformed"),
    "empty": (lambda token: "", "record_malformed"),
}


@pytest.mark.parametrize("name", sorted(TAMPERED))
@pytest.mark.parametrize("action", ["revoke", "suspend"])
def test_a_tampered_record_is_refused_and_changes_nothing(decider, make_control, workdir, suspension, name, action):
    root, link = allowed_delegated_call(decider, workdir)
    tamper, reason = TAMPERED[name]
    control = make_control()
    with pytest.raises(ControlRefused) as refused:
        if action == "revoke":
            control.revoke(tamper(record_line(workdir)), "task", "ops", NOW + 1)
        else:
            control.suspend(tamper(record_line(workdir)), "ops", NOW + 1)
    assert refused.value.reason == reason
    assert suspension.suspended is False
    assert next_delegated_call(decider, root, link).allowed
    assert control_entries(workdir) == []


def test_a_record_that_is_not_a_str_is_refused(make_control):
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(b"bytes", "task", "ops", NOW)
    assert refused.value.reason == "record_malformed"


@pytest.mark.parametrize("level", LEVELS)
def test_a_record_without_handles_is_refused_at_every_level(make_control, workdir, level):
    entry = Entry(
        entry_id="e-1", trace_id="trace-1", hop="decide", component=DECIDER_ID, decision="refuse", at=NOW, reason="x"
    )
    client(workdir, "decide", "decide-1", DECIDE_KEY).append(entry)
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(record_line(workdir, decision="refuse"), level, "ops", NOW + 1)
    assert refused.value.reason == "no_handle"
    assert control_entries(workdir) == []


def test_link_level_on_a_root_only_chain_is_refused(decider, make_control, workdir):
    root = make_root()
    assert decider.check(make_request(root), NOW).allowed
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(record_line(workdir), "link", "ops", NOW + 1)
    assert refused.value.reason == "no_handle"
    assert decider.check(make_request(root, nonce="n-2"), NOW + 1).allowed


@pytest.mark.parametrize("level", ["", "Task", "principal", "op", "agent_key", None])
def test_an_unknown_level_is_refused(decider, make_control, workdir, level):
    allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(record_line(workdir), level, "ops", NOW + 1)
    assert refused.value.reason == "unknown_level"


@pytest.mark.parametrize("actor", ["", "has space", "x" * 129, None, "tab\there", "café"])
def test_an_invalid_actor_is_refused(decider, make_control, workdir, actor):
    allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlRefused) as refused:
        make_control().revoke(record_line(workdir), "task", actor, NOW + 1)
    assert refused.value.reason == "invalid_actor"


def test_suspend_from_a_record_stops_decide_and_resume_restores_it(decider, make_control, workdir, suspension):
    root, link = allowed_delegated_call(decider, workdir)
    source = decode_record(record_line(workdir), build_kid_index(SINK_WRITERS)).entry
    control = make_control()
    suspended = control.suspend(record_line(workdir), "ops", NOW + 1)
    assert suspension.suspended is True
    assert next_delegated_call(decider, root, link).reason == "suspended"
    resumed = control.resume("ops", NOW + 2)
    assert suspension.suspended is False
    assert next_delegated_call(decider, root, link).allowed
    suspend_entry, resume_entry = control_entries(workdir)
    assert (suspend_entry.decision, suspend_entry.reason) == ("suspend", "suspended")
    assert (suspend_entry.trace_id, suspend_entry.parent_entry) == ("trace-7", source.entry_id)
    assert suspend_entry.entry_id == suspended.entry_id
    assert (resume_entry.decision, resume_entry.reason, resume_entry.parent_entry) == ("resume", "resumed", None)
    assert resume_entry.trace_id == resumed.trace_id != "trace-7"
    assert resume_entry.principal == "ops"


def test_a_second_suspend_and_an_idle_resume_are_recorded(decider, make_control, workdir, suspension):
    allowed_delegated_call(decider, workdir)
    control = make_control()
    control.suspend(record_line(workdir), "ops", NOW + 1)
    control.suspend(record_line(workdir), "ops-2", NOW + 2)
    control.resume("ops", NOW + 3)
    control.resume("ops", NOW + 4)
    assert [entry.reason for entry in control_entries(workdir)] == [
        "suspended",
        "already_suspended",
        "resumed",
        "not_suspended",
    ]


def test_suspend_refuses_a_suspension_directory_of_another_uid(decider, make_control, workdir, monkeypatch):
    allowed_delegated_call(decider, workdir)
    line = record_line(workdir)
    control = make_control(docket=MemoryDocket())
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ControlRefused) as refused:
        control.suspend(line, "ops", NOW + 1)
    assert refused.value.reason == "suspension_unavailable"
    with pytest.raises(ControlRefused):
        control.resume("ops", NOW + 1)


def test_a_revoke_is_applied_even_when_its_entry_is_not_recorded(decider, make_control, workdir):
    root, link = allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlUnrecorded) as unrecorded:
        make_control(docket=FailingDocket()).revoke(record_line(workdir), "task", "ops", NOW + 1)
    assert unrecorded.value.outcome.handles == {"tenant": TENANT, "task": root.task_id}
    assert next_delegated_call(decider, root, link).reason == "chain_invalid"


def test_a_suspend_is_applied_even_when_its_entry_is_not_recorded(decider, make_control, workdir, suspension):
    allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlUnrecorded):
        make_control(docket=FailingDocket()).suspend(record_line(workdir), "ops", NOW + 1)
    assert suspension.suspended is True


@pytest.mark.parametrize(
    "ack",
    [
        lambda record: None,
        lambda record: Record("decide", record.seq, None, record.entry, record.kid, record.token),
        lambda record: Record(
            record.writer, record.seq, None, replace(record.entry, reason="x"), record.kid, record.token
        ),
        lambda record: Record(record.writer, record.seq, None, record.entry, record.kid, ""),
    ],
)
def test_a_mismatched_acknowledgement_is_unrecorded(decider, make_control, workdir, ack):
    allowed_delegated_call(decider, workdir)
    with pytest.raises(ControlUnrecorded):
        make_control(docket=MemoryDocket(ack)).revoke(record_line(workdir), "task", "ops", NOW + 1)


class UnavailableLedger:
    def revoke(self, binding, now):
        raise LedgerUnavailable("disk gone")

    revoke_task = revoke_tenant = None


def test_an_unavailable_ledger_is_refused_without_an_entry(decider, make_control, workdir):
    allowed_delegated_call(decider, workdir)
    docket = MemoryDocket()
    with pytest.raises(ControlRefused) as refused:
        make_control(docket=docket, ledger=UnavailableLedger()).revoke(record_line(workdir), "root", "ops", NOW + 1)
    assert refused.value.reason == "ledger_unavailable"
    assert docket.entries == []


@pytest.mark.parametrize("now", [-1, True, 1.5, "1", 2**53])
def test_an_invalid_clock_is_refused(make_control, now):
    with pytest.raises(ValueError):
        make_control(docket=MemoryDocket()).resume("ops", now)


def test_a_revoke_with_an_unsafe_clock_is_not_reported_as_an_invalid_handle(decider, make_control, workdir):
    allowed_delegated_call(decider, workdir)
    with pytest.raises(ValueError, match="now must be"):
        make_control().revoke(record_line(workdir), "root", "ops", 2**53)
    assert control_entries(workdir) == []


def test_control_must_not_verify_its_own_writer(make_control):
    writers = {**VERIFIED_WRITERS, "control": {"control-1": CONTROL_KEY.public_key()}}
    with pytest.raises(ValueError):
        make_control(writers=writers, docket=MemoryDocket())


def test_control_needs_at_least_one_verified_writer(make_control):
    with pytest.raises(ValueError):
        make_control(writers={}, docket=MemoryDocket())
