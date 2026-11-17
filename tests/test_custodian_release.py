import json
import os
from dataclasses import asdict

import pytest
import test_custodian
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_custodian import CUSTODIAN_BINDINGS, Refused, Released, custodian_entries
from test_decide import CUSTODIAN_ID, DECIDE_KEY, MAX_PROOF_AGE, NOW, TENANT, Suspension

from agent_bailiff.custodian.bindings import BindingTable, BindingTableError, EffectorBinding
from agent_bailiff.custodian.release import (
    RELEASE_FIELDS,
    RELEASE_HEADER,
    RELEASE_LIFETIME,
    RELEASE_TYP,
    Release,
    ReleaseSigner,
    verify_release,
)
from agent_bailiff.decide.clearance import CLEARANCE_TYP, decode_clearance
from agent_bailiff.docket.entry import ENTRY_TYP
from agent_bailiff.signing import Refused as SigningRefused
from agent_bailiff.signing import sign

make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
issue = test_custodian.issue
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer
ledger_path = test_custodian.ledger_path

CATALOG = "c" * 43
RELEASE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))
RELEASE_KID = "custodian-release-1"
PINNED = {RELEASE_KID: RELEASE_KEY.public_key()}
EFFECTOR_BINDINGS = (
    EffectorBinding(TENANT, "deploy.service", "env/staging/*", "deploy-api", "deploy.example", CATALOG),
    *CUSTODIAN_BINDINGS[1:],
)


def signer():
    return ReleaseSigner(CUSTODIAN_ID, RELEASE_KEY, RELEASE_KID)


def verified(token, now=NOW + 1, aud="deploy-api"):
    return verify_release(token, PINNED, now=now, expected_aud=aud, expected_iss=CUSTODIAN_ID, skew_seconds=5)


def test_an_effector_binding_releases_a_signed_release_instead_of_a_credential(make_custodian, issue, workdir):
    request, token = issue()
    custodian = make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer())
    result = custodian.release(token, request, NOW + 1)
    assert isinstance(result, Released)
    assert (result.header_name, result.tier) == (RELEASE_HEADER, "effector")
    release = verified(result.header_value)
    clearance = decode_clearance(token, {"decide-1": DECIDE_KEY.public_key()}, max_lifetime=MAX_PROOF_AGE)
    assert (release.op_id, release.tool, release.resource) == (clearance.op_id, clearance.tool, clearance.resource)
    assert (release.args_digest, release.tenant, release.task) == (clearance.args_digest, TENANT, clearance.task)
    assert (release.aud, release.iss, release.catalog, release.clearance) == (
        "deploy-api",
        CUSTODIAN_ID,
        CATALOG,
        token,
    )
    assert release.exp == min(clearance.exp, NOW + 1 + RELEASE_LIFETIME)
    [entry] = [item for item in custodian_entries(workdir) if item.decision == "release"]
    assert (entry.credential_tier, entry.entry_id) == ("effector", release.entry_id)


def test_an_effector_release_never_reads_the_credential_store(make_custodian, issue, monkeypatch):
    request, token = issue()
    custodian = make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer())

    def no_decrypt(*args):
        raise AssertionError("the credential store must not be read")

    monkeypatch.setattr(custodian, "_decrypt", no_decrypt)
    assert isinstance(custodian.release(token, request, NOW + 1), Released)


def test_without_a_signer_the_release_is_refused_and_the_operation_is_not_spent(make_custodian, issue):
    request, token = issue()
    assert make_custodian(bindings=EFFECTOR_BINDINGS).release(token, request, NOW + 1) == Refused("release_unavailable")
    assert isinstance(
        make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer()).release(token, request, NOW + 2), Released
    )


def test_a_suspended_custodian_refuses_an_effector_release_without_spending_it(make_custodian, issue):
    request, token = issue()
    suspended = make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer(), suspension=Suspension(True))
    assert suspended.release(token, request, NOW + 1) == Refused("suspended")
    assert isinstance(
        make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer()).release(token, request, NOW + 2), Released
    )


def test_an_effector_release_is_claimed_once(make_custodian, issue):
    request, token = issue()
    custodian = make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer())
    assert isinstance(custodian.release(token, request, NOW + 1), Released)
    assert custodian.release(token, request, NOW + 2) == Refused("already_issued")


def release_body(**overrides):
    body = {
        "iss": CUSTODIAN_ID,
        "aud": "deploy-api",
        "iat": NOW,
        "exp": NOW + RELEASE_LIFETIME,
        "op_id": "op-1",
        "tenant": TENANT,
        "task": "task-1",
        "tool": "deploy.service",
        "resource": "env/staging/api",
        "args_digest": "d" * 43,
        "catalog": CATALOG,
        "clearance": "clearance-token",
        "entry_id": "e" * 32,
    }
    body.update(overrides)
    return body


def signed(body, key=RELEASE_KEY, kid=RELEASE_KID):
    return sign(key, kid, RELEASE_TYP, body)


def test_a_valid_release_verifies():
    assert verified(signed(release_body())) == Release(**release_body())


@pytest.mark.parametrize(
    ("token", "now", "aud", "reason"),
    [
        (signed(release_body(aud="other")), NOW + 1, "deploy-api", "wrong_audience"),
        (signed(release_body(iss="other")), NOW + 1, "deploy-api", "wrong_issuer"),
        (signed(release_body()), NOW + RELEASE_LIFETIME, "deploy-api", "expired"),
        (signed(release_body(iat=NOW + 10, exp=NOW + 20)), NOW, "deploy-api", "not_yet_valid"),
        (signed(release_body(exp=NOW + RELEASE_LIFETIME + 1)), NOW + 1, "deploy-api", "lifetime_exceeded"),
        (signed(release_body(exp=NOW)), NOW, "deploy-api", "invalid_field"),
        (signed(release_body(tool="")), NOW + 1, "deploy-api", "invalid_field"),
        (signed(release_body(), key=Ed25519PrivateKey.generate(), kid="other"), NOW + 1, "deploy-api", "unknown_kid"),
        (signed(release_body(), key=Ed25519PrivateKey.generate()), NOW + 1, "deploy-api", "bad_signature"),
        ("x" * 20000, NOW + 1, "deploy-api", "oversized"),
        (None, NOW + 1, "deploy-api", "malformed"),
    ],
)
def test_invalid_releases_are_refused(token, now, aud, reason):
    result = verified(token, now=now, aud=aud)
    assert isinstance(result, SigningRefused) and result.reason == reason, result


@pytest.mark.parametrize("typ", [ENTRY_TYP, CLEARANCE_TYP])
def test_a_release_body_signed_by_the_release_key_as_another_record_type_is_refused(typ):
    result = verified(sign(RELEASE_KEY, RELEASE_KID, typ, release_body()))
    assert isinstance(result, SigningRefused) and result.reason == "wrong_typ", result


def test_a_release_with_an_extra_or_missing_field_is_refused():
    extra = signed({**release_body(), "credential": "x"})
    missing_body = release_body()
    del missing_body["catalog"]
    for token in (extra, signed(missing_body)):
        result = verified(token)
        assert isinstance(result, SigningRefused), result


def test_the_release_fields_are_fixed():
    assert set(asdict(Release(**release_body()))) == RELEASE_FIELDS


def test_the_binding_table_loads_effector_bindings(tmp_path):
    path = tmp_path / "bindings.json"
    effector = {
        "tenant": TENANT,
        "tool": "k8s.deployments.scale",
        "resource": "k8s/staging/deployments/*",
        "credential_id": "effector.homelab",
        "target": "cluster.homelab",
        "catalog": CATALOG,
    }
    path.write_text(json.dumps({"bindings": [effector]}))
    os.chmod(path, 0o600)
    table = BindingTable.load(path)
    assert table.bindings == (EffectorBinding(**effector),)
    assert table.credential_bindings == ()
    path.write_text(json.dumps({"bindings": [{**effector, "catalog": "short"}]}))
    with pytest.raises(BindingTableError, match="catalog"):
        BindingTable.load(path)


def test_a_mixed_table_lists_only_credential_bindings_as_credentials():
    table = BindingTable(EFFECTOR_BINDINGS)
    assert table.credential_bindings == CUSTODIAN_BINDINGS[1:]


def test_an_oversized_release_is_refused_before_the_operation_is_claimed(make_custodian, issue, monkeypatch):
    from agent_bailiff.custodian import release as release_module

    request, token = issue()
    monkeypatch.setattr(release_module, "MAX_RELEASE_BYTES", 10)
    custodian = make_custodian(bindings=EFFECTOR_BINDINGS, release_signer=signer())
    assert custodian.release(token, request, NOW + 1) == Refused("release_too_large")
    monkeypatch.undo()
    assert isinstance(custodian.release(token, request, NOW + 2), Released)
