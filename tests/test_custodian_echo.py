import base64
import json
import logging

import pytest
import test_custodian
import test_custodian_release
from test_custodian import DEPLOY_SECRET, Refused, Released, custodian_entries
from test_decide import NOW, TENANT, make_root

from agent_bailiff.client.client import REFUSAL_REASONS
from agent_bailiff.custodian import ClaimsStore, CredentialStore, CustodianConfig, LocalBackend
from agent_bailiff.custodian import custodian as custodian_module
from agent_bailiff.custodian.config import (
    DEFAULT_INFLIGHT_MAX,
    DEFAULT_INFLIGHT_MAX_BYTES,
    DEFAULT_INFLIGHT_PER_TENANT,
    DEFAULT_INFLIGHT_TTL,
)
from agent_bailiff.custodian.custodian import RESPONSE_REASONS, ResponseChecked, ResponseRefused
from agent_bailiff.custodian.echo import MARKER
from agent_bailiff.signing import token_hash

make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
open_docket = test_custodian.open_docket
issue = test_custodian.issue
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer
ledger_path = test_custodian.ledger_path

TTL_NS = DEFAULT_INFLIGHT_TTL * 1_000_000_000


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class FailOnceDocket:
    def __init__(self, inner):
        self.inner = inner
        self.failed = False

    def append(self, entry):
        if not self.failed and entry.decision == "release":
            self.failed = True
            raise OSError("docket sink is down")
        return self.inner.append(entry)


def config_options(**overrides):
    options = {
        "custodian_id": "c",
        "decider_id": "d",
        "decide_keys": {"k": test_custodian.DECIDE_KEY.public_key()},
        "docket_writer": "c",
        "max_proof_age": 60,
        "max_clearance_lifetime": 60,
        "skew_seconds": 5,
        "rate_limit": 3,
        "rate_window": 60,
    }
    options.update(overrides)
    return options


def test_the_in_flight_defaults_hold_a_client_deadline_with_margin():
    config = CustodianConfig(**config_options())
    assert (config.inflight_ttl, config.inflight_max) == (DEFAULT_INFLIGHT_TTL, DEFAULT_INFLIGHT_MAX)
    assert (config.inflight_max_bytes, config.inflight_per_tenant) == (
        DEFAULT_INFLIGHT_MAX_BYTES,
        DEFAULT_INFLIGHT_PER_TENANT,
    )
    assert DEFAULT_INFLIGHT_TTL == 60


@pytest.mark.parametrize("name", ["inflight_ttl", "inflight_max", "inflight_max_bytes", "inflight_per_tenant"])
@pytest.mark.parametrize("value", [0, -1, True, "1"])
def test_in_flight_bounds_must_be_positive_integers(name, value):
    with pytest.raises(ValueError):
        CustodianConfig(**config_options(**{name: value}))


def test_a_full_in_flight_map_refuses_without_claiming_or_spending_the_rate_budget(
    make_custodian, issue, state, workdir
):
    clock = Clock()
    root = make_root()
    first_request, first_token = issue(root, nonce="n-1")
    second_request, second_token = issue(root, nonce="n-2")
    custodian = make_custodian(monotonic_ns=clock, inflight_max=1, rate_limit=2)
    assert isinstance(custodian.release(first_token, first_request, NOW + 1), Released)
    assert custodian.release(second_token, second_request, NOW + 1) == Refused("inflight_full")
    claims = ClaimsStore.open(state / "claims.db")
    try:
        second_op = [entry for entry in custodian_entries(workdir) if entry.reason == "inflight_full"][0].op_id
        assert claims.is_claimed(second_op) is False
    finally:
        claims.close()
    clock.now += TTL_NS
    assert isinstance(custodian.release(second_token, second_request, NOW + 2), Released)


def test_a_full_tenant_quota_refuses_the_release(make_custodian, issue):
    root = make_root()
    first_request, first_token = issue(root, nonce="n-1")
    second_request, second_token = issue(root, nonce="n-2")
    custodian = make_custodian(monotonic_ns=Clock(), inflight_per_tenant=1)
    assert isinstance(custodian.release(first_token, first_request, NOW + 1), Released)
    assert custodian.release(second_token, second_request, NOW + 1) == Refused("inflight_full")


def test_an_unacknowledged_release_frees_its_reservation(make_custodian, issue, open_docket):
    root = make_root()
    first_request, first_token = issue(root, nonce="n-1")
    second_request, second_token = issue(root, nonce="n-2")
    docket = FailOnceDocket(open_docket("custodian", "custodian-1", test_custodian.CUSTODIAN_KEY))
    custodian = make_custodian(docket=docket, monotonic_ns=Clock(), inflight_max=1)
    assert custodian.release(first_token, first_request, NOW + 1) == Refused("docket_unavailable")
    assert isinstance(custodian.release(second_token, second_request, NOW + 1), Released)


def test_a_clearance_already_in_flight_is_refused_as_already_issued(make_custodian, issue):
    request, token = issue()
    custodian = make_custodian(monotonic_ns=Clock())
    custodian._inflight.reserve(token_hash(token), TENANT, "Bearer another-value")
    assert custodian.release(token, request, NOW + 1) == Refused("already_issued")


def test_a_release_holds_the_released_value_under_the_clearance_hash(make_custodian, issue):
    request, token = issue()
    custodian = make_custodian(monotonic_ns=Clock())
    result = custodian.release(token, request, NOW + 1)
    held = custodian._inflight.take(token_hash(token))
    assert (held.header_value, held.tenant, held.release_entry_id) == (DEPLOY_SECRET.decode(), TENANT, result.entry_id)
    assert held.entry.clearance_digest == token_hash(token)


def test_a_credential_too_short_to_redact_is_released_with_a_warning(make_custodian, issue, state, caplog):
    store = CredentialStore.open(state / "credentials.db", LocalBackend.load(state / "kek"))
    store.put(TENANT, "deploy-api", "deploy.example", b"Bearer short-key")
    store.close()
    request, token = issue()
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.custodian"):
        assert isinstance(make_custodian(monotonic_ns=Clock()).release(token, request, NOW + 1), Released)
    assert "cannot be redacted" in caplog.text
    assert "short-key" not in caplog.text


def test_a_long_credential_is_released_without_a_warning(make_custodian, issue, caplog):
    request, token = issue()
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.custodian"):
        assert isinstance(make_custodian(monotonic_ns=Clock()).release(token, request, NOW + 1), Released)
    assert "cannot be redacted" not in caplog.text


class FailAlertDocket:
    def __init__(self, inner):
        self.inner = inner

    def append(self, entry):
        if entry.decision == "alert":
            raise OSError("docket sink is down")
        return self.inner.append(entry)


SECRET = DEPLOY_SECRET.decode()


def call_result(text, **extra):
    return json.dumps({"content": [{"type": "text", "text": text}], **extra}).encode()


def released(make_custodian, issue, **options):
    request, token = issue()
    custodian = make_custodian(monotonic_ns=Clock(), **options)
    result = custodian.release(token, request, NOW + 1)
    assert isinstance(result, Released)
    return custodian, token, result


def test_a_result_without_an_echo_passes_unchanged(make_custodian, issue, workdir):
    custodian, token, _ = released(make_custodian, issue)
    assert custodian.check_response(token, call_result("deployed"), NOW + 2) == ResponseChecked(None)
    assert [entry.decision for entry in custodian_entries(workdir)] == ["release"]


def test_an_echoed_credential_is_redacted_and_alerted(make_custodian, issue, workdir):
    custodian, token, result = released(make_custodian, issue)
    raw = base64.b64encode(f"Authorization: {SECRET}".encode()).decode()
    checked = custodian.check_response(token, call_result(f"got {SECRET}", structuredContent={"b": raw}), NOW + 2)
    assert isinstance(checked, ResponseChecked)
    document = json.loads(checked.result)
    assert document["content"][0]["text"] == f"got {MARKER}"
    assert MARKER in document["structuredContent"]["b"]
    assert b"deploy-secret" not in checked.result
    release_entry, alert = custodian_entries(workdir)
    assert (alert.decision, alert.reason, alert.parent_entry) == ("alert", "credential_echo", result.entry_id)
    assert (alert.op_id, alert.trace_id, alert.at) == (release_entry.op_id, release_entry.trace_id, NOW + 2)
    assert alert.entry_id not in (release_entry.entry_id, "custodian")
    assert alert.clearance_digest == token_hash(token)
    assert b"deploy-secret" not in (workdir / "docket.log").read_bytes()


def test_an_error_result_is_redacted(make_custodian, issue):
    custodian, token, _ = released(make_custodian, issue)
    checked = custodian.check_response(token, call_result(f"401 for {SECRET}", isError=True), NOW + 2)
    assert json.loads(checked.result) == {"content": [{"type": "text", "text": f"401 for {MARKER}"}], "isError": True}


def test_a_failed_alert_still_returns_the_redacted_result(make_custodian, issue, open_docket, caplog):
    docket = FailAlertDocket(open_docket("custodian", "custodian-1", test_custodian.CUSTODIAN_KEY))
    custodian, token, result = released(make_custodian, issue, docket=docket)
    with caplog.at_level(logging.ERROR, logger="agent_bailiff.custodian.custodian"):
        checked = custodian.check_response(token, call_result(SECRET), NOW + 2)
    assert json.loads(checked.result)["content"][0]["text"] == MARKER
    assert "credential echo alert" in caplog.text and result.op_id in caplog.text
    assert "deploy-secret" not in caplog.text


def test_logs_never_carry_the_credential(make_custodian, issue, caplog):
    custodian, token, _ = released(make_custodian, issue)
    with caplog.at_level(logging.DEBUG):
        custodian.check_response(token, call_result(f"x {SECRET} y"), NOW + 2)
        custodian.check_response(token, call_result(SECRET), NOW + 2)
    assert "deploy-secret" not in caplog.text
    assert "ZGVwbG95LXNlY3JldA" not in caplog.text


def test_a_result_is_checked_once(make_custodian, issue, caplog):
    custodian, token, _ = released(make_custodian, issue)
    assert custodian.check_response(token, call_result("ok"), NOW + 2) == ResponseChecked(None)
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.custodian"):
        assert custodian.check_response(token, call_result(SECRET), NOW + 2) == ResponseRefused("response_unmatched")
    assert "no in-flight release" in caplog.text


def test_an_unknown_clearance_is_unmatched(make_custodian, issue):
    custodian, token, _ = released(make_custodian, issue)
    other_request, other_token = issue(nonce="n-2")
    assert custodian.check_response(other_token, call_result(SECRET), NOW + 2) == ResponseRefused("response_unmatched")
    assert custodian.check_response(token, call_result(SECRET), NOW + 2) != ResponseRefused("response_unmatched")


@pytest.mark.parametrize("token", [None, "", 7])
def test_a_missing_clearance_is_refused(make_custodian, issue, token):
    custodian, _, _ = released(make_custodian, issue)
    assert custodian.check_response(token, call_result(SECRET), NOW + 2) == ResponseRefused(
        "response_clearance_missing"
    )


def test_a_non_ascii_clearance_is_unmatched(make_custodian, issue):
    custodian, _, _ = released(make_custodian, issue)
    assert custodian.check_response("clé", call_result(SECRET), NOW + 2) == ResponseRefused("response_unmatched")


def test_an_unreadable_result_is_refused(make_custodian, issue):
    custodian, token, _ = released(make_custodian, issue)
    assert custodian.check_response(token, b'{"a": NaN}', NOW + 2) == ResponseRefused("response_unreadable")


def test_an_oversize_redacted_result_is_refused(make_custodian, issue):
    custodian, token, _ = released(make_custodian, issue)
    raw = json.dumps({"text": "é" * 1_000_000 + SECRET}, ensure_ascii=False).encode()
    assert custodian.check_response(token, raw, NOW + 2) == ResponseRefused("response_oversize")


def test_an_internal_error_is_refused(make_custodian, issue, monkeypatch, caplog):
    custodian, token, _ = released(make_custodian, issue)

    def explode(result, needles):
        raise RuntimeError("boom")

    monkeypatch.setattr(custodian_module, "redact", explode)
    with caplog.at_level(logging.ERROR, logger="agent_bailiff.custodian.custodian"):
        assert custodian.check_response(token, call_result(SECRET), NOW + 2) == ResponseRefused(
            "response_internal_error"
        )
    assert "deploy-secret" not in caplog.text


def test_an_expired_release_is_unmatched(make_custodian, issue):
    clock = Clock()
    request, token = issue()
    custodian = make_custodian(monotonic_ns=clock)
    assert isinstance(custodian.release(token, request, NOW + 1), Released)
    clock.now += TTL_NS
    assert custodian.check_response(token, call_result(SECRET), NOW + 2) == ResponseRefused("response_unmatched")


def test_every_response_reason_is_outside_the_client_refusal_reasons():
    reasons = {
        "response_unmatched",
        "response_unreadable",
        "response_oversize",
        "response_clearance_missing",
        "response_internal_error",
    }
    assert reasons == set(RESPONSE_REASONS)
    assert not reasons & REFUSAL_REASONS


def test_an_echoed_effector_release_token_is_redacted(make_custodian, issue, workdir):
    request, token = issue()
    custodian = make_custodian(
        bindings=test_custodian_release.EFFECTOR_BINDINGS,
        release_signer=test_custodian_release.signer(),
        monotonic_ns=Clock(),
    )
    result = custodian.release(token, request, NOW + 1)
    assert result.tier == "effector"
    checked = custodian.check_response(token, call_result(f"release was {result.header_value}"), NOW + 2)
    assert json.loads(checked.result)["content"][0]["text"] == f"release was {MARKER}"
    assert [entry.reason for entry in custodian_entries(workdir)] == ["ok", "credential_echo"]
