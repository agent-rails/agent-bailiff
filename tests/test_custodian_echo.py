import logging

import pytest
import test_custodian
from test_custodian import DEPLOY_SECRET, Refused, Released, custodian_entries
from test_decide import NOW, TENANT, make_root

from agent_bailiff.custodian import ClaimsStore, CredentialStore, CustodianConfig, LocalBackend
from agent_bailiff.custodian.config import (
    DEFAULT_INFLIGHT_MAX,
    DEFAULT_INFLIGHT_MAX_BYTES,
    DEFAULT_INFLIGHT_PER_TENANT,
    DEFAULT_INFLIGHT_TTL,
)
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
