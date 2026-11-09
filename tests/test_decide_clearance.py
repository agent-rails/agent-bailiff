import json
from dataclasses import asdict, replace

import pytest
from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import b64u, b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.decide.clearance import (
    CLEARANCE_FIELDS,
    CLEARANCE_TYP,
    Clearance,
    decode_clearance,
    encode_clearance,
)
from agent_bailiff.signing import Refused, sign

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PINNED = {"decide-1": KEY.public_key()}
MAX_LIFETIME = 60
CLEARANCE = Clearance(
    iss="decide.example",
    aud="custodian.example",
    iat=1_800_000_000,
    exp=1_800_000_060,
    op_id="op-1",
    tenant="tenant-a",
    task="task-1",
    root_binding="root-binding",
    leaf_binding="leaf-binding",
    request_digest="request-digest",
    tool="deploy.service",
    resource="env/staging/api",
    args_digest="args-digest",
    cost=3,
    credential_id="deploy-api",
    target="deploy.example",
    trace_id="trace-1",
    entry_id="entry-1",
)


def decode(token, **options):
    options.setdefault("max_lifetime", MAX_LIFETIME)
    return decode_clearance(token, PINNED, **options)


def payload_of(token):
    return b64u_decode(token.partition(".")[0])


def test_wire_fields_are_exactly_the_specified_set():
    token = encode_clearance(CLEARANCE, KEY, "decide-1")
    fields = set(json.loads(payload_of(token)))
    assert fields == {
        "typ",
        "v",
        "kid",
        "iss",
        "aud",
        "iat",
        "exp",
        "op_id",
        "tenant",
        "task",
        "root_binding",
        "leaf_binding",
        "request_digest",
        "tool",
        "resource",
        "args_digest",
        "cost",
        "credential_id",
        "target",
        "trace_id",
        "entry_id",
    }
    assert fields - {"typ", "v", "kid"} == CLEARANCE_FIELDS


def test_round_trip():
    token = encode_clearance(CLEARANCE, KEY, "decide-1")
    assert decode(token) == CLEARANCE


def test_payload_carries_the_clearance_typ_and_kid():
    payload = json.loads(payload_of(encode_clearance(CLEARANCE, KEY, "decide-1")))
    assert (payload["typ"], payload["v"], payload["kid"]) == (CLEARANCE_TYP, 1, "decide-1")


@pytest.mark.parametrize("name", sorted(CLEARANCE_FIELDS))
def test_tampering_with_any_field_is_detected(name):
    token = encode_clearance(CLEARANCE, KEY, "decide-1")
    payload = json.loads(payload_of(token))
    payload[name] = payload[name] + 1 if isinstance(payload[name], int) else payload[name] + "x"
    forged = f"{b64u(canonicalize(payload))}.{token.partition('.')[2]}"
    result = decode(forged)
    assert isinstance(result, Refused)
    assert result.reason == "bad_signature"


def test_signature_from_an_unpinned_key_is_refused():
    token = encode_clearance(CLEARANCE, OTHER_KEY, "decide-1")
    result = decode(token)
    assert isinstance(result, Refused) and result.reason == "bad_signature"


def test_unknown_kid_is_refused():
    token = encode_clearance(CLEARANCE, KEY, "decide-2")
    result = decode(token)
    assert isinstance(result, Refused) and result.reason == "unknown_kid"


def test_wrong_typ_is_refused():
    token = sign(KEY, "decide-1", "agent-bailiff/docket-entry/v1", asdict(CLEARANCE))
    result = decode(token)
    assert isinstance(result, Refused) and result.reason == "wrong_typ"


def test_unknown_field_is_refused():
    token = sign(KEY, "decide-1", CLEARANCE_TYP, {**asdict(CLEARANCE), "secret": "x"})
    result = decode(token)
    assert isinstance(result, Refused) and result.reason == "malformed"


def test_missing_field_is_refused():
    body = asdict(CLEARANCE)
    del body["credential_id"]
    result = decode(sign(KEY, "decide-1", CLEARANCE_TYP, body))
    assert isinstance(result, Refused) and result.reason == "missing_fields"


@pytest.mark.parametrize(
    ("name", "value"),
    [("cost", "3"), ("cost", True), ("cost", -1), ("iat", "1"), ("tool", ""), ("tool", 7), ("target", None)],
)
def test_wrongly_typed_field_is_refused(name, value):
    result = decode(sign(KEY, "decide-1", CLEARANCE_TYP, {**asdict(CLEARANCE), name: value}))
    assert isinstance(result, Refused) and result.reason == "invalid_field"


def test_lifetime_longer_than_the_bound_is_refused_on_decode():
    token = sign(KEY, "decide-1", CLEARANCE_TYP, {**asdict(CLEARANCE), "exp": CLEARANCE.iat + MAX_LIFETIME + 1})
    result = decode(token)
    assert isinstance(result, Refused) and result.reason == "lifetime_exceeded"
    assert decode(token, max_lifetime=MAX_LIFETIME + 1) == replace(CLEARANCE, exp=CLEARANCE.iat + MAX_LIFETIME + 1)


def test_expiry_not_after_issue_is_refused_on_decode():
    token = sign(KEY, "decide-1", CLEARANCE_TYP, {**asdict(CLEARANCE), "exp": CLEARANCE.iat})
    result = decode(token)
    assert isinstance(result, Refused) and result.reason == "invalid_field"


def test_invalid_clearance_cannot_be_encoded():
    with pytest.raises(ValueError):
        encode_clearance(replace(CLEARANCE, exp=CLEARANCE.iat), KEY, "decide-1")
    with pytest.raises(ValueError):
        encode_clearance(replace(CLEARANCE, tool=""), KEY, "decide-1")


def test_non_string_token_is_refused():
    result = decode(None)
    assert isinstance(result, Refused) and result.reason == "malformed"
