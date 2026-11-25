import json

import pytest
from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import b64u, b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.docket import ENTRY_TYP, GRANT_TYP, Entry, Grant, decode_record, encode_record
from agent_bailiff.docket.grant import MAX_ROOT_TOKEN_CHARS
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.signing import MAX_TOKEN_CHARS, Refused, sign

DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
WRITERS = {
    "decide": {"decide-1": DECIDE_KEY.public_key()},
    "issuer": {"issuer-1": ISSUER_KEY.public_key()},
}
INDEX = build_kid_index(WRITERS, grant_writers={"issuer"})
GRANT = Grant(grant_id="g-1", at=1_700_000_000, root_token="root.token")
GOLDEN_ENTRY = Entry(
    entry_id="e-1",
    trace_id="t-1",
    hop="decide",
    component="decide",
    decision="allow",
    at=1_700_000_000,
    op_id="op-1",
    tenant="acme",
    task_root="root-1",
    links=("l-1",),
    tool="read",
    resource="doc",
    cost=3,
    latency_ms=7,
    performed=True,
    credential_tier="effector",
    handles={"task": "task-1", "tenant": "acme"},
)
GOLDEN_TOKEN = (
    "eyJhZ2VudF9rZXkiOm51bGwsImFyZ3NfZGlnZXN0IjpudWxsLCJhdCI6MTcwMDAwMDAwMCwiY2xlYXJhbmNlX2RpZ2VzdCI6bnVsbCwiY29tcG9u"
    "ZW50IjoiZGVjaWRlIiwiY29zdCI6MywiY3JlZGVudGlhbF90aWVyIjoiZWZmZWN0b3IiLCJkZWNpc2lvbiI6ImFsbG93IiwiZW50cnlfaWQiOiJl"
    "LTEiLCJoYW5kbGVzIjp7InRhc2siOiJ0YXNrLTEiLCJ0ZW5hbnQiOiJhY21lIn0sImhvcCI6ImRlY2lkZSIsImtpZCI6ImRlY2lkZS0xIiwibGF0"
    "ZW5jeV9tcyI6NywibGlua3MiOlsibC0xIl0sIm9wX2lkIjoib3AtMSIsIm91dGNvbWUiOm51bGwsInBhcmVudF9lbnRyeSI6bnVsbCwicGVyZm9y"
    "bWVkIjp0cnVlLCJwb2xpY3lfZGlnZXN0IjpudWxsLCJwb2xpY3lfaWQiOm51bGwsInBvbGljeV92ZXJzaW9uIjpudWxsLCJwcmV2IjoicHJldi1o"
    "YXNoIiwicHJpbmNpcGFsIjpudWxsLCJyZWFzb24iOm51bGwsInJlY2VpcHRfZGlnZXN0IjpudWxsLCJyZXNvdXJjZSI6ImRvYyIsInJ1bGUiOm51"
    "bGwsInNlcSI6MiwidGFza19yb290Ijoicm9vdC0xIiwidGVuYW50IjoiYWNtZSIsInRvb2wiOiJyZWFkIiwidHJhY2VfaWQiOiJ0LTEiLCJ0eXAi"
    "OiJhZ2VudC1iYWlsaWZmL2RvY2tldC1lbnRyeS92MSIsInYiOjEsInZlcmRpY3QiOm51bGwsIndyaXRlciI6ImRlY2lkZSJ9.nn-IrWLtLqfNFz1J"
    "SMwU0EuRTyaSpgHyzmfaTC_oCc01MCGO8UI2B5WOLWABFF2xCDbvw6IHXedlt9MaRCrrAQ"
)


def grant_record(grant=GRANT, seq=1, prev=None):
    return encode_record(ISSUER_KEY, "issuer-1", "issuer", seq, prev, grant)


def grant_payload(**changes):
    body = {"grant_id": "g-1", "at": 1_700_000_000, "root_token": "root.token", "writer": "issuer", "seq": 1}
    return {**body, "prev": None, **changes}


def resigned(token, change):
    encoded, _, signature = token.partition(".")
    payload = json.loads(b64u_decode(encoded))
    change(payload)
    return f"{b64u(canonicalize(payload))}.{signature}"


def refusal(token, index=INDEX):
    result = decode_record(token, index)
    assert isinstance(result, Refused), result
    return result


def test_a_grant_round_trips_through_its_token():
    record = grant_record()
    decoded = decode_record(record.token, INDEX)
    assert decoded == record
    assert decoded.entry == GRANT


def test_a_grant_token_carries_only_the_grant_fields():
    payload = json.loads(b64u_decode(grant_record().token.partition(".")[0]))
    assert payload == {**grant_payload(), "typ": GRANT_TYP, "v": 1, "kid": "issuer-1"}


def test_an_entry_v1_token_stays_byte_identical():
    record = encode_record(DECIDE_KEY, "decide-1", "decide", 2, "prev-hash", GOLDEN_ENTRY)
    assert record.token == GOLDEN_TOKEN
    assert decode_record(GOLDEN_TOKEN, INDEX).entry == GOLDEN_ENTRY


def test_an_unknown_record_type_is_refused_as_wrong_typ():
    token = sign(ISSUER_KEY, "issuer-1", "agent-bailiff/docket-other/v1", grant_payload())
    assert refusal(token).reason == "wrong_typ"


def test_a_record_type_rewritten_after_signing_is_refused():
    token = resigned(grant_record().token, lambda payload: payload.update(typ=ENTRY_TYP))
    assert refusal(token).reason == "malformed"


def test_a_record_type_rewritten_to_an_unknown_type_is_refused_before_verify():
    token = resigned(grant_record().token, lambda payload: payload.update(typ="agent-bailiff/docket-grant/v2"))
    assert refusal(token).reason == "wrong_typ"


def test_a_grant_changed_after_signing_fails_the_signature():
    token = resigned(grant_record().token, lambda payload: payload.update(grant_id="g-2"))
    assert refusal(token).reason == "bad_signature"


def test_a_duplicate_typ_is_refused_as_malformed():
    encoded, _, signature = grant_record().token.partition(".")
    raw = b64u_decode(encoded)
    duplicated = raw[:-1] + b',"typ":"' + ENTRY_TYP.encode() + b'"}'
    result = refusal(f"{b64u(duplicated)}.{signature}")
    assert (result.reason, result.detail.startswith("record type cannot be read")) == ("malformed", True)


@pytest.mark.parametrize("token", ["", "no-separator", "!!!.sig", f"{b64u(b'[1]')}.sig", f"{b64u(b'{}')}.sig"])
def test_an_unreadable_record_type_is_refused_as_malformed(token):
    assert refusal(token).reason == "malformed"


def test_a_typ_that_is_not_a_string_is_refused_as_malformed():
    assert refusal(f"{b64u(canonicalize({'typ': 1}))}.sig").reason == "malformed"


def test_an_oversized_token_is_refused_before_the_peek():
    assert refusal("a" * (MAX_TOKEN_CHARS + 1)).reason == "oversized"


def test_a_token_that_is_not_a_string_is_malformed():
    assert refusal(b"token").reason == "malformed"


@pytest.mark.parametrize("missing", ["grant_id", "at", "root_token", "writer", "seq", "prev"])
def test_a_grant_missing_a_field_is_refused(missing):
    payload = grant_payload()
    del payload[missing]
    assert refusal(sign(ISSUER_KEY, "issuer-1", GRANT_TYP, payload)).reason == "missing_fields"


@pytest.mark.parametrize("extra", ["tool", "task_root", "entry_id"])
def test_a_grant_with_an_entry_field_is_refused(extra):
    token = sign(ISSUER_KEY, "issuer-1", GRANT_TYP, grant_payload(**{extra: "x"}))
    assert refusal(token).reason == "malformed"


def entry_payload():
    record = encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, GOLDEN_ENTRY)
    payload = json.loads(b64u_decode(record.token.partition(".")[0]))
    return {name: value for name, value in payload.items() if name not in {"typ", "v", "kid"}}


def test_an_entry_with_a_grant_field_is_refused():
    token = sign(DECIDE_KEY, "decide-1", ENTRY_TYP, {**entry_payload(), "root_token": "root.token"})
    assert refusal(token).reason == "malformed"


def test_an_entry_missing_a_field_is_refused():
    body = entry_payload()
    del body["tool"]
    assert refusal(sign(DECIDE_KEY, "decide-1", ENTRY_TYP, body)).reason == "missing_fields"


@pytest.mark.parametrize(
    "changes",
    [
        {"grant_id": ""},
        {"grant_id": 7},
        {"at": -1},
        {"at": True},
        {"at": "1"},
        {"root_token": ""},
        {"root_token": 5},
        {"root_token": "ré"},
        {"root_token": "r" * (MAX_ROOT_TOKEN_CHARS + 1)},
        {"seq": 0},
        {"seq": 2, "prev": None},
        {"seq": 1, "prev": "x"},
        {"writer": ""},
    ],
)
def test_a_signed_grant_with_an_invalid_value_is_refused(changes):
    token = sign(ISSUER_KEY, "issuer-1", GRANT_TYP, grant_payload(**changes))
    assert refusal(token).reason == "invalid_field"


@pytest.mark.parametrize(
    "grant",
    [
        Grant("", 1, "root"),
        Grant("g-1", -1, "root"),
        Grant("g-1", 1, ""),
        Grant("g-1", 1, "ré"),
        Grant("g-1", 1, "r" * (MAX_ROOT_TOKEN_CHARS + 1)),
    ],
)
def test_an_invalid_grant_cannot_be_encoded(grant):
    with pytest.raises(ValueError):
        grant_record(grant)


def test_a_root_token_at_the_bound_is_encoded():
    grant = Grant("g-1", 1, "r" * MAX_ROOT_TOKEN_CHARS)
    assert decode_record(grant_record(grant).token, INDEX).entry == grant


def test_a_grant_writer_emitting_an_entry_is_refused():
    record = encode_record(ISSUER_KEY, "issuer-1", "issuer", 1, None, GOLDEN_ENTRY)
    result = refusal(record.token)
    assert result.reason == "wrong_record_type"
    assert result.detail == f"writer issuer is pinned for {GRANT_TYP} records, not {ENTRY_TYP}"


def test_an_entry_writer_emitting_a_grant_is_refused():
    record = encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, GRANT)
    assert refusal(record.token).reason == "wrong_record_type"


def test_a_reader_pinning_the_grant_writer_as_an_entry_writer_refuses_its_grants():
    assert refusal(grant_record().token, build_kid_index(WRITERS)).reason == "wrong_record_type"


def test_a_grant_from_another_writers_key_is_refused():
    record = encode_record(ISSUER_KEY, "issuer-1", "decide", 1, None, GRANT)
    assert refusal(record.token).reason == "unknown_writer"


def test_a_grant_writer_must_be_a_pinned_writer():
    with pytest.raises(ValueError, match="grant writers are not pinned writers: control"):
        build_kid_index(WRITERS, grant_writers={"issuer", "control"})


def test_the_kid_index_pins_each_writer_to_one_record_type():
    assert {kid: pin.typ for kid, pin in INDEX.items()} == {"decide-1": ENTRY_TYP, "issuer-1": GRANT_TYP}
