import json

import pytest
from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import b64u, b64u_decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.signing import MAX_TOKEN_CHARS, Refused, Verified, sign, token_hash, verify

TYP = "agent-bailiff/test-record/v1"
FIELDS = ("op_id", "tenant", "cost", "links")
BODY = {"op_id": "op-1", "tenant": "acme", "cost": 3, "links": ["a", "b"]}
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PINNED = {"k1": KEY.public_key()}


def split(token):
    payload, signature = token.split(".")
    return json.loads(b64u_decode(payload)), b64u_decode(signature)


def forge(payload, key=KEY):
    raw = canonicalize(payload)
    return f"{b64u(raw)}.{b64u(key.sign(raw))}"


def test_round_trip_returns_the_body_and_kid():
    result = verify(sign(KEY, "k1", TYP, BODY), PINNED, TYP, FIELDS)
    assert result == Verified(payload=BODY, kid="k1")
    assert result.ok


def test_payload_carries_typ_version_and_kid():
    payload, _ = split(sign(KEY, "k1", TYP, BODY))
    assert payload == {**BODY, "typ": TYP, "v": 1, "kid": "k1"}


def test_signing_is_deterministic():
    assert sign(KEY, "k1", TYP, BODY) == sign(KEY, "k1", TYP, BODY)


@pytest.mark.parametrize("field", ["op_id", "tenant", "cost", "links", "typ", "v", "kid"])
def test_tampering_with_any_field_fails(field):
    payload, signature = split(sign(KEY, "k1", TYP, BODY))
    replacements = {"op_id": "op-2", "tenant": "evil", "cost": 0, "links": ["a"], "typ": TYP, "v": 2, "kid": "k2"}
    payload[field] = replacements[field] if payload[field] != replacements[field] else "other"
    token = f"{b64u(canonicalize(payload))}.{b64u(signature)}"
    result = verify(token, {"k1": KEY.public_key(), "k2": KEY.public_key()}, TYP, FIELDS)
    assert isinstance(result, Refused)
    assert result.reason == "bad_signature"


def test_tampered_signature_fails():
    payload, signature = sign(KEY, "k1", TYP, BODY).split(".")
    flipped = bytearray(b64u_decode(signature))
    flipped[0] ^= 1
    assert verify(f"{payload}.{b64u(bytes(flipped))}", PINNED, TYP, FIELDS) == Refused(
        "bad_signature", "signature does not verify"
    )


def test_signature_from_another_key_fails():
    assert verify(sign(OTHER, "k1", TYP, BODY), PINNED, TYP, FIELDS).reason == "bad_signature"


def test_unknown_kid_is_refused():
    assert verify(sign(KEY, "k9", TYP, BODY), PINNED, TYP, FIELDS).reason == "unknown_kid"


def test_wrong_typ_is_refused():
    token = sign(KEY, "k1", "agent-bailiff/clearance/v1", BODY)
    assert verify(token, PINNED, TYP, FIELDS).reason == "wrong_typ"


def test_unknown_field_is_refused():
    token = sign(KEY, "k1", TYP, {**BODY, "extra": 1})
    result = verify(token, PINNED, TYP, FIELDS)
    assert result.reason == "malformed"
    assert "extra" in result.detail


def test_missing_field_is_refused():
    body = {key: value for key, value in BODY.items() if key != "cost"}
    result = verify(sign(KEY, "k1", TYP, body), PINNED, TYP, FIELDS)
    assert result == Refused("missing_fields", "missing fields: cost")


def test_missing_reserved_field_is_refused():
    payload = {**BODY, "typ": TYP, "kid": "k1"}
    assert verify(forge(payload), PINNED, TYP, FIELDS).reason == "malformed"


def test_unsupported_version_is_refused():
    payload = {**BODY, "typ": TYP, "v": 2, "kid": "k1"}
    assert verify(forge(payload), PINNED, TYP, FIELDS).reason == "unsupported_version"


def test_non_canonical_payload_is_refused():
    payload = {**BODY, "typ": TYP, "v": 1, "kid": "k1"}
    raw = json.dumps(payload, sort_keys=False, separators=(",", ":")).encode()
    assert raw != canonicalize(payload)
    token = f"{b64u(raw)}.{b64u(KEY.sign(raw))}"
    assert verify(token, PINNED, TYP, FIELDS).reason == "non_canonical"


def test_oversized_token_is_refused():
    assert verify("a" * (MAX_TOKEN_CHARS + 1), PINNED, TYP, FIELDS).reason == "oversized"
    assert verify(sign(KEY, "k1", TYP, BODY), PINNED, TYP, FIELDS, max_chars=10).reason == "oversized"


@pytest.mark.parametrize(
    "token",
    [
        None,
        b"bytes",
        42,
        "",
        "no-separator",
        "a.b.c",
        "!!!.AAAA",
        "e30.AAAA=",
        f"{b64u(b'not json')}.{b64u(b'x' * 64)}",
        f"{b64u(b'[1]')}.{b64u(b'x' * 64)}",
        f"{b64u(b'{"cost":1.5}')}.{b64u(b'x' * 64)}",
        f"{b64u(b'{"a":1,"a":2}')}.{b64u(b'x' * 64)}",
        f"{b64u(b'[' * 5000)}.{b64u(b'x' * 64)}",
    ],
)
def test_attacker_input_is_refused_without_raising(token):
    result = verify(token, PINNED, TYP, FIELDS)
    assert isinstance(result, Refused)
    assert result.reason == "malformed"


def test_short_signature_is_refused():
    payload = sign(KEY, "k1", TYP, BODY).split(".")[0]
    assert verify(f"{payload}.{b64u(b'x' * 10)}", PINNED, TYP, FIELDS).reason == "bad_signature"


def test_programmer_errors_raise():
    with pytest.raises(ValueError, match="reserved"):
        sign(KEY, "k1", TYP, {"kid": "k2"})
    with pytest.raises(ValueError):
        sign(KEY, "k1", TYP, {"cost": 1.5})
    with pytest.raises(TypeError):
        sign(KEY.public_key(), "k1", TYP, BODY)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="kid"):
        sign(KEY, "", TYP, BODY)
    with pytest.raises(TypeError):
        verify("x", PINNED, TYP, "op_id")
    with pytest.raises(ValueError, match="reserved"):
        verify("x", PINNED, TYP, ("typ",))
    with pytest.raises(TypeError):
        verify("x", {"k1": KEY}, TYP, FIELDS)  # type: ignore[dict-item]


def test_token_hash_is_base64url_sha256():
    digest = token_hash(sign(KEY, "k1", TYP, BODY))
    assert len(b64u_decode(digest)) == 32
    assert digest != token_hash(sign(KEY, "k1", TYP, {**BODY, "cost": 4}))


@pytest.mark.parametrize(
    ("pinned", "typ", "fields", "error"),
    [
        ([("k1", KEY.public_key())], TYP, FIELDS, TypeError),
        (None, TYP, FIELDS, TypeError),
        ({"": KEY.public_key()}, TYP, FIELDS, TypeError),
        (PINNED, TYP, (1,), TypeError),
        (PINNED, TYP, ("",), TypeError),
        (PINNED, TYP, None, TypeError),
        (PINNED, "", FIELDS, ValueError),
        (PINNED, 7, FIELDS, ValueError),
    ],
)
def test_invalid_configuration_raises_before_the_token_is_read(pinned, typ, fields, error):
    token = sign(KEY, "k1", TYP, BODY)
    for candidate in (token, "malformed"):
        with pytest.raises(error):
            verify(candidate, pinned, typ, fields)
