import base64
import json
import random
import string
from urllib.parse import quote, quote_plus

import pytest

from agent_bailiff.client.client import REFUSAL_REASONS
from agent_bailiff.custodian.echo import (
    MARKER,
    MAX_RESULT_BYTES,
    MIN_NEEDLE_LENGTH,
    Oversize,
    Redaction,
    UnreadableResult,
    needles,
    redact,
    redaction_problem,
)

TOKEN = "s3cr3t-T0ken/with+chars=="
HEADER = f"Bearer {TOKEN}"
ENCODERS = (base64.b64encode, base64.urlsafe_b64encode)


def result(value):
    return json.dumps({"content": [{"type": "text", "text": value}]}).encode()


def text(redaction):
    return json.loads(redaction.result)["content"][0]["text"]


def found(header, embedded):
    return any(needle in embedded for needle in needles(header))


def test_min_needle_length_is_twelve():
    assert MIN_NEEDLE_LENGTH == 12


def test_the_marker_is_not_a_refusal_reason():
    assert MARKER not in REFUSAL_REASONS


def test_an_empty_header_value_is_refused():
    with pytest.raises(ValueError):
        needles("")


@pytest.mark.parametrize("encode", ENCODERS)
def test_every_base64_embedding_of_a_token_is_found(encode):
    chooser = random.Random(80)
    alphabet = string.ascii_letters + string.digits + "-._~+/="
    for length in range(12, 65):
        token = "".join(chooser.choice(alphabet) for _ in range(length))
        header = f"Bearer {token}"
        for prefix in range(6):
            for suffix in range(6):
                embedded = encode(b"p" * prefix + token.encode() + b"s" * suffix).decode()
                assert found(header, embedded), (length, prefix, suffix)
                assert found(header, embedded.rstrip("=")), (length, prefix, suffix)


def test_no_needle_carries_padding():
    assert all("=" not in needle for needle in needles(HEADER) if needle not in (HEADER, TOKEN))


def test_the_token_after_the_scheme_is_a_needle():
    assert TOKEN in needles(HEADER)
    assert HEADER in needles(HEADER)


def test_the_scheme_split_takes_the_whole_whitespace_run():
    header = f"Bearer  \t{TOKEN}"
    assert TOKEN in needles(header)
    assert f" \t{TOKEN}" not in needles(header)


def test_needles_are_unique_and_longest_first():
    found_needles = needles(HEADER)
    assert len(found_needles) == len(set(found_needles))
    assert [len(needle) for needle in found_needles] == sorted((len(needle) for needle in found_needles), reverse=True)


def test_basic_credentials_yield_the_pair_and_the_password():
    pair = "deploy-user:correct-horse-battery"
    header = "Basic " + base64.b64encode(pair.encode()).decode()
    assert pair in needles(header)
    assert "correct-horse-battery" in needles(header)


def test_a_basic_scheme_that_does_not_decode_is_not_basic():
    header = "Basic not*base64*at*all"
    assert header in needles(header)
    assert "not*base64*at*all" in needles(header)


def test_percent_forms_cover_upper_lower_and_plus():
    token = "value with/slash and space"
    found_needles = needles(f"Bearer {token}")
    upper = quote(token, safe="")
    assert upper in found_needles
    assert upper.replace("%2F", "%2f") in found_needles
    assert quote_plus(token) in found_needles


def test_short_needles_are_dropped():
    assert needles("tok-1234") == ()
    assert "short" not in needles("Bearer short")
    assert all(len(needle) >= MIN_NEEDLE_LENGTH for needle in needles(HEADER))


@pytest.mark.parametrize(
    "header",
    ["tok-1234", "Bearer short-key", "Basic dXNlcjpzaG9ydHB3"],
)
def test_a_credential_with_any_form_under_the_needle_length_is_too_short_to_redact(header):
    assert redaction_problem(header) == "a form of it is shorter than 12 characters"


@pytest.mark.parametrize(
    "header",
    [
        f"Basic {base64.b64encode(b'user-long-name:\xff\xfe-password-long').decode()}",
        f"Basic {base64.b64encode(b'user-long-name-without-a-separator').decode()}",
        "Basic not-base64-at-all!",
    ],
)
def test_a_basic_token_that_is_not_a_utf8_user_password_cannot_be_redacted(header):
    assert redaction_problem(header) == "its basic token is not base64 of a UTF-8 user:password"


@pytest.mark.parametrize(
    "header",
    [HEADER, f"Basic {base64.b64encode(b'user-long-name:password-long').decode()}", "Bearer long-enough-token"],
)
def test_a_credential_with_every_form_at_the_needle_length_is_redactable(header):
    assert redaction_problem(header) is None


def test_no_hit_returns_none():
    assert redact(result("nothing to see"), needles(HEADER)) is None


def test_no_needles_returns_none():
    assert redact(result(HEADER), ()) is None


def test_a_raw_echo_is_replaced_by_the_marker():
    redaction = redact(result(f"auth was {HEADER}."), needles(HEADER))
    assert isinstance(redaction, Redaction)
    assert text(redaction) == f"auth was {MARKER}."
    assert redaction.hits == 1


@pytest.mark.parametrize("encode", ENCODERS)
def test_a_base64_echo_leaves_no_token_fragment(encode):
    encoded = encode(f"Authorization: {HEADER}\n".encode()).decode()
    redaction = redact(result(encoded), needles(HEADER))
    assert redaction is not None
    assert MARKER in text(redaction)


def test_each_occurrence_is_replaced():
    redaction = redact(result(f"{TOKEN} and {TOKEN}"), needles(HEADER))
    assert text(redaction) == f"{MARKER} and {MARKER}"
    assert redaction.hits == 2


def test_overlapping_needles_merge_into_one_marker():
    token = "abcabcabcabc"
    redaction = redact(result("abcabcabcabcabc"), needles(f"Bearer {token}"))
    assert text(redaction) == MARKER
    assert redaction.hits == 1


def test_the_marker_is_never_nested():
    redaction = redact(result(f"x{HEADER}y"), needles(HEADER))
    assert text(redaction) == f"x{MARKER}y"
    assert MARKER + "]" not in text(redaction)


def test_keys_are_redacted():
    raw = json.dumps({"content": [], "structuredContent": {TOKEN: 1}}).encode()
    redaction = redact(raw, needles(HEADER))
    assert json.loads(redaction.result)["structuredContent"] == {MARKER: 1}


def test_nested_structured_content_and_error_results_are_redacted():
    document = {
        "content": [{"type": "text", "text": "failed"}],
        "isError": True,
        "structuredContent": {"a": [{"b": [f"x {TOKEN}"]}], "n": 1.5, "flag": None},
    }
    redaction = redact(json.dumps(document).encode(), needles(HEADER))
    parsed = json.loads(redaction.result)
    assert parsed["isError"] is True
    assert parsed["structuredContent"] == {"a": [{"b": [f"x {MARKER}"]}], "n": 1.5, "flag": None}


def test_the_mutated_result_is_compact_ascii_json():
    redaction = redact(json.dumps({"text": f"café {TOKEN}"}).encode(), needles(HEADER))
    assert redaction.result == b'{"text":"caf\\u00e9 ' + MARKER.encode() + b'"}'


def test_a_lone_surrogate_does_not_crash():
    raw = b'{"text": "\\ud800 ' + TOKEN.replace("/", "\\/").encode() + b'"}'
    redaction = redact(raw, needles(HEADER))
    assert redaction.result == b'{"text":"\\ud800 ' + MARKER.encode() + b'"}'


def test_json_escaped_slashes_are_matched_after_decoding():
    raw = b'{"text": "' + TOKEN.replace("/", "\\/").encode() + b'"}'
    assert json.loads(redact(raw, needles(HEADER)).result)["text"] == MARKER


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a": 1, "a": 2}',
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": 1e400}',
        b"[1, 2]",
        b'"text"',
        b"not json",
        b"\xff\xfe\xfd",
        b"[" * 100_000 + b"]" * 100_000,
    ],
)
def test_unreadable_results_are_refused(raw):
    with pytest.raises(UnreadableResult):
        redact(raw, needles(HEADER))


def test_an_unreadable_result_is_refused_even_without_needles():
    with pytest.raises(UnreadableResult):
        redact(b'{"a": NaN}', ())


def test_a_key_collision_after_redaction_is_refused():
    raw = json.dumps({"structuredContent": {TOKEN: 1, MARKER: 2}}).encode()
    with pytest.raises(UnreadableResult):
        redact(raw, needles(HEADER))


def test_an_input_over_the_cap_is_refused():
    raw = result("a" * MAX_RESULT_BYTES)
    with pytest.raises(UnreadableResult):
        redact(raw, needles(HEADER))


def test_a_mutated_result_over_the_cap_is_oversize():
    raw = json.dumps({"text": "é" * 1_000_000 + TOKEN}, ensure_ascii=False).encode()
    assert len(raw) <= MAX_RESULT_BYTES
    with pytest.raises(Oversize):
        redact(raw, needles(HEADER))


@pytest.mark.parametrize("pair", [b"user-long-name:", b":password-long"])
def test_a_basic_token_with_an_empty_user_or_password_can_be_redacted(pair):
    header = f"Basic {base64.b64encode(pair).decode()}"
    assert redaction_problem(header) is None
    assert pair.decode() in needles(header)
