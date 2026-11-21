import base64

import pytest
from test_quickstart_canary import needles

TOKEN = "0123456789abcdef0123456789abcdef01234567"
CONTEXTS = [
    ("", ""),
    ("token ", ""),
    ("Authorization: token ", "\r\n"),
    ('{"token":"', '"}'),
    ('{"a":"', '"}'),
    ("x=", "&y=1"),
]


@pytest.mark.parametrize(("prefix", "suffix"), CONTEXTS)
def test_a_needle_matches_the_token_inside_base64(prefix, suffix):
    encoded = base64.b64encode(f"{prefix}{TOKEN}{suffix}".encode()).decode()
    assert any(needle in encoded for needle in needles(TOKEN))


def test_the_plain_token_is_a_needle():
    assert any(needle in f"Authorization: token {TOKEN}" for needle in needles(TOKEN))


def test_no_needle_matches_another_token():
    other = base64.b64encode(f"token {TOKEN[::-1]}".encode()).decode()
    assert not any(needle in other for needle in needles(TOKEN))
