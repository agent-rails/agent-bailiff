import pytest

from agent_bailiff.plain_http import allows_plain_http, parse_transport_url


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_plain_http_is_allowed_for_a_literal_loopback_address(host):
    assert allows_plain_http(host)


@pytest.mark.parametrize("host", ["localhost", "localhost.", "ip6-localhost"])
def test_plain_http_is_refused_for_a_loopback_name(host):
    assert not allows_plain_http(host)


@pytest.mark.parametrize(
    "host",
    [
        "gateway",
        "gitea-mcp",
        "svc_1",
        "gateway.local",
        "10.0.0.1",
        "gateway.example.com",
        "10.0.0.5",
        "167772165",
        "0xa000005",
        "",
        "Gateway",
        "a b",
    ],
)
def test_plain_http_is_refused_for_every_other_host(host):
    assert not allows_plain_http(host)


@pytest.mark.parametrize(
    ("text", "bare_host", "host", "port"),
    [
        ("https://mcp.example.com/mcp", False, "mcp.example.com", None),
        ("http://gateway:8080/mcp", False, "gateway", 8080),
        ("http://[::1]:8080", False, "::1", 8080),
        ("gateway", True, "gateway", None),
        ("gateway:8080", True, "gateway", 8080),
        ("[::1]", True, "::1", None),
        ("[::1]:8080", True, "::1", 8080),
    ],
)
def test_a_well_formed_transport_url_is_parsed(text, bare_host, host, port):
    parts = parse_transport_url(text, bare_host=bare_host)
    assert (parts.hostname, parts.port) == (host, port)


@pytest.mark.parametrize(
    ("text", "bare_host"),
    [
        ("gateway#@evil.com", True),
        ("gateway?@evil.com", True),
        ("gateway/@evil.com", True),
        ("gateway/", True),
        ("gateway:abc", True),
        ("gateway:99999", True),
        ("gate\tway", True),
        ("gate way", True),
        ("gateway\n", True),
        ("gateway\x00", True),
        ("gateway\x7f", True),
        ("gateway\\@evil.com", True),
        ("::1", True),
        ("user@gateway", True),
        ("", True),
        ("http://gateway/mcp", True),
        ("http://gateway:abc/mcp", False),
        ("http://gateway:99999/mcp", False),
        ("http://gate\tway/mcp", False),
        ("http://gateway/mcp?", False),
        ("http://gateway/mcp?x=1", False),
        ("http://gateway/mcp#", False),
        ("http://gateway/mcp#x", False),
        ("http://user:pw@gateway/mcp", False),
        ("http:///mcp", False),
        ("http://::1/mcp", False),
        ("ftp://gateway/mcp", False),
        ("gateway", False),
        ("gateway:", True),
        ("gateway:0", True),
        ("http://gateway:/mcp", False),
        ("http://gateway:0/mcp", False),
        ("https://gateway/\x80", False),
        ("https://gateway/\u00e9", False),
        ("https://g\u00e9teway/mcp", False),
    ],
)
def test_a_malformed_transport_url_is_refused(text, bare_host):
    with pytest.raises(ValueError):
        parse_transport_url(text, bare_host=bare_host)
