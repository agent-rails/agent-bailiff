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


QUERY = "url must not carry a query or fragment"
BARE = "a host without a scheme must be host or host:port"
PORT = "url port must be a number from 1 to 65535"
SPACE = "url must not contain whitespace, control characters or backslashes"
NO_HOST = "url must name a host"
CREDENTIALS = "url must be an http or https URL without credentials"
SCHEME = "url must be an http or https URL"
ASCII = "url must be ASCII; write an internationalized host in its IDNA form"


@pytest.mark.parametrize(
    ("text", "bare_host", "reason"),
    [
        ("gateway#@evil.com", True, QUERY),
        ("gateway?@evil.com", True, QUERY),
        ("gateway/@evil.com", True, BARE),
        ("gateway/", True, BARE),
        ("gateway:abc", True, PORT),
        ("gateway:99999", True, PORT),
        ("gate\tway", True, SPACE),
        ("gate way", True, SPACE),
        ("gateway\n", True, SPACE),
        ("gateway\x00", True, SPACE),
        ("gateway\x7f", True, SPACE),
        ("gateway\\@evil.com", True, SPACE),
        ("::1", True, NO_HOST),
        ("user@gateway", True, CREDENTIALS),
        ("", True, NO_HOST),
        ("http://gateway/mcp", True, "a host without a scheme must not be a url"),
        ("http://gateway:abc/mcp", False, PORT),
        ("http://gateway:99999/mcp", False, PORT),
        ("http://gate\tway/mcp", False, SPACE),
        ("http://gateway/mcp?", False, QUERY),
        ("http://gateway/mcp?x=1", False, QUERY),
        ("http://gateway/mcp#", False, QUERY),
        ("http://gateway/mcp#x", False, QUERY),
        ("http://user:pw@gateway/mcp", False, CREDENTIALS),
        ("http:///mcp", False, NO_HOST),
        ("http://::1/mcp", False, NO_HOST),
        ("ftp://gateway/mcp", False, SCHEME),
        ("gateway", False, SCHEME),
        ("gateway:", True, PORT),
        ("gateway:0", True, PORT),
        ("http://gateway:/mcp", False, PORT),
        ("http://gateway:0/mcp", False, PORT),
        ("https://gateway/\x80", False, ASCII),
        ("https://gateway/\u00e9", False, ASCII),
        ("https://g\u00e9teway/mcp", False, ASCII),
    ],
)
def test_a_malformed_transport_url_is_refused(text, bare_host, reason):
    with pytest.raises(ValueError) as refused:
        parse_transport_url(text, bare_host=bare_host)
    assert str(refused.value) == reason
