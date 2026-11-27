from __future__ import annotations

from urllib.parse import SplitResult, urlsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
PLAIN_HTTP_HOSTS = "127.0.0.1, localhost or [::1]"


def allows_plain_http(host: str) -> bool:
    return host in LOOPBACK_HOSTS


def parse_transport_url(text: str, *, bare_host: bool = False) -> SplitResult:
    if not text.isascii():
        raise ValueError("url must be ASCII; write an internationalized host in its IDNA form")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 or char == "\\" for char in text):
        raise ValueError("url must not contain whitespace, control characters or backslashes")
    if any(char in text for char in "?#"):
        raise ValueError("url must not carry a query or fragment")
    if bare_host:
        if "://" in text:
            raise ValueError("a host without a scheme must not be a url")
        parts = urlsplit(f"http://{text}")
        if parts.path:
            raise ValueError("a host without a scheme must be host or host:port")
    else:
        parts = urlsplit(text)
        if parts.scheme not in {"http", "https"}:
            raise ValueError("url must be an http or https URL")
    if not parts.hostname:
        raise ValueError("url must name a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("url must be an http or https URL without credentials")
    if ":" in parts.hostname and not parts.netloc.startswith("["):
        raise ValueError("an IPv6 host must be in brackets")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("url port must be a number from 1 to 65535") from None
    if port == 0 or parts.netloc.endswith(":"):
        raise ValueError("url port must be a number from 1 to 65535")
    return parts
