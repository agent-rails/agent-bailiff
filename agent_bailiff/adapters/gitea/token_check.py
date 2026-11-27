from __future__ import annotations

import http.client
import re
import ssl
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from agent_bailiff.plain_http import PLAIN_HTTP_HOSTS, allows_plain_http, parse_transport_url
from agent_bailiff.strict_json import parse_strict_json

ALL = "all"
PUBLIC_ONLY = "public-only"
ACCESS_LEVELS = {"read": 1, "write": 2}
SCOPE_FORM = re.compile(r"(read|write):([a-z]+)")
LOGIN_FORM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1 << 20
READ_CHUNK_BYTES = 65536
MAX_SHOWN_CHARS = 64


class TokenCheckRefused(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


@dataclass(frozen=True)
class TokenCheck:
    scopes: tuple[str, ...]
    login: str


def check_token(
    header_value: str,
    *,
    api_url: str,
    required: Iterable[str],
    cafile: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> TokenCheck:
    permissions = parse_required(required)
    provider = Provider(api_url, header_value, cafile=cafile, deadline=clock() + timeout, clock=clock)
    scopes, login = fetch_token_info(provider)
    broader = broader_scopes(scopes, permissions)
    if broader:
        raise TokenCheckRefused(
            "broader_scopes", f"the token holds scopes beyond the required ones: {', '.join(broader)}"
        )
    return TokenCheck(scopes, login)


def parse_required(required: Iterable[str]) -> frozenset[str]:
    if isinstance(required, str):
        raise ValueError("required permissions must be a list of scope names")
    permissions = frozenset(required)
    for name in permissions:
        if name != PUBLIC_ONLY and (not isinstance(name, str) or SCOPE_FORM.fullmatch(name) is None):
            raise ValueError(
                f"required permission {_shown(name)} is not read:<category>, write:<category> or public-only"
            )
    return permissions


def broader_scopes(scopes: Iterable[str], required: frozenset[str]) -> tuple[str, ...]:
    granted: dict[str, int] = {}
    for name in required:
        match = SCOPE_FORM.fullmatch(name)
        if match is not None:
            access, category = match.groups()
            granted[category] = max(granted.get(category, 0), ACCESS_LEVELS[access])
    held = frozenset(scopes)
    broader = set()
    for scope in held:
        if scope == PUBLIC_ONLY:
            continue
        if scope == ALL:
            broader.add(scope)
            continue
        match = SCOPE_FORM.fullmatch(scope)
        if match is None:
            raise TokenCheckRefused("unknown_scope", "the provider reported a scope of unknown form")
        access, category = match.groups()
        if ACCESS_LEVELS[access] > granted.get(category, 0):
            broader.add(scope)
    if PUBLIC_ONLY in required and PUBLIC_ONLY not in held:
        broader.add(f"no {PUBLIC_ONLY}")
    return tuple(sorted(broader))


def fetch_token_info(provider: Provider) -> tuple[tuple[str, ...], str]:
    document = provider.get("/token")
    if not isinstance(document, dict):
        raise _bad_response("the token info is not an object")
    scopes = document.get("scopes")
    if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
        raise _bad_response("the token info has no list of scopes")
    user = document.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    if not isinstance(login, str) or LOGIN_FORM.fullmatch(login) is None:
        raise _bad_response("the token info names no user login")
    return tuple(sorted(set(scopes))), login


class Provider:
    def __init__(
        self,
        api_url: str,
        header_value: str,
        *,
        cafile: str | None,
        deadline: float,
        clock: Callable[[], float],
    ) -> None:
        if not isinstance(header_value, str) or not _is_header_value(header_value):
            raise ValueError("the credential must be printable ASCII with no leading or trailing space or tab")
        parts = parse_transport_url(api_url)
        host = parts.hostname or ""
        if parts.scheme == "http" and not allows_plain_http(host):
            raise ValueError(f"the provider api url must use https unless its host is {PLAIN_HTTP_HOSTS}")
        if cafile is not None and parts.scheme != "https":
            raise ValueError("a ca file needs an https provider api url")
        self._https = parts.scheme == "https"
        self._host = host
        self._port = parts.port
        self._base = parts.path.rstrip("/")
        self._header_value = header_value
        self._context = ssl.create_default_context(cafile=cafile) if self._https else None
        self._deadline = deadline
        self._clock = clock

    def get(self, path: str) -> Any:
        return self.get_with_headers(path)[1]

    def get_with_headers(self, path: str) -> tuple[http.client.HTTPMessage, Any]:
        connection = self._connect(self._remaining())
        try:
            connection.request(
                "GET", self._base + path, headers={"Authorization": self._header_value, "Accept": "application/json"}
            )
            response = connection.getresponse()
            _check_status(response.status)
            raw = self._read(connection, response)
            headers = response.msg
        except TimeoutError:
            raise TokenCheckRefused("provider_unreachable", "the provider did not answer in time") from None
        except ssl.SSLError:
            raise TokenCheckRefused("provider_unreachable", "the provider TLS handshake failed") from None
        except (OSError, http.client.HTTPException):
            raise TokenCheckRefused("provider_unreachable", "the provider connection failed") from None
        finally:
            connection.close()
        try:
            return headers, parse_strict_json(raw)
        except (ValueError, RecursionError):
            raise _bad_response("the provider answer is not JSON") from None

    def _connect(self, timeout: float) -> http.client.HTTPConnection:
        if self._https:
            return http.client.HTTPSConnection(self._host, self._port, timeout=timeout, context=self._context)
        return http.client.HTTPConnection(self._host, self._port, timeout=timeout)

    def _read(self, connection: http.client.HTTPConnection, response: http.client.HTTPResponse) -> bytes:
        length = response.getheader("Content-Length")
        if length is not None and length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
            raise TokenCheckRefused(
                "response_too_large", f"a provider answer is larger than {MAX_RESPONSE_BYTES} bytes"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            remaining = self._remaining()
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read(READ_CHUNK_BYTES)
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise TokenCheckRefused(
                    "response_too_large", f"a provider answer is larger than {MAX_RESPONSE_BYTES} bytes"
                )
            chunks.append(chunk)

    def _remaining(self) -> float:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise TokenCheckRefused("deadline_exceeded", "the provider check ran past its deadline")
        return remaining


def _check_status(status: int) -> None:
    if status == 200:
        return
    if 300 <= status < 400:
        raise TokenCheckRefused("redirect_refused", f"the provider answered {status}; redirects are not followed")
    if status in (401, 403):
        raise TokenCheckRefused("token_rejected", f"the provider rejected the token with {status}")
    if status == 429:
        raise TokenCheckRefused("rate_limited", "the provider answered 429; run the check again later")
    raise TokenCheckRefused("provider_unreachable", f"the provider answered {status}")


def _is_header_value(value: str) -> bool:
    if not value or value != value.strip(" \t"):
        return False
    return all(character in " \t" or "!" <= character <= "~" for character in value)


def _bad_response(detail: str) -> TokenCheckRefused:
    return TokenCheckRefused("bad_response", detail)


def _shown(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    return repr(text[:MAX_SHOWN_CHARS])
