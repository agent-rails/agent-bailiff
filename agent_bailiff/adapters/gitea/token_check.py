from __future__ import annotations

import http.client
import re
import socket
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
REPOSITORY_SCOPES = frozenset({"read:repository", "write:repository"})
SCOPE_FORM = re.compile(r"(read|write):([a-z]+)")
LOGIN_FORM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
NAME = r"[A-Za-z0-9._-]+"
REPO_FORM = re.compile(rf"({NAME})/({NAME})")
BINDING_FORM = re.compile(rf"gitea/repos/({NAME})/(\*|{NAME})")
VISIBILITIES = frozenset({"public", "limited", "private"})
NON_PUBLIC_VISIBILITIES = frozenset({"limited", "private"})
PAGE_LIMIT = 50
DEFAULT_MAX_REPOS = 1000
MAX_NAMED_REPOS = 10
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 3600.0
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
    private_total: int


@dataclass(frozen=True)
class Repo:
    id: int
    full_name: str
    private: bool
    owner_visibility: str

    @property
    def non_public(self) -> bool:
        return self.private or self.owner_visibility in NON_PUBLIC_VISIBILITIES


@dataclass(frozen=True)
class Binding:
    owner: str
    repo: str | None

    def covers(self, repo: Repo) -> bool:
        owner, name = repo.full_name.split("/")
        return owner.casefold() == self.owner and (self.repo is None or name.casefold() == self.repo)


def check_token(
    header_value: str,
    *,
    api_url: str,
    binding_resource: str,
    required: Iterable[str],
    cafile: str | None = None,
    unix_socket: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_repos: int = DEFAULT_MAX_REPOS,
    clock: Callable[[], float] = time.monotonic,
) -> TokenCheck:
    permissions = parse_required(required)
    binding = parse_binding(binding_resource)
    if isinstance(max_repos, bool) or not isinstance(max_repos, int) or max_repos < 1:
        raise ValueError("max_repos must be a positive int")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be a number of seconds above 0 and at most {MAX_TIMEOUT_SECONDS:g}")
    provider = Provider(
        api_url, header_value, cafile=cafile, unix_socket=unix_socket, deadline=clock() + timeout, clock=clock
    )
    scopes, login = fetch_token_info(provider)
    broader = broader_scopes(scopes, permissions)
    if broader:
        raise TokenCheckRefused(
            "broader_scopes", f"the token holds scopes beyond the required ones: {', '.join(broader)}"
        )
    private = fetch_private_repos(provider, max_repos)
    visible = fetch_visible_repos(provider, max_repos)
    outside = outside_binding((*private, *visible), binding)
    if outside:
        raise TokenCheckRefused("outside_binding", _outside_detail(outside, binding_resource))
    return TokenCheck(scopes, login, len(private))


def parse_binding(binding_resource: str) -> Binding:
    match = BINDING_FORM.fullmatch(binding_resource) if isinstance(binding_resource, str) else None
    if match is None:
        raise ValueError("the binding resource must be gitea/repos/<owner>/* or gitea/repos/<owner>/<repo>")
    owner, repo = match.groups()
    return Binding(owner.casefold(), None if repo == "*" else repo.casefold())


def fetch_private_repos(provider: Provider, max_repos: int) -> tuple[Repo, ...]:
    repos = _search_repos(provider, "is_private=true&", max_repos)
    if not all(repo.private for repo in repos):
        raise _bad_response("the private repository search returned a public repository")
    return repos


def fetch_visible_repos(provider: Provider, max_repos: int) -> tuple[Repo, ...]:
    return _search_repos(provider, "", max_repos)


def outside_binding(repos: Iterable[Repo], binding: Binding) -> tuple[Repo, ...]:
    outside = {repo.id: repo for repo in repos if repo.non_public and not binding.covers(repo)}
    return tuple(sorted(outside.values(), key=lambda repo: repo.full_name.casefold()))


def parse_required(required: Iterable[str]) -> frozenset[str]:
    if isinstance(required, str):
        raise ValueError("required permissions must be a list of scope names")
    permissions = frozenset(required)
    for name in permissions:
        if name != PUBLIC_ONLY and (not isinstance(name, str) or SCOPE_FORM.fullmatch(name) is None):
            raise ValueError(
                f"required permission {_shown(name)} is not read:<category>, write:<category> or public-only"
            )
    if not permissions & REPOSITORY_SCOPES:
        raise ValueError("required permissions must include read:repository or write:repository")
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


def _search_repos(provider: Provider, query: str, max_repos: int) -> tuple[Repo, ...]:
    seen: dict[int, Repo] = {}
    total: int | None = None
    served = 0
    page = 1
    while True:
        headers, document = provider.get_with_headers(f"/repos/search?{query}limit={PAGE_LIMIT}&page={page}")
        page_total = _total_count(headers)
        if total is None:
            total = page_total
            if total > max_repos:
                raise TokenCheckRefused(
                    "too_many_repos", f"a repository search reports {total} repositories, more than {max_repos}"
                )
        elif page_total != total:
            raise TokenCheckRefused("paging_drift", "the repository total changed between pages")
        items = _search_items(document)
        if not items:
            break
        served += len(items)
        if served > max_repos:
            raise TokenCheckRefused(
                "too_many_repos", f"a repository search served more than {max_repos} items across its pages"
            )
        before = len(seen)
        for item in items:
            repo = _repo(item)
            if seen.setdefault(repo.id, repo) != repo:
                raise TokenCheckRefused("paging_drift", "a repository changed between pages")
        if len(seen) == before or len(seen) > total:
            raise TokenCheckRefused("paging_drift", "the repository pages disagree with the reported total")
        if len(seen) == total:
            break
        page += 1
    if len(seen) != total:
        raise TokenCheckRefused("paging_drift", "the repository pages disagree with the reported total")
    return tuple(seen.values())


def _total_count(headers: http.client.HTTPMessage) -> int:
    values = headers.get_all("X-Total-Count") or []
    if len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
        raise _bad_response("a repository search has no single X-Total-Count")
    return int(values[0])


def _search_items(document: Any) -> list[Any]:
    items = document.get("data") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise _bad_response("a repository search answer has no data list")
    return items


def _repo(item: Any) -> Repo:
    if not isinstance(item, dict):
        raise _bad_response("a repository search item is not an object")
    repo_id = item.get("id")
    full_name = item.get("full_name")
    private = item.get("private")
    owner = item.get("owner")
    visibility = owner.get("visibility") if isinstance(owner, dict) else None
    if isinstance(repo_id, bool) or not isinstance(repo_id, int):
        raise _bad_response("a repository search item has no id")
    if not isinstance(full_name, str) or REPO_FORM.fullmatch(full_name) is None:
        raise _bad_response("a repository search item has no owner/name")
    if not isinstance(private, bool):
        raise _bad_response("a repository search item has no private flag")
    if not isinstance(visibility, str) or visibility not in VISIBILITIES:
        raise _bad_response("a repository search item has no owner visibility")
    return Repo(repo_id, full_name, private, visibility)


def _outside_detail(outside: tuple[Repo, ...], binding_resource: str) -> str:
    named = ", ".join(repo.full_name for repo in outside[:MAX_NAMED_REPOS])
    more = len(outside) - MAX_NAMED_REPOS
    suffix = f" and {more} more" if more > 0 else ""
    return (
        f"the token's user reaches {len(outside)} non-public repositories outside {binding_resource}: {named}{suffix}"
    )


class Provider:
    def __init__(
        self,
        api_url: str,
        header_value: str,
        *,
        cafile: str | None,
        unix_socket: str | None,
        deadline: float,
        clock: Callable[[], float],
    ) -> None:
        if not isinstance(header_value, str) or not _is_header_value(header_value):
            raise ValueError("the credential must be printable ASCII with no leading or trailing space or tab")
        parts = parse_transport_url(api_url)
        host = parts.hostname or ""
        if unix_socket is not None and parts.scheme != "http":
            raise ValueError("a unix socket carries plain http; the provider api url must be http")
        if parts.scheme == "http" and unix_socket is None and not allows_plain_http(host):
            raise ValueError(f"the provider api url must use https unless its host is {PLAIN_HTTP_HOSTS}")
        if cafile is not None and parts.scheme != "https":
            raise ValueError("a ca file needs an https provider api url")
        self._unix_socket = unix_socket
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
        if self._unix_socket is not None:
            return UnixConnection(self._host, self._unix_socket, timeout)
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


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, host: str, path: str, timeout: float) -> None:
        super().__init__(host, timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self._path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


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
