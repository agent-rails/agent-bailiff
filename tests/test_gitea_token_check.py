import json
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_bailiff.adapters.gitea import token_check
from agent_bailiff.adapters.gitea.token_check import TokenCheck, TokenCheckRefused, broader_scopes, check_token

NEEDLE = "token needle-0123456789abcdef0123456789abcdef"
REQUIRED = ("read:issue", "read:repository")


class FakeGitea:
    def __init__(self):
        self.requests = []
        self.routes = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, dict(self.headers)))
                status, headers, body = owner.routes.get(self.path.split("?")[0], (404, {}, b"{}"))
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/v1"

    def route(self, path, document=None, *, status=200, headers=None, raw=None):
        body = raw if raw is not None else json.dumps(document).encode()
        self.routes[f"/api/v1{path}"] = (status, headers or {}, body)

    def token(self, scopes, login="agent"):
        self.route("/token", {"id": 1, "name": "quickstart", "scopes": scopes, "user": {"id": 5, "login": login}})

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Listener:
    def __init__(self):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.accepted = []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        self.port = self.socket.getsockname()[1]

    def _accept(self):
        while True:
            try:
                connection, _ = self.socket.accept()
            except OSError:
                return
            self.accepted.append(connection)

    def close(self):
        for connection in self.accepted:
            connection.close()
        self.socket.close()


@pytest.fixture
def gitea():
    fake = FakeGitea()
    yield fake
    fake.close()


@pytest.fixture
def listener():
    opened = Listener()
    yield opened
    opened.close()


def check(gitea, header=NEEDLE, **options):
    options.setdefault("required", REQUIRED)
    return check_token(header, api_url=gitea.url, **options)


def refusal(gitea, **options):
    with pytest.raises(TokenCheckRefused) as raised:
        check(gitea, **options)
    assert NEEDLE not in str(raised.value)
    return raised.value


def test_a_token_within_the_required_permissions_passes(gitea):
    gitea.token(["read:repository", "read:issue"])
    assert check(gitea) == TokenCheck(("read:issue", "read:repository"), "agent")
    [(path, headers)] = gitea.requests
    assert path == "/api/v1/token"
    assert headers["Authorization"] == NEEDLE


@pytest.mark.parametrize(
    ("scopes", "required"),
    [
        (["read:repository"], ["write:repository"]),
        (["write:repository"], ["write:repository", "read:issue"]),
        ([], ["read:repository"]),
        (["public-only", "read:repository"], ["read:repository"]),
        (["public-only", "read:repository"], ["public-only", "read:repository"]),
    ],
)
def test_a_scope_covered_by_a_required_one_passes(gitea, scopes, required):
    gitea.token(scopes)
    assert check(gitea, required=required).login == "agent"


@pytest.mark.parametrize(
    ("scopes", "broader"),
    [
        (["write:repository"], "write:repository"),
        (["read:repository", "write:admin"], "write:admin"),
        (["all"], "all"),
        (["read:repository", "read:user"], "read:user"),
        (["public-only", "read:organization"], "read:organization"),
    ],
)
def test_a_scope_beyond_the_required_ones_is_refused_and_named(gitea, scopes, broader):
    gitea.token(scopes)
    refused = refusal(gitea)
    assert refused.reason == "broader_scopes"
    assert broader in str(refused)


def test_public_only_never_grants_a_scope():
    assert broader_scopes(["read:repository"], frozenset({"public-only"})) == ("no public-only", "read:repository")
    assert broader_scopes(["public-only"], frozenset({"public-only"})) == ()


@pytest.mark.parametrize("scope", ["repository", "read:Repository", "admin:repository", "", "read:repo:x", "sudo"])
def test_a_scope_of_unknown_form_is_refused(gitea, scope):
    gitea.token(["read:repository", scope])
    assert refusal(gitea).reason == "unknown_scope"


@pytest.mark.parametrize("required", [["all"], ["repository"], ["read:repository", "admin:x"], "read:repository"])
def test_required_permissions_of_unknown_form_are_refused(gitea, required):
    with pytest.raises(ValueError, match="required permission"):
        check(gitea, required=required)
    assert gitea.requests == []


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (401, "token_rejected"),
        (403, "token_rejected"),
        (429, "rate_limited"),
        (404, "provider_unreachable"),
        (500, "provider_unreachable"),
        (502, "provider_unreachable"),
    ],
)
def test_a_provider_status_other_than_200_is_refused_after_one_request(gitea, status, reason):
    gitea.route("/token", {"message": NEEDLE}, status=status)
    refused = refusal(gitea)
    assert refused.reason == reason
    assert str(status) in str(refused)
    assert len(gitea.requests) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_not_followed(gitea, status):
    target = FakeGitea()
    try:
        target.token(["read:repository"])
        gitea.route("/token", {}, status=status, headers={"Location": f"{target.url}/token"})
        assert refusal(gitea).reason == "redirect_refused"
        assert target.requests == []
    finally:
        target.close()


def test_a_cross_host_redirect_is_refused(gitea):
    gitea.route("/token", {}, status=302, headers={"Location": "https://attacker.example/api/v1/token"})
    assert refusal(gitea).reason == "redirect_refused"
    assert len(gitea.requests) == 1


def test_proxy_settings_are_ignored(gitea, listener, monkeypatch):
    proxy = f"http://127.0.0.1:{listener.port}"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, proxy)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    gitea.token(["read:repository"])
    assert check(gitea).login == "agent"
    assert listener.accepted == []
    assert len(gitea.requests) == 1


def test_a_provider_that_does_not_answer_in_time_is_unreachable(listener):
    with pytest.raises(TokenCheckRefused) as raised:
        check_token(NEEDLE, api_url=f"http://127.0.0.1:{listener.port}/api/v1", required=REQUIRED, timeout=0.2)
    assert raised.value.reason == "provider_unreachable"
    assert NEEDLE not in str(raised.value)


def test_a_refused_connection_is_unreachable():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with pytest.raises(TokenCheckRefused) as raised:
        check_token(NEEDLE, api_url=f"http://127.0.0.1:{port}/api/v1", required=REQUIRED)
    assert raised.value.reason == "provider_unreachable"


def test_a_check_past_its_deadline_is_refused_before_connecting(gitea):
    gitea.token(["read:repository"])
    times = iter([100.0, 110.0])
    refused = refusal(gitea, timeout=10.0, clock=lambda: next(times))
    assert refused.reason == "deadline_exceeded"
    assert gitea.requests == []


def test_a_deadline_reached_while_reading_is_refused(gitea):
    gitea.token(["read:repository"])
    times = iter([100.0, 100.0, 100.0, 110.0])
    assert refusal(gitea, timeout=10.0, clock=lambda: next(times)).reason == "deadline_exceeded"
    assert len(gitea.requests) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'{"scopes": "read:repository", "user": {"login": "agent"}}',
        b'{"scopes": ["read:repository", 7], "user": {"login": "agent"}}',
        b'{"scopes": ["read:repository"]}',
        b'{"scopes": ["read:repository"], "user": {"login": ""}}',
        b'{"scopes": ["read:repository"], "user": {"login": "agent\\n"}}',
        b'{"scopes": ["read:repository"], "user": {"login": "token needle"}}',
        b'{"scopes": ["read:repository"], "user": {"login": "agent"}, "user": {"login": "root"}}',
        b"[" * 100000 + b"]" * 100000,
    ],
)
def test_a_bad_token_info_body_is_refused(gitea, raw):
    gitea.route("/token", raw=raw)
    assert refusal(gitea).reason == "bad_response"


def test_an_answer_over_the_byte_cap_is_refused(gitea, monkeypatch):
    monkeypatch.setattr(token_check, "MAX_RESPONSE_BYTES", 64)
    monkeypatch.setattr(token_check, "READ_CHUNK_BYTES", 16)
    gitea.token(["read:repository"], login="a" * 80)
    assert refusal(gitea).reason == "response_too_large"


def test_an_answer_over_the_byte_cap_without_a_length_is_refused(gitea, monkeypatch):
    monkeypatch.setattr(token_check, "MAX_RESPONSE_BYTES", 64)
    monkeypatch.setattr(token_check, "READ_CHUNK_BYTES", 16)
    original = token_check.Provider._read

    def unknown_length(self, connection, response):
        response.msg.replace_header("Content-Length", "x")
        return original(self, connection, response)

    monkeypatch.setattr(token_check.Provider, "_read", unknown_length)
    gitea.token(["read:repository"], login="a" * 80)
    assert refusal(gitea).reason == "response_too_large"


@pytest.mark.parametrize(
    "api_url",
    [
        "http://gitea.example.com/api/v1",
        "ftp://127.0.0.1/api/v1",
        "http://user:pw@127.0.0.1/api/v1",
        "http://127.0.0.1/api/v1?x=1",
        "http://127.0.0.1/api/v1#x",
    ],
)
def test_a_provider_url_outside_the_transport_rules_is_refused(api_url):
    with pytest.raises(ValueError, match="url"):
        check_token(NEEDLE, api_url=api_url, required=REQUIRED)


def test_a_ca_file_needs_https(gitea, tmp_path):
    with pytest.raises(ValueError, match="https"):
        check(gitea, cafile=str(tmp_path / "ca.pem"))


@pytest.mark.parametrize("header", ["", " token abc", "token abc\r\nX-Other: 1", "token café", NEEDLE + "\n"])
def test_a_credential_that_is_not_a_header_value_is_refused_without_a_request(gitea, header):
    with pytest.raises(ValueError, match="printable ASCII") as raised:
        check(gitea, header=header)
    assert "abc" not in str(raised.value) and NEEDLE not in str(raised.value)
    assert gitea.requests == []


def test_the_credential_never_reaches_a_message_or_log(gitea, caplog):
    caplog.set_level(logging.DEBUG)
    gitea.route("/token", {"message": NEEDLE, "token": NEEDLE}, status=500)
    refusal(gitea)
    gitea.route("/token", raw=json.dumps({"scopes": [NEEDLE], "user": {"login": "agent"}}).encode())
    refused = refusal(gitea)
    assert refused.reason == "unknown_scope"
    assert NEEDLE not in caplog.text
