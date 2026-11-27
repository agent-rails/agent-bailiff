import hashlib
import io
import json
import logging
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from agent_bailiff import cli
from agent_bailiff.adapters.gitea import token_check
from agent_bailiff.adapters.gitea.token_check import TokenCheck, TokenCheckRefused, broader_scopes, check_token

NEEDLE = "token needle-0123456789abcdef0123456789abcdef"
REQUIRED = ("read:issue", "read:repository")
BINDING = "gitea/repos/quickstart/*"
SEARCH = "/api/v1/repos/search"


class FakeGitea:
    def __init__(self):
        self.requests = []
        self.routes = {SEARCH: self.search}
        self.private = []
        self.visible = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, dict(self.headers)))
                parts = urlsplit(self.path)
                route = owner.routes.get(parts.path, (404, {}, b"{}"))
                status, headers, body = route(parse_qs(parts.query)) if callable(route) else route
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

    def search(self, query):
        items = self.private if query.get("is_private") == ["true"] else self.visible
        limit, page = int(query["limit"][0]), int(query["page"][0])
        return page_answer(items[(page - 1) * limit : page * limit], len(items))

    def searches(self):
        return [path for path, _ in self.requests if path.startswith(SEARCH)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def page_answer(items, total, headers=None):
    return 200, {"X-Total-Count": str(total), **(headers or {})}, json.dumps({"ok": True, "data": items}).encode()


def repo(repo_id, full_name, *, private=True, visibility="public"):
    owner = full_name.split("/")[0]
    return {
        "id": repo_id,
        "full_name": full_name,
        "private": private,
        "owner": {"login": owner, "visibility": visibility},
    }


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


class Drip:
    def __init__(self, head, drip):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.head, self.drip = head, drip
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.socket.getsockname()[1]}/api/v1"

    def _serve(self):
        try:
            connection, _ = self.socket.accept()
        except OSError:
            return
        with connection:
            try:
                connection.recv(65536)
                connection.sendall(self.head)
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    connection.sendall(self.drip)
                    time.sleep(0.05)
            except OSError:
                return

    def close(self):
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
    options.setdefault("binding_resource", BINDING)
    return check_token(header, api_url=gitea.url, **options)


def refusal(gitea, **options):
    with pytest.raises(TokenCheckRefused) as raised:
        check(gitea, **options)
    assert NEEDLE not in str(raised.value)
    return raised.value


def test_a_token_within_the_required_permissions_passes(gitea):
    gitea.token(["read:repository", "read:issue"])
    assert check(gitea) == TokenCheck(("read:issue", "read:repository"), "agent", 0)
    assert [path for path, _ in gitea.requests] == [
        "/api/v1/token",
        "/api/v1/repos/search?is_private=true&limit=50&page=1",
        "/api/v1/repos/search?limit=50&page=1",
    ]
    assert all(headers["Authorization"] == NEEDLE for _, headers in gitea.requests)


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


@pytest.mark.parametrize("required", [["read:issue"], ["public-only"], ["write:issue", "read:user"], []])
def test_required_permissions_without_repository_access_are_refused(gitea, required):
    with pytest.raises(ValueError, match="must include read:repository or write:repository"):
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
    assert len(gitea.requests) == 3


def test_a_provider_that_does_not_answer_in_time_is_unreachable(listener):
    with pytest.raises(TokenCheckRefused) as raised:
        check_token(
            NEEDLE,
            api_url=f"http://127.0.0.1:{listener.port}/api/v1",
            binding_resource=BINDING,
            required=REQUIRED,
            timeout=0.2,
        )
    assert raised.value.reason == "provider_unreachable"
    assert NEEDLE not in str(raised.value)


def test_a_refused_connection_is_unreachable():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with pytest.raises(TokenCheckRefused) as raised:
        check_token(NEEDLE, api_url=f"http://127.0.0.1:{port}/api/v1", binding_resource=BINDING, required=REQUIRED)
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
        check_token(NEEDLE, api_url=api_url, binding_resource=BINDING, required=REQUIRED)


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


def test_private_reach_inside_the_binding_passes_and_is_counted(gitea):
    gitea.token(["read:repository"])
    gitea.private = [repo(1, "quickstart/payroll"), repo(2, "quickstart/notes")]
    gitea.visible = [*gitea.private, repo(3, "someone/public", private=False)]
    assert check(gitea).private_total == 2


def test_a_private_repository_outside_the_binding_is_refused_and_named(gitea):
    gitea.token(["read:repository"])
    gitea.private = [repo(1, "quickstart/payroll"), repo(2, "finance/ledger")]
    refused = refusal(gitea)
    assert refused.reason == "outside_binding"
    assert "1 non-public repositories outside gitea/repos/quickstart/*: finance/ledger" in str(refused)


def test_reach_outside_the_binding_names_ten_and_the_total(gitea):
    gitea.token(["read:repository"])
    gitea.private = [repo(index, f"other/r{index:02d}") for index in range(12)]
    message = str(refusal(gitea))
    assert "12 non-public repositories" in message
    assert "other/r09" in message and "other/r10" not in message
    assert message.endswith("and 2 more")


@pytest.mark.parametrize("visibility", ["limited", "private"])
def test_a_repository_of_a_non_public_owner_outside_the_binding_is_refused(gitea, visibility):
    gitea.token(["read:repository"])
    gitea.visible = [repo(1, "orglimited/p1", private=False, visibility=visibility)]
    refused = refusal(gitea)
    assert refused.reason == "outside_binding"
    assert "orglimited/p1" in str(refused)


def test_a_repository_of_a_limited_owner_inside_the_binding_passes(gitea):
    gitea.token(["read:repository"])
    gitea.visible = [repo(1, "quickstart/p1", private=False, visibility="limited")]
    assert check(gitea).private_total == 0


def test_a_public_repository_outside_the_binding_is_ignored(gitea):
    gitea.token(["read:repository"])
    gitea.visible = [repo(index, f"someone/p{index}", private=False) for index in range(120)]
    assert check(gitea).private_total == 0
    assert gitea.searches()[-1] == "/api/v1/repos/search?limit=50&page=3"


@pytest.mark.parametrize(
    ("binding", "name", "inside"),
    [
        ("gitea/repos/quickstart/*", "QuickStart/payroll", True),
        ("gitea/repos/QuickStart/Payroll", "quickstart/PAYROLL", True),
        ("gitea/repos/quickstart/payroll", "quickstart/notes", False),
        ("gitea/repos/quickstart/*", "quickstart2/payroll", False),
    ],
)
def test_names_compare_case_folded_against_the_binding_shape(gitea, binding, name, inside):
    gitea.token(["read:repository"])
    gitea.private = [repo(1, name)]
    if inside:
        assert check(gitea, binding_resource=binding).private_total == 1
    else:
        assert refusal(gitea, binding_resource=binding).reason == "outside_binding"


@pytest.mark.parametrize(
    "binding",
    [
        "gitea/repos/quickstart",
        "gitea/repos/*",
        "gitea/repos/*/*",
        "gitea/repos/quickstart/a/b",
        "gitea/repos/quickstart/pay*",
        "gitea/issues/quickstart/*",
        "github/repos/quickstart/*",
        "gitea/repos/quick start/*",
        5,
    ],
)
def test_a_binding_of_another_shape_is_refused_without_a_request(gitea, binding):
    with pytest.raises(ValueError, match="binding resource"):
        check(gitea, binding_resource=binding)
    assert gitea.requests == []


@pytest.mark.parametrize("max_repos", [0, -1, True, "5", 1.5])
def test_an_item_cap_that_is_not_a_positive_int_is_refused(gitea, max_repos):
    with pytest.raises(ValueError, match="max_repos"):
        check(gitea, max_repos=max_repos)
    assert gitea.requests == []


def test_a_search_past_the_item_cap_is_refused_after_one_page(gitea):
    gitea.token(["read:repository"])
    gitea.visible = [repo(index, f"someone/p{index}", private=False) for index in range(3)]
    refused = refusal(gitea, max_repos=2)
    assert refused.reason == "too_many_repos"
    assert gitea.searches() == [
        "/api/v1/repos/search?is_private=true&limit=50&page=1",
        "/api/v1/repos/search?limit=50&page=1",
    ]


def test_a_search_at_the_item_cap_passes(gitea):
    gitea.token(["read:repository"])
    gitea.visible = [repo(index, f"someone/p{index}", private=False) for index in range(3)]
    assert check(gitea, max_repos=3).private_total == 0


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Total-Count": "x"}, {"X-Total-Count": "-1"}, {"X-Total-Count": "\u00b2"}],
)
def test_a_search_without_a_valid_total_is_refused(gitea, headers):
    gitea.token(["read:repository"])
    gitea.routes[SEARCH] = lambda query: (200, headers, b'{"ok": true, "data": []}')
    assert refusal(gitea).reason == "bad_response"


def test_a_search_with_two_totals_is_refused(gitea):
    gitea.token(["read:repository"])

    class TwoTotals(dict):
        def items(self):
            return [("X-Total-Count", "0"), ("X-Total-Count", "0")]

    gitea.routes[SEARCH] = lambda query: (200, TwoTotals(), b'{"ok": true, "data": []}')
    assert refusal(gitea).reason == "bad_response"


def pages(*answers):
    served = iter(answers)
    return lambda query: page_answer(*next(served))


@pytest.mark.parametrize(
    "answers",
    [
        ((list(range(2)), 3), (list(range(1, 3)), 4)),
        ((list(range(2)), 3), ([], 3)),
        ((list(range(2)), 3), (list(range(2)), 3)),
        ((list(range(3)), 2),),
        (([], 1),),
    ],
    ids=["total-changed", "short", "repeated-page", "more-than-total", "empty-with-total"],
)
def test_pages_that_disagree_with_the_total_are_refused(gitea, answers):
    gitea.token(["read:repository"])
    gitea.routes[SEARCH] = pages(*(([repo(i, f"quickstart/r{i}") for i in ids], total) for ids, total in answers))
    assert refusal(gitea).reason == "paging_drift"


def test_a_repository_seen_twice_counts_once(gitea):
    gitea.token(["read:repository"])
    first = [repo(1, "quickstart/a"), repo(2, "quickstart/b")]
    second = [repo(2, "quickstart/b"), repo(3, "quickstart/c")]
    private = pages((first, 3), (second, 3))
    gitea.routes[SEARCH] = lambda query: private(query) if query.get("is_private") else page_answer([], 0)
    assert check(gitea).private_total == 3


def test_repeated_items_count_against_the_item_cap_before_they_are_deduplicated(gitea):
    gitea.token(["read:repository"])
    first = [repo(1, "quickstart/a")] * 3
    second = [repo(2, "quickstart/b")] * 3
    gitea.routes[SEARCH] = pages((first, 2), (second, 2))
    refused = refusal(gitea, max_repos=5)
    assert refused.reason == "too_many_repos"
    assert "more than 5 items" in str(refused)
    assert len(gitea.searches()) == 2


def test_a_repository_that_changes_between_pages_is_refused(gitea):
    gitea.token(["read:repository"])
    first = [repo(1, "quickstart/a"), repo(2, "quickstart/b")]
    second = [repo(2, "finance/b"), repo(3, "quickstart/c")]
    gitea.routes[SEARCH] = pages((first, 3), (second, 3))
    assert refusal(gitea).reason == "paging_drift"


def test_a_public_repository_in_the_private_search_is_refused(gitea):
    gitea.token(["read:repository"])
    gitea.private = [repo(1, "quickstart/a", private=False)]
    assert refusal(gitea).reason == "bad_response"


@pytest.mark.parametrize(
    "item",
    [
        {"id": 1, "full_name": "orglimited/p1", "private": False, "owner": {"login": "orglimited"}},
        {"id": 1, "full_name": "orglimited/p1", "private": False},
        {"id": 1, "full_name": "orglimited/p1", "private": False, "owner": {"visibility": "secret"}},
        {"id": 1, "full_name": "orglimited/p1", "private": False, "owner": {"visibility": None}},
        {"id": True, "full_name": "quickstart/a", "private": False, "owner": {"visibility": "public"}},
        {"id": 1, "full_name": "quickstart", "private": False, "owner": {"visibility": "public"}},
        {"id": 1, "full_name": "token needle/a", "private": False, "owner": {"visibility": "public"}},
        {"id": 1, "full_name": "quickstart/a", "private": "no", "owner": {"visibility": "public"}},
        "quickstart/a",
    ],
)
def test_a_search_item_without_its_reach_fields_is_refused(gitea, item):
    gitea.token(["read:repository"])
    gitea.visible = [item]
    assert refusal(gitea).reason == "bad_response"


@pytest.mark.parametrize("raw", [b"[]", b'{"ok": true}', b'{"data": {}}'])
def test_a_search_answer_without_a_data_list_is_refused(gitea, raw):
    gitea.token(["read:repository"])
    gitea.routes[SEARCH] = lambda query: (200, {"X-Total-Count": "0"}, raw)
    assert refusal(gitea).reason == "bad_response"


def test_a_search_link_header_is_not_followed(gitea):
    target = FakeGitea()
    try:
        gitea.token(["read:repository"])
        link = {"Link": f'<{target.url}/repos/search?page=2>; rel="next"'}
        gitea.routes[SEARCH] = lambda query: page_answer([], 0, link)
        assert check(gitea).private_total == 0
        assert target.requests == []
    finally:
        target.close()


@pytest.mark.parametrize(
    ("status", "reason"), [(403, "token_rejected"), (429, "rate_limited"), (500, "provider_unreachable")]
)
def test_a_search_status_other_than_200_is_refused(gitea, status, reason):
    gitea.token(["read:repository"])
    gitea.routes[SEARCH] = lambda query: (status, {}, b"{}")
    assert refusal(gitea).reason == reason
    assert len(gitea.searches()) == 1


def credential_check(gitea, stdin, *extra, api_url=None):
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    try:
        arguments = ["credential-check", "--provider", "gitea", "--api-url", api_url or gitea.url]
        arguments += ["--binding-resource", BINDING, "--required", "read:issue", "--required", "read:repository"]
        return cli.main([*arguments, *extra])
    finally:
        sys.stdin = original


def test_credential_check_passes_and_prints_the_fingerprint(gitea, capsys):
    gitea.token(["read:repository", "read:issue"])
    gitea.private = [repo(1, "quickstart/a")]
    assert credential_check(gitea, NEEDLE.encode() + b"\n") == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "fingerprint": hashlib.sha256(NEEDLE.encode()).hexdigest(),
        "login": "agent",
        "private_repositories": 1,
        "scopes": ["read:issue", "read:repository"],
    }
    assert NEEDLE not in captured.out + captured.err
    assert {headers["Authorization"] for _, headers in gitea.requests} == {NEEDLE}


@pytest.mark.parametrize(
    ("head", "drip"),
    [
        (b"HTTP/1.1 200 OK\r\nX-Drip: ", b"a"),
        (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[", b" "),
    ],
    ids=["headers", "body"],
)
def test_credential_check_refuses_a_slow_drip_at_its_wall_clock_deadline(capsys, monkeypatch, head, drip):
    monkeypatch.setattr(cli, "DEFAULT_TIMEOUT_SECONDS", 0.5, raising=False)
    server = Drip(head, drip)
    try:
        started = time.monotonic()
        assert credential_check(None, NEEDLE.encode() + b"\n", api_url=server.url) == cli.EXIT_REFUSED
        elapsed = time.monotonic() - started
    finally:
        server.close()
    assert "credential-check refused: deadline_exceeded" in capsys.readouterr().err
    assert elapsed < 2


def test_credential_check_refuses_an_alarm_that_fires_as_it_is_armed(capsys, monkeypatch):
    setitimer = cli.signal.setitimer

    def fire_on_arm(which, seconds):
        setitimer(which, 0)
        if seconds:
            cli.signal.getsignal(cli.signal.SIGALRM)(cli.signal.SIGALRM, None)

    monkeypatch.setattr(cli.signal, "setitimer", fire_on_arm)
    assert credential_check(None, NEEDLE.encode() + b"\n", api_url="http://127.0.0.1:9/api/v1") == cli.EXIT_REFUSED
    assert "credential-check refused: deadline_exceeded" in capsys.readouterr().err


def test_credential_check_lets_the_check_report_its_own_refusal_just_past_its_deadline(capsys, monkeypatch):
    def slow_refusal(header, **options):
        time.sleep(options["timeout"] * 2)
        raise TokenCheckRefused("provider_unreachable", "the check gave up on its own")

    monkeypatch.setattr(cli, "DEFAULT_TIMEOUT_SECONDS", 0.2, raising=False)
    monkeypatch.setattr(cli, "check_token", slow_refusal)
    assert credential_check(None, NEEDLE.encode() + b"\n", api_url="http://127.0.0.1:9/api/v1") == cli.EXIT_REFUSED
    err = capsys.readouterr().err
    assert "credential-check refused: provider_unreachable: the check gave up on its own" in err
    assert "deadline_exceeded" not in err


def test_credential_check_fingerprint_matches_put_credential(gitea, capsys):
    gitea.token(["read:repository"])
    assert credential_check(gitea, NEEDLE.encode() + b"\r\n") == 0
    fingerprint = json.loads(capsys.readouterr().out)["fingerprint"]
    assert fingerprint == cli._credential_fingerprint(NEEDLE.encode())


@pytest.mark.parametrize("stdin", [b"", b"\n", b"\r\n"])
def test_credential_check_with_an_empty_stdin_exits_2(gitea, capsys, stdin):
    assert credential_check(gitea, stdin) == cli.EXIT_NO_CREDENTIAL == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "the credential on stdin is empty" in captured.err
    assert gitea.requests == []


def test_credential_check_refusal_exits_1_with_the_reason(gitea, capsys):
    gitea.token(["read:repository", "write:admin"])
    assert credential_check(gitea, NEEDLE.encode() + b"\n") == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "credential-check refused: broader_scopes" in captured.err and "write:admin" in captured.err
    assert NEEDLE not in captured.err


def test_credential_check_refuses_reach_outside_the_binding(gitea, capsys):
    gitea.token(["read:repository"])
    gitea.private = [repo(1, "other/secret")]
    assert credential_check(gitea, NEEDLE.encode() + b"\n") == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert captured.out == "" and "outside_binding" in captured.err and "other/secret" in captured.err


def test_credential_check_refuses_past_the_item_cap(gitea, capsys):
    gitea.token(["read:repository"])
    gitea.private = [repo(1, "quickstart/a"), repo(2, "quickstart/b")]
    assert credential_check(gitea, NEEDLE.encode() + b"\n", "--max-repos", "1") == cli.EXIT_REFUSED
    assert "too_many_repos" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("stdin", "message"),
    [
        (NEEDLE.encode() + b"\nsecond line\n", "printable ASCII"),
        ("token n\u00e9edle".encode() + b"\n", "not ASCII"),
        (b"x" * (cli.MAX_SECRET_BYTES + 1), "larger than"),
    ],
)
def test_credential_check_refuses_a_stdin_that_is_not_one_header_line(gitea, capsys, stdin, message):
    assert credential_check(gitea, stdin) == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert captured.out == "" and message in captured.err and "needle" not in captured.err
    assert gitea.requests == []


def test_credential_check_config_refuses_required_without_repository(gitea, capsys):
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(NEEDLE.encode() + b"\n"))
    try:
        arguments = ["credential-check", "--provider", "gitea", "--api-url", gitea.url]
        code = cli.main([*arguments, "--binding-resource", BINDING, "--required", "read:issue"])
    finally:
        sys.stdin = original
    assert code == cli.EXIT_REFUSED
    assert "must include read:repository" in capsys.readouterr().err
    assert gitea.requests == []


@pytest.mark.parametrize(
    ("api_url", "extra", "message"),
    [
        ("http://gitea.example.com/api/v1", (), "must use https"),
        ("ftp://127.0.0.1/api/v1", (), ""),
        (None, ("--ca-file", "/nonexistent-ca.pem"), "needs an https"),
    ],
)
def test_credential_check_config_follows_the_transport_rules(gitea, capsys, api_url, extra, message):
    assert credential_check(gitea, NEEDLE.encode() + b"\n", *extra, api_url=api_url) == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert captured.out == "" and "credential-check refused" in captured.err and message in captured.err
    assert gitea.requests == []


def test_credential_check_refuses_a_missing_ca_file(capsys):
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(NEEDLE.encode() + b"\n"))
    try:
        arguments = ["credential-check", "--provider", "gitea", "--api-url", "https://gitea.example.com/api/v1"]
        arguments += ["--binding-resource", BINDING, "--required", "read:repository"]
        code = cli.main([*arguments, "--ca-file", "/nonexistent-ca.pem"])
    finally:
        sys.stdin = original
    assert code == cli.EXIT_REFUSED
    assert "credential-check refused" in capsys.readouterr().err


def test_credential_check_refuses_a_provider_other_than_gitea(gitea, capsys):
    with pytest.raises(SystemExit) as raised:
        credential_check(gitea, NEEDLE.encode(), "--provider", "github")
    assert raised.value.code == 2
    assert "argument --provider: invalid choice: 'github'" in capsys.readouterr().err
    assert gitea.requests == []
