import json
import os

import pytest
from test_quickstart_stack import b


def test_a_probe_that_returns_ok_is_allowed():
    assert b.probe_outcome("read issues", 200) == "allowed"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_probe_that_is_denied_is_refused_with_its_status(status):
    assert b.probe_outcome("create a repository", status) == f"refused ({status})"


@pytest.mark.parametrize("status", [201, 400, 422, 500])
def test_a_probe_that_is_neither_allowed_nor_refused_fails_bootstrap(status):
    with pytest.raises(b.BootstrapError, match=f"'create a repository' returned {status}"):
        b.probe_outcome("create a repository", status)


def test_an_old_docket_config_fails_bootstrap_with_the_reset_hint(tmp_path, monkeypatch):
    config = tmp_path / "docket" / "config.json"
    config.parent.mkdir(mode=0o700)
    config.write_text(json.dumps({"snapshot_every": 10_000}))
    os.chmod(config, 0o600)
    monkeypatch.setitem(b.DIRS, "docket", config.parent)
    monkeypatch.setattr(b, "read_pin", lambda path: None)
    monkeypatch.setattr(b, "WRITERS", ())
    with pytest.raises(b.BootstrapError, match="missing .*free_space_floor.*run docker compose down --volumes"):
        b.init_docket()


GITEA_UPSTREAM = b.QUICKSTART_UPSTREAMS / "gitea.json"


def write_upstream(tmp_path, routes=None, **changes):
    document = {**json.loads(GITEA_UPSTREAM.read_text()), **changes}
    routes_document = (
        routes if routes is not None else json.loads((b.QUICKSTART_UPSTREAMS / "gitea-routes.json").read_text())
    )
    (tmp_path / document.get("routes_file", "routes.json")).write_text(json.dumps(routes_document))
    path = tmp_path / "upstream.json"
    path.write_text(json.dumps(document))
    return path


def test_the_gitea_upstream_loads_with_one_unit_of_cost_per_routed_tool():
    upstream = b.load_upstream(GITEA_UPSTREAM)
    routes = json.loads((b.QUICKSTART_UPSTREAMS / "gitea-routes.json").read_text())["routes"]
    assert (upstream.service, upstream.credential_id, upstream.target) == ("gitea", "gitea-token", "gitea")
    assert list(upstream.routes) == routes
    assert upstream.costs == {"version": 1, "tools": {route["tool"]: 1 for route in routes}}


def test_the_gateway_targets_the_gitea_upstream_url():
    gateway = json.loads((b.QUICKSTART_UPSTREAMS.parent / "gateway.json").read_text())
    assert [target["mcp"]["host"] for target in gateway["mcp"]["targets"]] == [b.load_upstream(GITEA_UPSTREAM).url]


@pytest.mark.parametrize(
    "url", ["http://gitea-mcp:8080/mcp", "https://mcp.example.com/mcp", "https://mcp.example.com:8443/mcp"]
)
def test_an_upstream_url_is_a_compose_service_with_a_port_or_https(tmp_path, url):
    assert b.load_upstream(write_upstream(tmp_path, url=url)).url == url


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"version": 2}, "version must be 1"),
        ({"version": True}, "version must be 1"),
        ({"extra": "x"}, "exactly the fields"),
        ({"service": ""}, "service must be a non-empty ASCII printable string"),
        ({"credential_id": "gitea token"}, "credential_id must be a non-empty ASCII printable string"),
        ({"target": 7}, "target must be a non-empty ASCII printable string"),
        ({"service": "k8s"}, r"k8s\.\* tools are routed only from their catalog"),
        ({"url": "http://mcp.example.com:8080/mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "http://gitea-mcp/mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "ftp://gitea-mcp:21/mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "https:///mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "https://user:secret@mcp.example.com/mcp"}, "no credentials, query or fragment"),
        ({"url": "https://mcp.example.com/mcp?key=1"}, "no credentials, query or fragment"),
        ({"url": "https://mcp.example.com:99999/mcp"}, "url Port out of range"),
        ({"credential_header": "Bad:Header"}, "HTTP field name token"),
        ({"binding_resource": "gitea/*/issues"}, "final /\\* segment"),
        ({"routes_file": "../routes.json"}, "a file beside the upstream config"),
        ({"routes_file": ".."}, "a file beside the upstream config"),
    ],
)
def test_an_invalid_upstream_fails_bootstrap(tmp_path, changes, message):
    path = write_upstream(tmp_path, **{key: value for key, value in changes.items() if key != "routes_file"})
    if "routes_file" in changes:
        path.write_text(json.dumps({**json.loads(path.read_text()), "routes_file": changes["routes_file"]}))
    with pytest.raises(b.BootstrapError, match=message):
        b.load_upstream(path)


def test_an_upstream_missing_a_field_fails_bootstrap(tmp_path):
    path = write_upstream(tmp_path)
    document = json.loads(path.read_text())
    del document["target"]
    path.write_text(json.dumps(document))
    with pytest.raises(b.BootstrapError, match="exactly the fields"):
        b.load_upstream(path)


@pytest.mark.parametrize(
    "raw, message",
    [
        ('{"version": 1, "version": 1}', "not strict JSON: duplicate key 'version'"),
        ('{"version": NaN}', "not strict JSON"),
        (b"\xff", "not strict JSON"),
        (" " * (64 * 1024 + 1), "larger than 65536 bytes"),
    ],
)
def test_an_upstream_that_is_not_bounded_strict_json_fails_bootstrap(tmp_path, raw, message):
    path = tmp_path / "upstream.json"
    path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
    with pytest.raises(b.BootstrapError, match=message):
        b.load_upstream(path)


def test_a_symlinked_or_missing_upstream_fails_bootstrap(tmp_path):
    (tmp_path / "link.json").symlink_to(write_upstream(tmp_path))
    with pytest.raises(b.BootstrapError, match="cannot open .*link.json"):
        b.load_upstream(tmp_path / "link.json")
    with pytest.raises(b.BootstrapError, match="cannot open .*absent.json"):
        b.load_upstream(tmp_path / "absent.json")


def test_a_missing_routes_file_fails_bootstrap(tmp_path):
    path = write_upstream(tmp_path)
    (tmp_path / "gitea-routes.json").unlink()
    with pytest.raises(b.BootstrapError, match="cannot open .*gitea-routes.json"):
        b.load_upstream(path)


ROUTE = {"service": "gitea", "name": "list_issues", "tool": "gitea.issues.list", "resource": "gitea/repos/x/issues"}


@pytest.mark.parametrize(
    "routes, message",
    [
        ({"routes": []}, "non-empty routes list and nothing else"),
        ({"routes": [ROUTE], "catalogs": []}, "non-empty routes list and nothing else"),
        ([ROUTE], "non-empty routes list and nothing else"),
        ({"routes": [{**ROUTE, "resource": ""}]}, "route 0 \\('list_issues'\\)"),
        ({"routes": [{**ROUTE, "service": "other"}]}, "every route must be on service 'gitea'"),
    ],
)
def test_invalid_upstream_routes_fail_bootstrap(tmp_path, routes, message):
    with pytest.raises(b.BootstrapError, match=message):
        b.load_upstream(write_upstream(tmp_path, routes=routes))
