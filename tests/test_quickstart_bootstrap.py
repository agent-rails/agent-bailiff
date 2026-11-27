import datetime
import hashlib
import http.server
import ipaddress
import json
import os
import re
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from agent_warrant.identity import encode_public_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID
from test_gitea_token_check import NEEDLE, Drip
from test_quickstart_stack import b

from agent_bailiff import cli
from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.gitea.token_check import DEFAULT_MAX_REPOS, DEFAULT_TIMEOUT_SECONDS
from agent_bailiff.custodian.backend import LocalBackend
from agent_bailiff.custodian.store import CredentialStore
from agent_bailiff.docket.client import DocketError
from agent_bailiff.keys import load_signing_key


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


class FakeDocket:
    def __init__(self, error=None):
        self.error = error
        self.clients = []
        self.grants = []
        self.files_at_append = []

    def __call__(self, socket_path, writer, kid, key, *, sink_uid, state_dir):
        self.clients.append({"writer": writer, "sink_uid": sink_uid, "state_dir": state_dir, "closed": False})
        return self

    def append(self, grant):
        self.files_at_append.append((b.TASK_FILE.exists(), b.LOAD_FILE.exists()))
        if self.error is not None:
            raise self.error
        self.grants.append(grant)

    def close(self):
        self.clients[-1]["closed"] = True


@pytest.fixture
def issuer(tmp_path, monkeypatch):
    for name in ("issuer", "issuer-docket", "pins", "tasks", "agent-public"):
        (tmp_path / name).mkdir(mode=0o700)
    monkeypatch.setattr(b, "PINS", tmp_path / "pins")
    (tmp_path / "pins" / "issuer").mkdir(mode=0o755)
    monkeypatch.setattr(b, "ISSUER_KEY", tmp_path / "issuer" / "issuer.key")
    monkeypatch.setattr(b, "ISSUER_DOCKET_KEY", tmp_path / "issuer-docket" / "signing.key")
    monkeypatch.setattr(b, "ISSUER_DOCKET_STATE", tmp_path / "issuer-docket" / "docket-state")
    monkeypatch.setattr(b, "GRANT_PIN", tmp_path / "pins" / "issuer" / "issuer-docket.json")
    monkeypatch.setattr(b, "TASK_FILE", tmp_path / "tasks" / "task.json")
    monkeypatch.setattr(b, "LOAD_FILE", tmp_path / "tasks" / "load.json")
    monkeypatch.setattr(b, "AGENT_PUBLIC_KEY", tmp_path / "agent-public" / "agent.pub")
    b.AGENT_PUBLIC_KEY.write_text(encode_public_key(Ed25519PrivateKey.generate().public_key()))
    assert b.init_issuer() == "created"
    return tmp_path


def test_init_issuer_creates_a_docket_writer_key_apart_from_the_issuer_key_and_keeps_it(issuer):
    issuer_key = load_signing_key(b.ISSUER_KEY).public_key()
    docket_key = load_signing_key(b.ISSUER_DOCKET_KEY).public_key()
    assert issuer_key != docket_key
    assert b.read_pin(b.GRANT_PIN) == b.record_of(b.ISSUER_DOCKET_KEY, b.NAMES["issuer-docket"])
    assert b.read_pin(b.pin_path("issuer")) == b.record_of(b.ISSUER_KEY, b.NAMES["issuer"])
    assert b.ISSUER_DOCKET_STATE.stat().st_mode & 0o777 == 0o700
    assert b.init_issuer() == "kept"


def test_init_issuer_refuses_a_grant_pin_without_its_key(issuer):
    b.ISSUER_DOCKET_KEY.unlink()
    with pytest.raises(b.BootstrapError, match="exists without .*signing.key"):
        b.init_issuer()


def test_issue_records_the_grant_before_it_writes_the_task_file(issuer, monkeypatch):
    docket = FakeDocket()
    monkeypatch.setattr(b, "DocketClient", docket)
    task_id = b.issue_task()
    document = json.loads(b.TASK_FILE.read_text())
    assert document["task_id"] == task_id
    assert docket.files_at_append == [(False, False)]
    assert [grant.root_token for grant in docket.grants] == [document["task_root"]]
    client = {"writer": b.NAMES["issuer-docket"], "sink_uid": b.DOCKET_UID, "state_dir": b.ISSUER_DOCKET_STATE}
    assert docket.clients == [client | {"closed": True}]


def test_a_refused_grant_writes_no_task_file(issuer, monkeypatch, capsys):
    docket = FakeDocket(DocketError("unknown_writer", "writer is not pinned"))
    monkeypatch.setattr(b, "DocketClient", docket)
    assert b.main(["issue"]) == 1
    assert "bootstrap issue refused: unknown_writer" in capsys.readouterr().err
    assert not b.TASK_FILE.exists()
    assert docket.clients[-1]["closed"] is True


def test_issue_load_records_every_grant_through_one_client_before_the_load_file(issuer, monkeypatch):
    docket = FakeDocket()
    monkeypatch.setattr(b, "DocketClient", docket)
    b.issue_load_tasks()
    tasks = json.loads(b.LOAD_FILE.read_text())["tasks"]
    assert len(docket.clients) == 1 and docket.clients[0]["closed"]
    assert docket.files_at_append == [(False, False)] * b.LOAD_TASKS
    assert [grant.root_token for grant in docket.grants] == [task["task_root"] for task in tasks]
    assert len({grant.grant_id for grant in docket.grants}) == b.LOAD_TASKS


@pytest.fixture
def reader(issuer, monkeypatch):
    (issuer / "reader").mkdir(mode=0o700)
    monkeypatch.setattr(b, "READER_ISSUERS", issuer / "reader" / "issuers.json")
    return issuer


def test_init_reader_writes_an_owned_0600_copy_of_the_issuers(reader):
    assert b.init_reader() == "created"
    info = b.READER_ISSUERS.stat()
    assert (info.st_uid, info.st_mode & 0o777) == (os.geteuid(), 0o600)
    assert json.loads(b.READER_ISSUERS.read_text()) == b.issuers()
    assert b.load_issuers(b.READER_ISSUERS).resolver.resolve(b.NAMES["issuer"])
    assert b.init_reader() == "kept"


@pytest.mark.parametrize("existing", [False, True])
def test_init_reader_replaces_a_staged_file_left_by_a_crash(reader, existing):
    if existing:
        b.init_reader()
        b.READER_ISSUERS.write_text(json.dumps({"stale": {}}))
    b.READER_ISSUERS.with_name(".issuers.json.new").write_text("partial")
    assert b.init_reader() == ("updated" if existing else "created")
    assert json.loads(b.READER_ISSUERS.read_text()) == b.issuers()
    assert not b.READER_ISSUERS.with_name(".issuers.json.new").exists()


def test_init_reader_rewrites_a_copy_that_no_longer_matches(reader):
    b.init_reader()
    b.READER_ISSUERS.write_text(json.dumps({"stale": {}}))
    assert b.init_reader() == "updated"
    assert json.loads(b.READER_ISSUERS.read_text()) == b.issuers()
    assert b.READER_ISSUERS.stat().st_mode & 0o777 == 0o600


GITEA_UPSTREAM = b.QUICKSTART_UPSTREAMS / "gitea.json"


def write_upstream(tmp_path, routes=None, **changes):
    document = json.loads(GITEA_UPSTREAM.read_text())
    if "url" in changes:
        del document["ca_file"]
    document.update(changes)
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


@pytest.mark.parametrize("name", ["gitea.json", "stub.json"])
def test_the_gateway_config_targets_only_the_upstream_url(name):
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / name)
    template = json.loads(b.GATEWAY_TEMPLATE.read_text())
    document = b.gateway_document(upstream)
    policies = {"policies": {"backendTLS": {"root": str(b.GATEWAY_CA)}}}
    assert document["mcp"]["targets"] == [{"name": upstream.target, "mcp": {"host": upstream.url}, **policies}]
    assert {**document, "mcp": {**document["mcp"], "targets": []}} == template


def test_the_stub_upstream_is_served_over_https_with_the_install_ca():
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json")
    assert upstream.url.startswith("https://stub-upstream:")
    assert upstream.ca_file == b.INSTALL_CA == b.STATE / "certs" / "public" / "current" / "ca.pem"


def test_gitea_mcp_is_reached_through_its_tls_sidecar_with_the_install_ca():
    upstream = b.load_upstream(GITEA_UPSTREAM)
    assert upstream.url == "https://gitea-mcp-tls:8443/mcp"
    assert upstream.ca_file == b.INSTALL_CA


@pytest.mark.parametrize("name", ["gitea.json", "stub.json"])
def test_the_quickstart_gateway_config_passes_check_config(name):
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / name)
    expected = GatewayExpectations(
        decide_socket=b.SOCKETS["decide"],
        custodian_socket=b.SOCKETS["custodian"],
        redactor_socket=b.SOCKETS["redactor"],
        services=frozenset({upstream.target}),
        credential_headers=frozenset({upstream.credential_header}),
    )
    assert validate_gateway_config(b.gateway_document(upstream), expected) == ()


def test_a_gateway_template_with_a_target_is_refused(tmp_path, monkeypatch):
    template = json.loads(b.GATEWAY_TEMPLATE.read_text())
    template["mcp"]["targets"] = [{"name": "other", "mcp": {"host": "http://other:8080/mcp"}}]
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(template))
    monkeypatch.setattr(b, "GATEWAY_TEMPLATE", path)
    with pytest.raises(b.BootstrapError, match="must leave mcp.targets empty"):
        b.gateway_document(b.load_upstream(GITEA_UPSTREAM))


def test_init_gateway_creates_keeps_and_updates_the_config(tmp_path, monkeypatch):
    (tmp_path / "install.pem").write_bytes(pem(issue_certificate("quickstart install ca")[0]))
    monkeypatch.setattr(b, "INSTALL_CA", tmp_path / "install.pem")
    monkeypatch.setattr(b, "GATEWAY_CA", tmp_path / "ca.pem")
    monkeypatch.setattr(b, "GATEWAY_CONFIG", tmp_path / "gateway.json")
    monkeypatch.setattr(b, "UPSTREAM_FILE", b.QUICKSTART_UPSTREAMS / "stub.json")
    assert b.init_gateway() == "created"
    assert (tmp_path / "gateway.json").stat().st_mode & 0o777 == 0o644
    assert b.init_gateway() == "kept"
    monkeypatch.setattr(b, "UPSTREAM_FILE", GITEA_UPSTREAM)
    assert b.init_gateway() == "updated"
    written = json.loads((tmp_path / "gateway.json").read_text())
    assert written["mcp"]["targets"][0]["mcp"]["host"] == "https://gitea-mcp-tls:8443/mcp"


@pytest.mark.parametrize(
    "url", ["https://mcp-server/mcp", "https://mcp.example.com/mcp", "https://mcp.example.com:8443/mcp"]
)
def test_an_upstream_url_is_https(tmp_path, url):
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
        ({"url": "http://mcp-server:8080/mcp"}, "url must be https://<host>"),
        ({"url": "http://mcp.example.com:8080/mcp"}, "url must be https://<host>"),
        ({"url": "http://mcp-server/mcp"}, "url must be https://<host>"),
        ({"url": "http://167772165:8080/mcp"}, "url must be https://<host>"),
        ({"url": "http://0xa000005:8080/mcp"}, "url must be https://<host>"),
        ({"url": "ftp://mcp-server:21/mcp"}, "url must be https://<host>"),
        ({"url": "https:///mcp"}, "url must be https://<host>"),
        ({"url": "https://user:secret@mcp.example.com/mcp"}, "no credentials, query or fragment"),
        ({"url": "https://mcp.example.com/mcp?key=1"}, "no credentials, query or fragment"),
        ({"url": "https://mcp.example.com:99999/mcp"}, "url Port out of range"),
        ({"url": "http://localhost:15000/"}, "must not name the stack's own localhost"),
        ({"url": "http://gateway:8080/mcp"}, "must not name the stack's own gateway"),
        ({"url": "http://custodian:8080/mcp"}, "must not name the stack's own custodian"),
        ({"url": "http://gitea-mcp:8080/mcp"}, "must not name the stack's own gitea-mcp"),
        ({"url": "https://gitea:3000/mcp"}, "must not name the stack's own gitea"),
        ({"url": "http://gitea-mcp-spike:8080/mcp"}, "must not name the stack's own gitea-mcp-spike"),
        ({"url": "https://LocalHost./mcp"}, "must not name the stack's own localhost"),
        ({"url": "https://127.0.0.1/mcp"}, "loopback, link-local, unspecified or multicast"),
        ({"url": "https://[::1]:8443/mcp"}, "loopback, link-local, unspecified or multicast"),
        ({"url": "https://[::ffff:127.0.0.1]/mcp"}, "loopback, link-local, unspecified or multicast"),
        ({"url": "https://169.254.169.254/x"}, "loopback, link-local, unspecified or multicast"),
        ({"url": "https://[fe80::1]/mcp"}, "loopback, link-local, unspecified or multicast"),
        ({"url": "https://0.0.0.0/mcp"}, "loopback, link-local, unspecified or multicast"),
        ({"url": "https://224.0.0.1/mcp"}, "loopback, link-local, unspecified or multicast"),
        ({"credential_header": "Bad:Header"}, "HTTP field name token"),
        ({"binding_resource": "gitea/*/issues"}, "final /\\* segment"),
        ({"routes_file": "../routes.json"}, "a file beside the upstream config"),
        ({"routes_file": ".."}, "a file beside the upstream config"),
        ({"provider": "github"}, "provider must be one of gitea"),
        ({"provider": ""}, "provider must be a non-empty ASCII printable string"),
        ({"provider_api_url": "http://gitea.example.com/api/v1"}, "provider_api_url must be http://gitea/<path>"),
        ({"provider_api_url": "http://gitea:3000/api/v1"}, "provider_api_url must be http://gitea/<path>"),
        ({"provider_api_url": "https://gitea/api/v1"}, "provider_api_url must be http://gitea/<path>"),
        ({"provider_api_url": "http://127.0.0.1/api/v1"}, "provider_api_url must be http://gitea/<path>"),
        ({"provider_api_url": "http://user:secret@gitea/api/v1"}, "provider_api_url must be http://gitea/<path>"),
        ({"provider_api_url": "http://gitea/api/v1?x=1"}, "provider_api_url must be http://gitea/<path>"),
        ({"provider_api_url": "http://gitea:99999/api/v1"}, "provider_api_url Port out of range"),
        ({"required_permissions": "read:repository"}, "required_permissions must be a list of scope names"),
        ({"required_permissions": ["read:repository", 7]}, "required_permissions must be a list of scope names"),
        ({"required_permissions": ["read:issue"]}, "must include read:repository or write:repository"),
        ({"required_permissions": ["admin"]}, "is not read:<category>, write:<category> or public-only"),
    ],
)
def test_an_invalid_upstream_fails_bootstrap(tmp_path, changes, message):
    path = write_upstream(tmp_path, **{key: value for key, value in changes.items() if key != "routes_file"})
    if "routes_file" in changes:
        path.write_text(json.dumps({**json.loads(path.read_text()), "routes_file": changes["routes_file"]}))
    with pytest.raises(b.BootstrapError, match=message):
        b.load_upstream(path)


@pytest.mark.parametrize("field", ["target", "provider", "provider_api_url", "required_permissions"])
def test_an_upstream_missing_a_field_fails_bootstrap(tmp_path, field):
    path = write_upstream(tmp_path)
    document = json.loads(path.read_text())
    del document[field]
    path.write_text(json.dumps(document))
    with pytest.raises(b.BootstrapError, match="exactly the fields .*optionally all of provider"):
        b.load_upstream(path)


def test_the_gitea_upstream_names_the_provider_check_and_the_stub_names_none():
    check = b.load_upstream(GITEA_UPSTREAM).provider_check
    assert check == b.ProviderCheck(
        "gitea", "http://gitea/api/v1", ("read:issue", "read:repository"), DEFAULT_MAX_REPOS, DEFAULT_TIMEOUT_SECONDS
    )
    assert (DEFAULT_MAX_REPOS, DEFAULT_TIMEOUT_SECONDS) == (1000, 10.0)
    assert b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json").provider_check is None


@pytest.mark.parametrize(
    "changes", [{"max_repos": 1}, {"max_repos": 10_000, "check_timeout_seconds": 1}, {"check_timeout_seconds": 60}]
)
def test_an_upstream_sets_the_credential_check_bounds(tmp_path, changes):
    check = b.load_upstream(write_upstream(tmp_path, **changes)).provider_check
    expected = {"max_repos": DEFAULT_MAX_REPOS, "check_timeout_seconds": DEFAULT_TIMEOUT_SECONDS} | changes
    assert (check.max_repos, check.timeout_seconds) == (expected["max_repos"], expected["check_timeout_seconds"])


@pytest.mark.parametrize(
    "field, cap", [("max_repos", b.MAX_CHECK_REPOS), ("check_timeout_seconds", b.MAX_CHECK_TIMEOUT_SECONDS)]
)
@pytest.mark.parametrize("value", [0, -1, True, False, "5", 1.5, 10.0, None, [5], "above"])
def test_a_credential_check_bound_that_is_not_a_bounded_positive_int_fails_bootstrap(tmp_path, field, cap, value):
    path = write_upstream(tmp_path, **{field: cap + 1 if value == "above" else value})
    with pytest.raises(b.BootstrapError, match=f"{field} must be an integer from 1 to {cap}$"):
        b.load_upstream(path)


def test_the_credential_check_bounds_are_capped_at_ten_thousand_repositories_and_a_minute():
    assert (b.MAX_CHECK_REPOS, b.MAX_CHECK_TIMEOUT_SECONDS) == (10_000, 60)
    assert b.GITEA_HEALTH_SECONDS + 2 * (b.MAX_CHECK_TIMEOUT_SECONDS + cli.CREDENTIAL_CHECK_GRACE_SECONDS) < (
        b.HANDOFF_SECONDS
    )


@pytest.mark.parametrize("field", ["max_repos", "check_timeout_seconds"])
def test_a_credential_check_bound_without_a_provider_fails_bootstrap(tmp_path, field):
    path = write_upstream(tmp_path, **{field: 5})
    document = json.loads(path.read_text())
    for name in ("provider", "provider_api_url", "required_permissions"):
        del document[name]
    path.write_text(json.dumps(document))
    with pytest.raises(b.BootstrapError, match="exactly the fields .*optionally all of provider"):
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


KEY_USAGES = (
    "digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
    "key_cert_sign", "crl_sign", "encipher_only", "decipher_only",
)  # fmt: skip


def issue_certificate(common_name, issuer=None, dns_name=None, ip_address=None, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signer_name, signer_key = (issuer[0].subject, issuer[1]) if issuer else (subject, key)
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2 if expired else 0, minutes=5))
        .not_valid_after(now + datetime.timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()), critical=False)
    )
    if issuer is None:
        usage = {name: False for name in KEY_USAGES}
        builder = builder.add_extension(
            x509.KeyUsage(**{**usage, "key_cert_sign": True, "crl_sign": True}), critical=True
        )
    names = [x509.DNSName(dns_name)] if dns_name else []
    if ip_address:
        names.append(x509.IPAddress(ipaddress.ip_address(ip_address)))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(signer_key, hashes.SHA256()), key


def pem(certificate):
    return certificate.public_bytes(Encoding.PEM)


def private_pem(key):
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


HTTPS_URL = "https://mcp.example.com/mcp"


def write_ca(tmp_path, data, url=HTTPS_URL):
    (tmp_path / "ca.pem").write_bytes(data)
    return write_upstream(tmp_path, url=url, ca_file="ca.pem")


def test_a_ca_file_is_kept_as_its_certificates_only(tmp_path):
    ca, key = issue_certificate("quickstart test ca")
    upstream = b.load_upstream(write_ca(tmp_path, private_pem(key) + pem(ca)))
    assert upstream.ca_file == tmp_path / "ca.pem"
    assert b.load_upstream_ca(upstream.ca_file) == pem(ca)


def test_a_ca_file_points_the_gateway_target_at_the_copied_ca(tmp_path):
    ca, _ = issue_certificate("quickstart test ca")
    upstream = b.load_upstream(write_ca(tmp_path, pem(ca)))
    assert b.gateway_document(upstream)["mcp"]["targets"] == [
        {"name": upstream.target, "mcp": {"host": HTTPS_URL}, "policies": {"backendTLS": {"root": str(b.GATEWAY_CA)}}}
    ]


@pytest.mark.parametrize(
    "data, url, message",
    [
        (b"not a certificate", HTTPS_URL, "must hold PEM certificates"),
        (b"", HTTPS_URL, "must hold PEM certificates"),
        (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", HTTPS_URL, "must hold PEM certificates"),
        (b"x" * (64 * 1024 + 1), HTTPS_URL, "larger than 65536 bytes"),
        (None, "http://stub-upstream:8080/mcp", "url must be https://<host>"),
    ],
)
def test_an_invalid_ca_file_fails_bootstrap(tmp_path, data, url, message):
    if data is None:
        data = pem(issue_certificate("quickstart test ca")[0])
    with pytest.raises(b.BootstrapError, match=message):
        b.load_upstream(write_ca(tmp_path, data, url))


@pytest.mark.parametrize("name", ["../ca.pem", "..", "link.pem", "absent.pem"])
def test_a_ca_file_outside_the_upstream_directory_or_symlinked_fails_bootstrap(tmp_path, name):
    (tmp_path / "ca.pem").write_bytes(pem(issue_certificate("quickstart test ca")[0]))
    (tmp_path / "link.pem").symlink_to(tmp_path / "ca.pem")
    with pytest.raises(b.BootstrapError, match="a file beside the upstream config|cannot open"):
        b.load_upstream(write_upstream(tmp_path, url=HTTPS_URL, ca_file=name))


def test_init_gateway_writes_keeps_and_removes_the_ca(tmp_path, monkeypatch):
    upstreams = tmp_path / "upstreams"
    upstreams.mkdir()
    ca, _ = issue_certificate("quickstart test ca")
    monkeypatch.setattr(b, "GATEWAY_CONFIG", tmp_path / "gateway.json")
    monkeypatch.setattr(b, "GATEWAY_CA", tmp_path / "ca.pem")
    monkeypatch.setattr(b, "UPSTREAM_FILE", write_ca(upstreams, pem(ca)))
    assert b.init_gateway() == "created"
    assert (tmp_path / "ca.pem").read_bytes() == pem(ca)
    assert (tmp_path / "ca.pem").stat().st_mode & 0o777 == 0o644
    assert b.init_gateway() == "kept"
    other, _ = issue_certificate("another test ca")
    (upstreams / "ca.pem").write_bytes(pem(other))
    assert b.init_gateway() == "updated"
    assert (tmp_path / "ca.pem").read_bytes() == pem(other)
    public = tmp_path / "public"
    public.mkdir()
    monkeypatch.setattr(b, "UPSTREAM_FILE", write_upstream(public, url="https://mcp.example.com/mcp"))
    assert b.init_gateway() == "updated"
    assert not (tmp_path / "ca.pem").exists()
    assert "policies" not in json.loads((tmp_path / "gateway.json").read_text())["mcp"]["targets"][0]


def test_ca_file_install_is_read_only_when_the_gateway_config_is_written(tmp_path, monkeypatch):
    install, _ = issue_certificate("quickstart install ca")
    monkeypatch.setattr(b, "INSTALL_CA", tmp_path / "absent.pem")
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json")
    assert upstream.ca_file == tmp_path / "absent.pem"
    monkeypatch.setattr(b, "GATEWAY_CONFIG", tmp_path / "gateway.json")
    monkeypatch.setattr(b, "GATEWAY_CA", tmp_path / "ca.pem")
    monkeypatch.setattr(b, "UPSTREAM_FILE", b.QUICKSTART_UPSTREAMS / "stub.json")
    with pytest.raises(b.BootstrapError, match="cannot open .*absent.pem"):
        b.init_gateway()
    assert not (tmp_path / "gateway.json").exists()
    monkeypatch.setattr(b, "INSTALL_CA", tmp_path / "install.pem")
    (tmp_path / "install.pem").write_bytes(pem(install))
    assert b.init_gateway() == "created"
    assert (tmp_path / "ca.pem").read_bytes() == pem(install)
    reissued, _ = issue_certificate("quickstart reissued ca")
    (tmp_path / "install.pem").write_bytes(pem(reissued))
    assert b.init_gateway() == "updated"
    assert (tmp_path / "ca.pem").read_bytes() == pem(reissued)


@pytest.mark.parametrize("host", sorted(b.UPSTREAM_HOSTS) + ["STUB-UPSTREAM.", "GITEA-MCP-TLS."])
@pytest.mark.parametrize("ca_file", [None, "ca.pem"])
def test_an_https_url_to_an_in_stack_upstream_without_ca_file_install_fails_bootstrap(tmp_path, host, ca_file):
    (tmp_path / "ca.pem").write_bytes(pem(issue_certificate("quickstart test ca")[0]))
    changes = {"url": f"https://{host}:8443/mcp"} | ({"ca_file": ca_file} if ca_file else {})
    with pytest.raises(b.BootstrapError, match=r"an https url to the stack's .* needs ca_file install"):
        b.load_upstream(write_upstream(tmp_path, **changes))


@pytest.mark.parametrize(
    "url, message",
    [
        (HTTPS_URL, "ca_file install is the install CA, which signs only gitea-mcp-tls, stub-upstream"),
        ("https://203.0.113.7/mcp", "ca_file install is the install CA"),
        ("http://stub-upstream:8443/mcp", "url must be https://<host>"),
    ],
)
def test_ca_file_install_outside_the_stack_or_over_http_fails_bootstrap(tmp_path, url, message):
    with pytest.raises(b.BootstrapError, match=message):
        b.load_upstream(write_upstream(tmp_path, url=url, ca_file="install"))


def test_stored_credential_returns_the_stored_secret_as_text(tmp_path, monkeypatch):
    state = tmp_path / "custodian"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    backend = LocalBackend.generate(state / "kek")
    store = CredentialStore.create(state / "credentials.db", backend)
    store.put(b.TENANT, "gitea", "https://gitea.example", b"token " + b"a" * 40)
    store.close()
    settings = SimpleNamespace(credentials=state / "credentials.db", kek=state / "kek")
    monkeypatch.setattr(b, "load_custodian", lambda path: settings)
    upstream = SimpleNamespace(credential_id="gitea", target="https://gitea.example")
    assert b.stored_credential(upstream) == "token " + "a" * 40


class GiteaHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.answer(200, {"host": self.headers["host"], "authorization": self.headers["authorization"]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        self.answer(201, {"path": self.path, "body": body})

    def answer(self, status, document):
        raw = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def socket_path():
    directory = Path(tempfile.mkdtemp(prefix="bg-", dir="/tmp"))
    yield directory / "gitea.sock"
    shutil.rmtree(directory)


@pytest.fixture
def gitea_socket(socket_path):
    server = socketserver.ThreadingUnixStreamServer(str(socket_path), GiteaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield socket_path
    finally:
        server.shutdown()
        server.server_close()


def test_gitea_is_reached_over_its_unix_socket(gitea_socket):
    gitea = b.Gitea(gitea_socket)
    assert gitea.request("GET", "/api/v1/user", "token abc") == (200, {"host": "gitea", "authorization": "token abc"})
    assert gitea.expect({201}, "POST", "/api/v1/orgs", None, {"username": "quickstart"}) == {
        "path": "/api/v1/orgs",
        "body": {"username": "quickstart"},
    }


def test_a_missing_gitea_socket_fails_without_waiting(gitea_socket):
    began = time.monotonic()
    with pytest.raises(FileNotFoundError):
        b.Gitea(gitea_socket.with_name("absent.sock")).request("GET", "/api/healthz", None)
    assert time.monotonic() - began < 1


def test_gitea_not_healthy_on_its_socket_fails_bootstrap(gitea_socket):
    with pytest.raises(b.BootstrapError, match="absent.sock was not healthy within 0s"):
        b.Gitea(gitea_socket.with_name("absent.sock")).wait_healthy(0)


STORED = "token " + "s" * 40
MINTED = "token " + "m" * 40


def fingerprint(credential):
    return hashlib.sha256(credential.encode()).hexdigest()


class TokenGitea(b.Gitea):
    def __init__(self, events):
        super().__init__(b.GITEA_SOCKET)
        self.tokens = {7: b.TOKEN_NAME, 8: "laptop"}
        self.deleted = []
        self.events = events
        self.demo = {STORED: 200, MINTED: 200}
        self.page_cap = 50
        self.lost = None
        self.last_eight = {7: "s" * 8}

    def wait_healthy(self, seconds):
        pass

    def request(self, method, path, authorization, body=None):
        tokens = f"/api/v1/users/{b.AGENT}/tokens"
        if (method, path) == ("GET", f"/api/v1/repos/{b.ORG}/demo"):
            return self.demo[authorization], {"permissions": {"pull": True}}
        if (method, path) == ("POST", tokens):
            token_id = max(self.tokens) + 1
            self.tokens[token_id] = body["name"]
            self.last_eight[token_id] = "m" * 8
            self.events.append(("minted", token_id))
            if self.lost is not None:
                return self.lost()
            return 201, {"id": token_id, "sha1": "m" * 40}
        if method == "DELETE" and path.startswith(f"{tokens}/"):
            token_id = int(path.rsplit("/", 1)[1])
            del self.tokens[token_id]
            self.deleted.append(token_id)
            self.events.append(("deleted", token_id))
            return 204, None
        if method == "GET" and urlsplit(path).path == tokens:
            query = parse_qs(urlsplit(path).query)
            limit, page = min(int(query.get("limit", ["50"])[0]), self.page_cap), int(query.get("page", ["1"])[0])
            listed = [self.listed(token_id, name) for token_id, name in self.tokens.items()]
            return 200, listed[(page - 1) * limit : page * limit]
        assert method in ("GET", "PATCH")
        return 200, {}

    def listed(self, token_id, name):
        last_eight = self.last_eight.get(token_id, f"{token_id:08x}")
        return {"id": token_id, "name": name} | ({} if last_eight is None else {"token_last_eight": last_eight})


class FakeCli:
    def __init__(self, events=None):
        self.calls = []
        self.timeouts = []
        self.refused = {}
        self.put_fails = False
        self.store = None
        self.events = [] if events is None else events

    def __call__(self, command, **options):
        arguments, stdin = tuple(command[3:]), options["input"]
        self.calls.append((arguments, stdin))
        self.timeouts.append((arguments[0], options["timeout"]))
        if arguments[0] == "credential-check":
            if stdin in self.refused:
                stderr = f"agent-bailiff credential-check refused: {self.refused[stdin]}: a detail\n"
                return subprocess.CompletedProcess(command, 1, "", stderr)
            document = {"fingerprint": fingerprint(stdin), "login": "agent", "private_repositories": 2}
            return subprocess.CompletedProcess(command, 0, json.dumps(document), "")
        if self.put_fails:
            return subprocess.CompletedProcess(command, 1, "", "agent-bailiff put-credential refused: a detail\n")
        self.events.append(("stored", stdin))
        self.store = stdin
        return subprocess.CompletedProcess(command, 0, "stored\n", "")

    def of(self, command):
        return [(arguments, stdin) for arguments, stdin in self.calls if arguments[0] == command]


@pytest.fixture
def pair(tmp_path, monkeypatch):
    handoff = tmp_path / "handoff"
    handoff.mkdir(mode=0o700)
    (tmp_path / "password").write_text("admin password")
    events = []
    fake = SimpleNamespace(
        cli=FakeCli(events), stored=None, handoff=handoff, gitea=TokenGitea(events), built=[], events=events
    )
    monkeypatch.setattr(b, "HANDOFF", handoff)
    monkeypatch.setattr(b, "HANDOFF_POLL_SECONDS", 0.01)
    monkeypatch.setattr(b, "READY_SECONDS", 10)
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 10)
    monkeypatch.setattr(b, "UPSTREAM_FILE", GITEA_UPSTREAM)
    monkeypatch.setattr(b, "ADMIN_PASSWORD", tmp_path / "password")
    monkeypatch.setattr(b, "Gitea", lambda base: fake.built.append(base) or fake.gitea)
    monkeypatch.setattr(b, "seed", lambda gitea, admin: [])
    monkeypatch.setattr(b, "token_reach", lambda gitea, credential: {})
    monkeypatch.setattr(b, "stored_credential", lambda upstream: fake.cli.store or fake.stored)
    monkeypatch.setattr(b.subprocess, "run", fake.cli)
    return fake


@pytest.fixture
def gitea(pair):
    return pair.gitea


def run_pair():
    with ThreadPoolExecutor(1) as pool:
        put = pool.submit(b.main, ["credential"])
        checked = b.main(["gitea"])
        return put.result(timeout=30), checked


def test_a_minted_credential_that_passes_the_check_is_put_with_its_fingerprint(pair, capsys):
    assert run_pair() == (0, 0)
    [(arguments, stdin)] = pair.cli.of("credential-check")
    assert stdin == MINTED
    assert arguments[1:] == (
        "--provider", "gitea", "--api-url", "http://gitea/api/v1", "--unix-socket", "/run/gitea/gitea.sock",
        "--binding-resource", "gitea/repos/quickstart/*", "--required", "read:issue", "--required", "read:repository",
        "--max-repos", "1000", "--timeout", "10.0",
    )  # fmt: skip
    [(arguments, stdin)] = pair.cli.of("custodian")
    assert arguments[:2] == ("custodian", "put-credential")
    assert arguments[-2:] == ("--expect-fingerprint", fingerprint(MINTED))
    assert stdin == MINTED
    lines = capsys.readouterr().out.splitlines()
    assert "credential: created" in lines and "gitea: created" in lines
    assert list(pair.handoff.iterdir()) == []


def test_the_upstream_credential_check_bounds_reach_the_check_under_a_longer_subprocess_timeout(
    pair, tmp_path, monkeypatch
):
    monkeypatch.setattr(b, "UPSTREAM_FILE", write_upstream(tmp_path, max_repos=10_000, check_timeout_seconds=60))
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"
    assert run_pair() == (0, 0)
    checks = pair.cli.of("credential-check")
    assert [arguments[-4:] for arguments, _ in checks] == [("--max-repos", "10000", "--timeout", "60")] * 2
    assert pair.cli.timeouts == [
        ("credential-check", 60 + b.CLI_TIMEOUT_SECONDS),
        ("credential-check", 60 + b.CLI_TIMEOUT_SECONDS),
        ("custodian", b.CLI_TIMEOUT_SECONDS),
    ]
    assert 60 + b.CLI_TIMEOUT_SECONDS > 60 + cli.CREDENTIAL_CHECK_GRACE_SECONDS


def test_a_minted_credential_the_check_refuses_is_deleted_from_gitea_before_any_put(pair, gitea, capsys):
    pair.cli.refused[MINTED] = "broader_scopes"
    assert run_pair() == (1, 1)
    assert gitea.deleted == [9]
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"}
    assert pair.cli.of("custodian") == []
    err = capsys.readouterr().err
    assert "bootstrap gitea refused: agent-bailiff credential-check --provider failed: agent-bailiff" in err
    assert "bootstrap credential refused: bootstrap refused the credential, so nothing is stored" in err
    assert list(pair.handoff.iterdir()) == []


def test_a_minted_credential_that_cannot_read_the_repository_is_deleted_from_gitea(pair, gitea, capsys):
    gitea.demo[MINTED] = 404
    assert run_pair() == (1, 1)
    assert gitea.deleted == [9]
    assert pair.cli.calls == []
    assert f"the minted credential cannot read {b.ORG}/demo" in capsys.readouterr().err


@pytest.mark.parametrize(
    "reason",
    ["provider_unreachable", "rate_limited", "deadline_exceeded", "bad_response", "outside_binding", "too_many_repos"],
)
def test_a_kept_credential_refused_for_another_reason_aborts_without_minting(pair, gitea, capsys, reason):
    pair.stored = STORED
    pair.cli.refused[STORED] = reason
    assert run_pair() == (1, 1)
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"} and gitea.deleted == []
    assert [stdin for _, stdin in pair.cli.of("credential-check")] == [STORED]
    assert pair.cli.of("custodian") == []
    assert f"credential-check refused: {reason}: a detail" in capsys.readouterr().err


@pytest.mark.parametrize("status", [429, 500, 502])
def test_a_kept_credential_gitea_cannot_answer_for_aborts_without_minting(pair, gitea, capsys, status):
    pair.stored = STORED
    gitea.demo[STORED] = status
    assert run_pair() == (1, 1)
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"} and pair.cli.calls == []
    assert f"gitea GET /api/v1/repos/{b.ORG}/demo returned {status}" in capsys.readouterr().err


def test_a_kept_credential_is_checked_and_not_put_again(pair, capsys):
    pair.stored = STORED
    assert run_pair() == (0, 0)
    assert [stdin for _, stdin in pair.cli.of("credential-check")] == [STORED]
    assert pair.cli.of("custodian") == [] and pair.gitea.deleted == []
    lines = capsys.readouterr().out.splitlines()
    assert "credential: kept" in lines and "gitea: kept" in lines
    assert list(pair.handoff.iterdir()) == []


def test_a_kept_credential_retires_every_other_quickstart_token(pair, gitea):
    gitea.tokens.update({20: f"{b.TOKEN_NAME}-0123456789abcdef", 21: f"{b.TOKEN_NAME}-laptop"})
    pair.stored = STORED
    assert run_pair() == (0, 0)
    assert pair.events == [("deleted", 20)]
    assert gitea.tokens.keys() == {7, 8, 21} and pair.cli.of("custodian") == []


def test_a_kept_credential_whose_old_tokens_cannot_be_retired_fails_bootstrap(pair, gitea, monkeypatch, capsys):
    pair.stored = STORED

    def unlisted(gitea, agent):
        raise b.BootstrapError("token list failed")

    monkeypatch.setattr(b, "agent_tokens", unlisted)
    assert run_pair() == (0, 1)
    assert f"older {b.TOKEN_NAME} tokens may still be live in gitea: token list failed" in capsys.readouterr().err


def test_a_kept_credential_beside_a_token_with_no_last_eight_fails_and_deletes_nothing(pair, gitea, capsys):
    gitea.tokens[20] = f"{b.TOKEN_NAME}-0123456789abcdef"
    gitea.last_eight[7] = None
    pair.stored = STORED
    assert run_pair() == (0, 1)
    assert gitea.deleted == []
    assert "gitea listed token 7 with no token_last_eight" in capsys.readouterr().err


def test_a_stored_remint_whose_old_tokens_cannot_be_retired_fails_bootstrap(pair, gitea, monkeypatch, capsys):
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"

    def unlisted(gitea, agent):
        raise b.BootstrapError("token list failed")

    monkeypatch.setattr(b, "agent_tokens", unlisted)
    assert run_pair() == (0, 1)
    assert pair.events == [("minted", 9), ("stored", MINTED)]
    assert f"older {b.TOKEN_NAME} tokens may still be live in gitea: token list failed" in capsys.readouterr().err


@pytest.mark.parametrize("reason", ["broader_scopes", "token_rejected"])
def test_a_kept_credential_the_check_refuses_is_replaced_by_a_checked_one(pair, gitea, capsys, reason):
    pair.stored = STORED
    pair.cli.refused[STORED] = reason
    assert run_pair() == (0, 0)
    assert [stdin for _, stdin in pair.cli.of("credential-check")] == [STORED, MINTED]
    assert pair.events == [("minted", 9), ("stored", MINTED), ("deleted", 7)]
    assert gitea.tokens.keys() == {8, 9} and gitea.tokens[9].startswith(f"{b.TOKEN_NAME}-")
    [(arguments, stdin)] = pair.cli.of("custodian")
    assert (arguments[-1], stdin) == (fingerprint(MINTED), MINTED)
    captured = capsys.readouterr()
    assert "the stored credential is refused, so a new one is minted" in captured.err
    assert "credential: created" in captured.out.splitlines()


def test_a_refused_remint_deletes_only_the_new_token_and_leaves_the_stored_one_live(pair, gitea, capsys):
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"
    pair.cli.refused[MINTED] = "broader_scopes"
    assert run_pair() == (1, 1)
    assert pair.events == [("minted", 9), ("deleted", 9)]
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"}
    assert "bootstrap refused the credential, so nothing is stored" in capsys.readouterr().err


def test_a_remint_credential_put_fails_to_store_deletes_only_the_new_token(pair, gitea, capsys):
    pair.stored = STORED
    pair.cli.refused[STORED] = "token_rejected"
    pair.cli.put_fails = True
    assert run_pair() == (1, 1)
    assert pair.events == [("minted", 9), ("deleted", 9)]
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"}
    assert "credential-put did not store the minted credential, so it is deleted from gitea" in capsys.readouterr().err


def test_a_put_that_stores_then_times_out_keeps_the_new_token_and_fails_credential_put(
    pair, gitea, monkeypatch, capsys
):
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"

    def stored_then_timed_out(command, **options):
        result = pair.cli(command, **options)
        if command[3] == "custodian":
            raise subprocess.TimeoutExpired(command, b.CLI_TIMEOUT_SECONDS)
        return result

    monkeypatch.setattr(b.subprocess, "run", stored_then_timed_out)
    assert run_pair() == (1, 0)
    assert pair.events == [("minted", 9), ("stored", MINTED), ("deleted", 7)]
    assert gitea.tokens.keys() == {8, 9}
    err = capsys.readouterr().err
    assert "did not finish within 60s; the store holds the checked credential anyway, so it is kept" in err
    assert list(pair.handoff.iterdir()) == []


def test_a_saved_marker_that_cannot_be_written_keeps_the_new_token_and_fails_both(pair, gitea, monkeypatch, capsys):
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 2)
    write = b.write_handoff

    def disk_full_on_saved(name, text):
        if name == "saved":
            raise OSError(28, "No space left on device")
        write(name, text)

    monkeypatch.setattr(b, "write_handoff", disk_full_on_saved)
    assert run_pair() == (1, 1)
    assert pair.events == [("minted", 9), ("stored", MINTED)]
    assert gitea.tokens.keys() == {7, 8, 9}
    err = capsys.readouterr().err
    assert "bootstrap credential refused: [Errno 28] No space left on device" in err
    assert "reported no store of the minted credential within 2s, so token 9 stays in gitea" in err


def test_a_store_result_that_never_comes_keeps_the_new_token_and_fails_bootstrap(pair, gitea, monkeypatch, capsys):
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 0.2)
    monkeypatch.setattr(b, "store_handed_off", lambda upstream, stored: b.wait_for_handoff(("checked",), 10, "unused"))
    assert run_pair() == (0, 1)
    assert pair.events == [("minted", 9)]
    assert gitea.tokens.keys() == {7, 8, 9}
    assert "within 0.2s, so token 9 stays in gitea until a later run keeps or deletes it" in capsys.readouterr().err


def test_a_remint_a_later_bootstrap_step_fails_deletes_only_the_new_token(pair, gitea, monkeypatch, capsys):
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"

    def unreachable(gitea, credential):
        raise b.BootstrapError("token reach probe failed")

    monkeypatch.setattr(b, "token_reach", unreachable)
    assert run_pair() == (1, 1)
    assert pair.events == [("minted", 9), ("deleted", 9)]
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"} and pair.cli.of("custodian") == []
    assert "token reach probe failed" in capsys.readouterr().err


def test_a_kept_fingerprint_other_than_the_stored_credential_stores_nothing(pair):
    b.export_credential(STORED)
    b.hand_off("kept", STORED, fingerprint(MINTED))
    with pytest.raises(b.BootstrapError, match="kept a credential other than the stored one"):
        b.store_handed_off(b.load_upstream(GITEA_UPSTREAM), STORED)
    assert pair.cli.calls == []


def test_every_handoff_file_is_owner_read_only(pair):
    b.export_credential(STORED)
    b.hand_off("created", MINTED, fingerprint(MINTED))
    modes = {entry.name: entry.stat().st_mode & 0o777 for entry in pair.handoff.iterdir()}
    assert modes == dict.fromkeys(("stored", "ready", "token", "fingerprint", "checked"), 0o400)


def test_each_mint_names_its_token_uniquely_and_deletes_nothing(pair, gitea):
    first, second = b.mint_credential(gitea, "admin"), b.mint_credential(gitea, "admin")
    assert (first.token_id, second.token_id) == (9, 10) and gitea.deleted == []
    assert gitea.tokens[9] != gitea.tokens[10]
    assert all(re.fullmatch(f"{b.TOKEN_NAME}-[0-9a-f]{{16}}", gitea.tokens[token_id]) for token_id in (9, 10))


def lose(error):
    raise error


@pytest.mark.parametrize(
    "lost",
    [
        lambda: lose(b.GiteaUnavailable("gitea POST /api/v1/users/agent/tokens did not answer within 10s")),
        lambda: lose(ConnectionResetError(54, "Connection reset by peer")),
        lambda: lose(json.JSONDecodeError("Expecting value", "", 0)),
        lambda: (201, {"id": 9}),
        lambda: (201, ["m" * 40]),
    ],
    ids=["unavailable", "reset", "not-json", "no-sha1", "not-an-object"],
)
def test_a_mint_with_no_clear_answer_deletes_the_token_by_its_name_and_fails(gitea, lost):
    gitea.lost = lost
    with pytest.raises((b.BootstrapError, OSError, ValueError)):
        b.mint_credential(gitea, "admin")
    assert gitea.events == [("minted", 9), ("deleted", 9)]
    assert gitea.tokens == {7: b.TOKEN_NAME, 8: "laptop"}


def test_a_stored_remint_retires_every_other_quickstart_token_from_every_page(pair, gitea):
    gitea.tokens = {token_id: f"laptop-{token_id}" for token_id in range(1, 121)}
    gitea.tokens[60] = f"{b.TOKEN_NAME}-0123456789abcdef"
    gitea.tokens[110] = b.TOKEN_NAME
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"
    assert run_pair() == (0, 0)
    assert pair.events == [("minted", 121), ("stored", MINTED), ("deleted", 60), ("deleted", 110)]
    assert gitea.tokens[121].startswith(f"{b.TOKEN_NAME}-") and len(gitea.tokens) == 119


def test_a_stored_remint_spares_tokens_that_only_share_the_quickstart_prefix(pair, gitea):
    gitea.tokens.update(
        {20: f"{b.TOKEN_NAME}-laptop", 21: f"{b.TOKEN_NAME}ish", 22: f"{b.TOKEN_NAME}-0123456789ABCDEF"}
    )
    pair.stored = STORED
    pair.cli.refused[STORED] = "broader_scopes"
    assert run_pair() == (0, 0)
    assert pair.events == [("minted", 23), ("stored", MINTED), ("deleted", 7)]
    assert gitea.tokens.keys() == {8, 20, 21, 22, 23}


def test_the_token_list_refuses_a_list_longer_than_its_page_bound(pair, gitea, monkeypatch):
    monkeypatch.setattr(b, "MAX_TOKEN_PAGES", 2, raising=False)
    gitea.tokens = {token_id: f"laptop-{token_id}" for token_id in range(1, 101)}
    with pytest.raises(b.BootstrapError, match=f"the gitea token list of {b.AGENT} runs past 2 pages"):
        b.agent_tokens(gitea, "agent")


def test_the_token_list_is_read_past_a_short_page_until_an_empty_one(gitea):
    gitea.page_cap = 3
    gitea.tokens = {token_id: f"laptop-{token_id}" for token_id in range(1, 8)}
    assert [token["id"] for token in b.agent_tokens(gitea, "agent")] == list(range(1, 8))


@pytest.fixture
def answering(socket_path):
    answer = SimpleNamespace(status=200, body=b"{}", path=socket_path)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(answer.status)
            self.send_header("Content-Length", str(len(answer.body)))
            self.end_headers()
            self.wfile.write(answer.body)

        def log_message(self, *args):
            pass

    server = socketserver.ThreadingUnixStreamServer(str(socket_path), Handler)
    threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True).start()
    yield answer
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("status", [200, 500])
def test_a_gitea_answer_over_the_byte_cap_fails_bootstrap(answering, monkeypatch, status):
    monkeypatch.setattr(b, "MAX_GITEA_BYTES", 64, raising=False)
    answering.status, answering.body = status, json.dumps({"pad": "x" * 64}).encode()
    with pytest.raises(b.BootstrapError, match="gitea GET /api/v1/user answered more than 64 bytes"):
        b.Gitea(answering.path).request("GET", "/api/v1/user", None)


@pytest.mark.parametrize(
    ("head", "drip"),
    [
        (b"HTTP/1.1 200 OK\r\nX-Drip: ", b"a"),
        (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[", b" "),
    ],
    ids=["headers", "body"],
)
def test_a_gitea_answer_that_drips_fails_bootstrap_at_its_wall_clock_deadline(monkeypatch, socket_path, head, drip):
    monkeypatch.setattr(b, "HTTP_TIMEOUT_SECONDS", 0.5, raising=False)
    server = Drip(head, drip, socket_path)
    try:
        started = time.monotonic()
        with pytest.raises(b.BootstrapError, match=r"gitea GET /user did not answer within 0\.5s"):
            b.Gitea(socket_path).request("GET", "/user", None)
        elapsed = time.monotonic() - started
    finally:
        server.close()
    assert elapsed < 2


def test_a_cli_call_that_outlives_its_timeout_fails_bootstrap():
    server = Drip(b"HTTP/1.1 200 OK\r\nX-Drip: ", b"a")
    try:
        started = time.monotonic()
        with pytest.raises(b.BootstrapError, match="credential-check --provider did not finish within 1s"):
            b.cli(
                "credential-check", "--provider", "gitea", "--api-url", server.url, "--binding-resource",
                "gitea/repos/quickstart/*", "--required", "read:repository", stdin=NEEDLE, timeout=1,
            )  # fmt: skip
        elapsed = time.monotonic() - started
    finally:
        server.close()
    assert elapsed < 3


def test_a_handoff_file_appears_under_its_name_only_once_it_is_whole_and_synced(pair, monkeypatch):
    events = []
    fsync, rename = os.fsync, os.rename

    def synced(fd):
        events.append(("fsync", os.fstat(fd).st_size))
        fsync(fd)

    def renamed(source, target):
        events.append(("rename", Path(target).name, Path(source).read_text(), os.path.lexists(target)))
        rename(source, target)

    monkeypatch.setattr(b.os, "fsync", synced)
    monkeypatch.setattr(b.os, "rename", renamed)
    b.write_handoff("fingerprint", fingerprint(MINTED))
    assert events == [("fsync", 64), ("rename", "fingerprint", fingerprint(MINTED), False)]
    assert [entry.name for entry in pair.handoff.iterdir()] == ["fingerprint"]
    assert (pair.handoff / "fingerprint").stat().st_mode & 0o777 == 0o400


def test_a_stored_handoff_bootstrap_cannot_read_writes_the_refused_marker(pair, capsys):
    pair.stored = "token " + "x" * b.MAX_HANDOFF_BYTES
    assert run_pair() == (1, 1)
    err = capsys.readouterr().err
    assert f"stored is larger than {b.MAX_HANDOFF_BYTES} bytes" in err
    assert "bootstrap refused the credential, so nothing is stored" in err
    assert pair.built == [] and pair.cli.calls == []
    assert list(pair.handoff.iterdir()) == []


def test_credential_put_alone_fails_at_the_deadline_naming_bootstrap(pair, monkeypatch, capsys):
    pair.stored = STORED
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 0)
    assert b.main(["credential"]) == 1
    err = capsys.readouterr().err
    assert "bootstrap handed off no checked credential within 0s" in err
    assert "run credential-put and bootstrap together" in err
    assert pair.cli.calls == [] and list(pair.handoff.iterdir()) == []


def test_credential_put_ignores_a_stale_checked_handoff_from_an_earlier_run(pair, monkeypatch, capsys):
    pair.stored = STORED
    (pair.handoff / "fingerprint").write_text(fingerprint(STORED))
    (pair.handoff / "checked").write_text("kept")
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 0)
    assert b.main(["credential"]) == 1
    assert "bootstrap handed off no checked credential within 0s" in capsys.readouterr().err
    assert list(pair.handoff.iterdir()) == []


def test_bootstrap_alone_fails_at_the_deadline_naming_credential_put(pair, monkeypatch, capsys):
    monkeypatch.setattr(b, "READY_SECONDS", 0)
    assert b.main(["gitea"]) == 1
    err = capsys.readouterr().err
    assert "credential-put exported no stored credential within 0s" in err
    assert "run bootstrap together with credential-put" in err
    assert pair.built == [] and pair.cli.calls == []


def test_the_handoff_wait_polls_until_its_deadline_then_fails(pair):
    ticks = iter([0.0, 0.0, 1.0, 2.0])
    sleeps = []
    with pytest.raises(b.BootstrapError, match="^nobody came$"):
        b.wait_for_handoff(("checked",), 2, "nobody came", clock=lambda: next(ticks), sleep=sleeps.append)
    assert sleeps == [b.HANDOFF_POLL_SECONDS] * 2


def test_the_handoff_wait_returns_the_first_file_that_appears(pair):
    def sleep(seconds):
        (pair.handoff / "refused").write_text("")

    assert b.wait_for_handoff(("checked", "refused"), 60, "unused", clock=lambda: 0.0, sleep=sleep) == "refused"


@pytest.mark.parametrize("step", ["credential", "gitea"])
def test_an_upstream_without_a_provider_fails_the_pair(pair, monkeypatch, capsys, step):
    monkeypatch.setattr(b, "UPSTREAM_FILE", b.QUICKSTART_UPSTREAMS / "stub.json")
    assert b.main([step]) == 1
    assert "stub.json names no provider to check the token against" in capsys.readouterr().err
    assert list(pair.handoff.iterdir()) == []
