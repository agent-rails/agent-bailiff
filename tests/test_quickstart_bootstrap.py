import datetime
import http.server
import ipaddress
import json
import os
import shutil
import socketserver
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from agent_warrant.identity import encode_public_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID
from test_quickstart_stack import b

from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
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


@pytest.mark.parametrize(
    "name, policies",
    [("gitea.json", {}), ("stub.json", {"policies": {"backendTLS": {"root": str(b.GATEWAY_CA)}}})],
)
def test_the_gateway_config_targets_only_the_upstream_url(name, policies):
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / name)
    template = json.loads(b.GATEWAY_TEMPLATE.read_text())
    document = b.gateway_document(upstream)
    assert document["mcp"]["targets"] == [{"name": upstream.target, "mcp": {"host": upstream.url}, **policies}]
    assert {**document, "mcp": {**document["mcp"], "targets": []}} == template


def test_the_stub_upstream_is_served_over_https_with_the_install_ca():
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json")
    assert upstream.url.startswith("https://stub-upstream:")
    assert upstream.ca_file == b.INSTALL_CA == b.STATE / "certs" / "public" / "current" / "ca.pem"


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
    assert written["mcp"]["targets"][0]["mcp"]["host"] == "http://gitea-mcp:8080/mcp"


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
        ({"url": "http://167772165:8080/mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "http://0xa000005:8080/mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "ftp://gitea-mcp:21/mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "https:///mcp"}, "http://<compose-service>:<port> or https://"),
        ({"url": "https://user:secret@mcp.example.com/mcp"}, "no credentials, query or fragment"),
        ({"url": "https://mcp.example.com/mcp?key=1"}, "no credentials, query or fragment"),
        ({"url": "https://mcp.example.com:99999/mcp"}, "url Port out of range"),
        ({"url": "http://localhost:15000/"}, "must not name the stack's own localhost"),
        ({"url": "http://gateway:8080/mcp"}, "must not name the stack's own gateway"),
        ({"url": "http://custodian:8080/mcp"}, "must not name the stack's own custodian"),
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
        (None, "http://stub-upstream:8080/mcp", "ca_file needs an https:// url"),
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
    monkeypatch.setattr(b, "UPSTREAM_FILE", GITEA_UPSTREAM)
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


@pytest.mark.parametrize("host", sorted(b.UPSTREAM_HOSTS) + ["STUB-UPSTREAM.", "gitea-mcp."])
@pytest.mark.parametrize("ca_file", [None, "ca.pem"])
def test_an_https_url_to_an_in_stack_upstream_without_ca_file_install_fails_bootstrap(tmp_path, host, ca_file):
    (tmp_path / "ca.pem").write_bytes(pem(issue_certificate("quickstart test ca")[0]))
    changes = {"url": f"https://{host}:8443/mcp"} | ({"ca_file": ca_file} if ca_file else {})
    with pytest.raises(b.BootstrapError, match=r"an https url to the stack's .* needs ca_file install"):
        b.load_upstream(write_upstream(tmp_path, **changes))


@pytest.mark.parametrize(
    "url, message",
    [
        (HTTPS_URL, "ca_file install is the install CA, which signs only gitea, gitea-mcp, gitea-mcp-spike"),
        ("https://203.0.113.7/mcp", "ca_file install is the install CA"),
        ("http://stub-upstream:8443/mcp", "ca_file needs an https:// url"),
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
def gitea_socket():
    directory = Path(tempfile.mkdtemp(prefix="bg-", dir="/tmp"))
    path = directory / "gitea.sock"
    server = socketserver.ThreadingUnixStreamServer(str(path), GiteaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield path
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(directory)


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
