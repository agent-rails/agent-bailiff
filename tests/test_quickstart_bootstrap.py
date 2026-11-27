import datetime
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
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


@pytest.mark.parametrize("name", ["gitea.json", "stub.json"])
def test_the_gateway_config_targets_only_the_upstream_url(name):
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / name)
    template = json.loads(b.GATEWAY_TEMPLATE.read_text())
    document = b.gateway_document(upstream)
    assert document["mcp"]["targets"] == [{"name": upstream.target, "mcp": {"host": upstream.url}}]
    assert {**document, "mcp": {**document["mcp"], "targets": []}} == template


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
        ({"provider": "github"}, "provider must be one of gitea"),
        ({"provider": ""}, "provider must be a non-empty ASCII printable string"),
        ({"provider_api_url": "http://gitea.example.com:3000/api/v1"}, "provider_api_url must be http://<compose"),
        ({"provider_api_url": "http://custodian:3000/api/v1"}, "provider_api_url must not name the stack's own"),
        ({"provider_api_url": "https://127.0.0.1/api/v1"}, "provider_api_url must not name a loopback"),
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
    assert check == b.ProviderCheck("gitea", "http://gitea:3000/api/v1", ("read:issue", "read:repository"))
    assert b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json").provider_check is None


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


def issue_certificate(common_name, issuer=None, dns_name=None):
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
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()), critical=False)
    )
    if issuer is None:
        usage = {name: False for name in KEY_USAGES}
        builder = builder.add_extension(
            x509.KeyUsage(**{**usage, "key_cert_sign": True, "crl_sign": True}), critical=True
        )
    if dns_name:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
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
    assert upstream.ca_pem == pem(ca)
    assert b"PRIVATE KEY" not in upstream.ca_pem


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
    monkeypatch.setattr(b, "UPSTREAM_FILE", b.QUICKSTART_UPSTREAMS / "stub.json")
    assert b.init_gateway() == "updated"
    assert not (tmp_path / "ca.pem").exists()
    assert "policies" not in json.loads((tmp_path / "gateway.json").read_text())["mcp"]["targets"][0]


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


STORED = "token " + "s" * 40
MINTED = "token " + "m" * 40


def fingerprint(credential):
    return hashlib.sha256(credential.encode()).hexdigest()


class FakeGitea:
    built = []

    def __init__(self, base):
        FakeGitea.built.append(base)

    def wait_healthy(self, seconds):
        pass

    def expect(self, statuses, method, path, authorization, body=None):
        return {}


class FakeCli:
    def __init__(self):
        self.calls = []
        self.refused = set()

    def __call__(self, *arguments, stdin=None):
        self.calls.append((arguments, stdin))
        if arguments[0] == "credential-check":
            if stdin in self.refused:
                raise b.BootstrapError("agent-bailiff credential-check --provider failed: broader_scopes")
            return json.dumps({"fingerprint": fingerprint(stdin), "login": "agent", "private_repositories": 2})
        return "stored"

    def of(self, command):
        return [(arguments, stdin) for arguments, stdin in self.calls if arguments[0] == command]


@pytest.fixture
def pair(tmp_path, monkeypatch):
    handoff = tmp_path / "handoff"
    handoff.mkdir(mode=0o700)
    (tmp_path / "password").write_text("admin password")
    fake = SimpleNamespace(cli=FakeCli(), stored=None, minted=[], handoff=handoff)
    monkeypatch.setattr(b, "HANDOFF", handoff)
    monkeypatch.setattr(b, "HANDOFF_POLL_SECONDS", 0.01)
    monkeypatch.setattr(b, "READY_SECONDS", 10)
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 10)
    monkeypatch.setattr(b, "UPSTREAM_FILE", GITEA_UPSTREAM)
    monkeypatch.setattr(b, "ADMIN_PASSWORD", tmp_path / "password")
    monkeypatch.setattr(b, "Gitea", FakeGitea)
    monkeypatch.setattr(b, "seed", lambda gitea, admin: [])
    monkeypatch.setattr(b, "token_reach", lambda gitea, credential: {})
    monkeypatch.setattr(b, "credential_works", lambda gitea, credential: True)
    monkeypatch.setattr(b, "stored_credential", lambda upstream: fake.stored)
    monkeypatch.setattr(b, "mint_credential", lambda gitea, admin: fake.minted.append(MINTED) or MINTED)
    monkeypatch.setattr(b, "cli", fake.cli)
    FakeGitea.built = []
    return fake


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
        "--provider", "gitea", "--api-url", "http://gitea:3000/api/v1", "--binding-resource",
        "gitea/repos/quickstart/*", "--required", "read:issue", "--required", "read:repository",
    )  # fmt: skip
    [(arguments, stdin)] = pair.cli.of("custodian")
    assert arguments[:2] == ("custodian", "put-credential")
    assert arguments[-2:] == ("--expect-fingerprint", fingerprint(MINTED))
    assert stdin == MINTED
    lines = capsys.readouterr().out.splitlines()
    assert "credential: created" in lines and "gitea: created" in lines
    assert list(pair.handoff.iterdir()) == []


def test_a_refused_credential_aborts_before_any_put(pair, capsys):
    pair.cli.refused.add(MINTED)
    assert run_pair() == (1, 1)
    assert pair.cli.of("custodian") == []
    err = capsys.readouterr().err
    assert "bootstrap gitea refused: agent-bailiff credential-check --provider failed: broader_scopes" in err
    assert "bootstrap credential refused: bootstrap refused the credential, so nothing is stored" in err
    assert list(pair.handoff.iterdir()) == []


def test_a_kept_credential_is_checked_and_not_put_again(pair, capsys):
    pair.stored = STORED
    assert run_pair() == (0, 0)
    assert [stdin for _, stdin in pair.cli.of("credential-check")] == [STORED]
    assert pair.cli.of("custodian") == [] and pair.minted == []
    lines = capsys.readouterr().out.splitlines()
    assert "credential: kept" in lines and "gitea: kept" in lines
    assert list(pair.handoff.iterdir()) == []


def test_a_kept_credential_the_check_refuses_is_replaced_by_a_checked_one(pair, capsys):
    pair.stored = STORED
    pair.cli.refused.add(STORED)
    assert run_pair() == (0, 0)
    assert [stdin for _, stdin in pair.cli.of("credential-check")] == [STORED, MINTED]
    [(arguments, stdin)] = pair.cli.of("custodian")
    assert (arguments[-1], stdin) == (fingerprint(MINTED), MINTED)
    captured = capsys.readouterr()
    assert "the stored credential is refused, so a new one is minted" in captured.err
    assert "credential: created" in captured.out.splitlines()


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


def test_credential_put_alone_fails_at_the_deadline_naming_bootstrap(pair, monkeypatch, capsys):
    pair.stored = STORED
    monkeypatch.setattr(b, "HANDOFF_SECONDS", 0)
    assert b.main(["credential"]) == 1
    err = capsys.readouterr().err
    assert "bootstrap handed off no checked credential within 0s" in err
    assert "run credential-put and bootstrap together" in err
    assert pair.cli.calls == [] and list(pair.handoff.iterdir()) == []


def test_bootstrap_alone_fails_at_the_deadline_naming_credential_put(pair, monkeypatch, capsys):
    monkeypatch.setattr(b, "READY_SECONDS", 0)
    assert b.main(["gitea"]) == 1
    err = capsys.readouterr().err
    assert "credential-put exported no stored credential within 0s" in err
    assert "run bootstrap together with credential-put" in err
    assert FakeGitea.built == [] and pair.cli.calls == []


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
