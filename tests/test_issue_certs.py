import datetime
import errno
import importlib.util
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID

QUICKSTART = Path(__file__).resolve().parents[1] / "examples" / "quickstart"
_spec = importlib.util.spec_from_file_location("quickstart_issue_certs", QUICKSTART / "issue_certs.py")
assert _spec is not None and _spec.loader is not None
certs_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = certs_module
_spec.loader.exec_module(certs_module)

GID = os.getgid()
SERVICES = {name: certs_module.Service(service.names, GID) for name, service in certs_module.SERVICES.items()}
NAMES = ("public", *SERVICES)


@pytest.fixture
def certs(tmp_path):
    root = tmp_path / "certs"
    for name in NAMES:
        (root / name).mkdir(parents=True)
    return root


def run(certs, *arguments, services=SERVICES):
    return certs_module.main(["--certs", str(certs), *arguments], services)


def snapshot(certs):
    files = {}
    for path in sorted(certs.rglob("*")):
        relative = str(path.relative_to(certs))
        files[relative] = os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
    return files


def current(certs, name):
    return os.readlink(certs / name / "current")


def leaf(certs, service):
    return x509.load_pem_x509_certificate((certs / "public" / "current" / f"{service}.pem").read_bytes())


def ca(certs):
    return x509.load_pem_x509_certificate((certs / "public" / "current" / "ca.pem").read_bytes())


def spki(key):
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def make_writable(path):
    os.chmod(path, 0o600)


class TlsServer:
    def __init__(self, certificate, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, key)
        self.socket = socket.create_server(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                connection, _ = self.socket.accept()
            except OSError:
                return
            try:
                with self.context.wrap_socket(connection, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                connection.close()

    def close(self):
        self.socket.close()


def serve_leaf(certs, service, served=None):
    served = served or service
    directory = certs / served / "current"
    return TlsServer(directory / f"{served}.pem", directory / f"{served}.key")


def test_an_issued_set_chains_with_each_service_name_and_server_auth(certs):
    assert run(certs, "issue") == 0
    authority = ca(certs)
    constraints = authority.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = authority.extensions.get_extension_for_class(x509.KeyUsage)
    assert constraints.critical and constraints.value.ca
    assert usage.critical and usage.value.key_cert_sign and usage.value.crl_sign
    assert authority.not_valid_after_utc - authority.not_valid_before_utc > datetime.timedelta(days=2 * 365)
    for service, settings in SERVICES.items():
        certificate = leaf(certs, service)
        certificate.verify_directly_issued_by(authority)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        listed = [*names.get_values_for_type(x509.DNSName), *map(str, names.get_values_for_type(x509.IPAddress))]
        assert sorted(listed) == sorted(settings.names)
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
        assert not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert sorted(SERVICES["gateway"].names) == ["127.0.0.1", "gateway", "localhost"]


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_the_gateway_leaf_passes_python_strict_verification(certs, host):
    assert run(certs, "issue") == 0
    server = serve_leaf(certs, "gateway")
    context = ssl.create_default_context(cafile=certs / "public" / "current" / "ca.pem")
    assert context.verify_flags & ssl.VERIFY_X509_STRICT
    try:
        with (
            socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            assert tls.version()
    finally:
        server.close()


def test_the_ca_key_is_never_on_disk(certs):
    assert run(certs, "issue") == 0
    authority = spki(ca(certs).public_key())
    keys = [path for path in certs.rglob("*") if path.is_file() and b"PRIVATE KEY" in path.read_bytes()]
    assert sorted(path.name for path in keys) == sorted(f"{service}.key" for service in SERVICES)
    for path in keys:
        assert spki(load_pem_private_key(path.read_bytes(), None).public_key()) != authority
    assert not [path for path in (certs / "public").rglob("*") if path.is_file() and "key" in path.name]


def test_keys_get_their_service_group_and_certificates_are_world_readable(certs):
    assert run(certs, "issue") == 0
    for service in SERVICES:
        directory = certs / service / "current"
        key = (directory / f"{service}.key").stat()
        assert (stat.S_IMODE(key.st_mode), key.st_gid) == (0o440, GID)
        assert stat.S_IMODE((directory / f"{service}.pem").stat().st_mode) == 0o444
        assert stat.S_IMODE((certs / "public" / "current" / f"{service}.pem").stat().st_mode) == 0o444
    assert stat.S_IMODE((certs / "public" / "current" / "ca.pem").stat().st_mode) == 0o444


def test_a_group_the_issuer_is_not_in_fails_and_leaves_no_generation(certs):
    foreign = max(os.getgroups()) + 54321
    services = {**SERVICES, "gateway": certs_module.Service(SERVICES["gateway"].names, foreign)}
    assert run(certs, "issue", services=services) == 1
    assert all(os.listdir(certs / name) == [] for name in NAMES)


def test_a_rerun_keeps_a_complete_set_unchanged(certs, capsys):
    assert run(certs, "issue") == 0
    before = snapshot(certs)
    assert run(certs, "issue") == 0
    assert snapshot(certs) == before
    assert "kept gen-0001" in capsys.readouterr().out


def drop_public_leaf(certs):
    os.unlink(certs / "public" / "current" / "stub-upstream.pem")


def drop_gateway_link(certs):
    os.unlink(certs / "gateway" / "current")


def drop_gateway_key(certs):
    os.unlink(certs / "gateway" / "current" / "gateway.key")


def swap_in_another_set(certs):
    other = certs.parent / "other"
    for name in NAMES:
        (other / name).mkdir(parents=True)
    assert run(other, "issue") == 0
    target = certs / "gateway" / "gen-0001"
    for path in target.iterdir():
        make_writable(path)
    shutil.rmtree(target)
    shutil.copytree(other / "gateway" / "gen-0001", target)


def point_gateway_at_another_generation(certs):
    shutil.copytree(certs / "gateway" / "gen-0001", certs / "gateway" / "gen-0002")
    os.unlink(certs / "gateway" / "current")
    os.symlink("gen-0002", certs / "gateway" / "current")


def swap_gateway_key(certs):
    key = certs / "gateway" / "current" / "gateway.key"
    make_writable(key)
    key.write_bytes((certs / "stub-upstream" / "current" / "stub-upstream.key").read_bytes())


@pytest.mark.parametrize(
    "damage",
    [
        drop_public_leaf,
        drop_gateway_link,
        drop_gateway_key,
        swap_in_another_set,
        point_gateway_at_another_generation,
        swap_gateway_key,
    ],
)
def test_a_partial_or_mixed_set_is_refused_with_the_runbook(certs, capsys, damage):
    assert run(certs, "issue") == 0
    damage(certs)
    capsys.readouterr()
    assert run(certs, "issue") == 1
    assert "docker compose run --rm certs issue --reissue" in capsys.readouterr().err


def test_a_chain_valid_set_naming_other_hosts_is_refused_on_rerun(certs, capsys):
    renamed = {**SERVICES, "gateway": certs_module.Service(("gateway.example", "10.0.0.5"), GID)}
    assert run(certs, "issue", services=renamed) == 0
    before = snapshot(certs)
    capsys.readouterr()
    assert run(certs, "issue") == 1
    error = capsys.readouterr().err
    assert "gateway.pem names 10.0.0.5, gateway.example, not 127.0.0.1, gateway, localhost" in error
    assert "docker compose run --rm certs issue --reissue" in error
    assert snapshot(certs) == before
    assert run(certs, "check") == 1


def test_a_first_issue_killed_before_its_switch_is_replaced_on_rerun(certs):
    (certs / "gateway" / "gen-0001").mkdir()
    assert run(certs, "issue") == 0
    assert {current(certs, name) for name in NAMES} == {"gen-0002"}
    assert all(sorted(os.listdir(certs / name)) == ["current", "gen-0002"] for name in NAMES)


def test_reissue_switches_to_a_new_generation_and_deletes_the_previous_one(certs):
    assert run(certs, "issue") == 0
    first = ca(certs)
    assert run(certs, "issue", "--reissue") == 0
    assert {current(certs, name) for name in NAMES} == {"gen-0002"}
    assert ca(certs) != first
    assert all(sorted(os.listdir(certs / name)) == ["current", "gen-0002"] for name in NAMES)
    assert certs_module.check(certs, SERVICES, datetime.datetime.now(datetime.UTC), 30, keys=True) == []
    assert run(certs, "issue", "--reissue") == 0
    assert all(sorted(os.listdir(certs / name)) == ["current", "gen-0003"] for name in NAMES)


def private_keys(certs):
    return {
        path: path.read_bytes() for path in certs.rglob("*") if path.is_file() and b"PRIVATE KEY" in path.read_bytes()
    }


def test_reissue_leaves_no_earlier_private_key_on_disk(certs):
    assert run(certs, "issue") == 0
    earlier = set(private_keys(certs).values())
    assert run(certs, "issue", "--reissue") == 0
    keys = private_keys(certs)
    assert len(keys) == len(SERVICES)
    assert earlier.isdisjoint(keys.values())
    for service in SERVICES:
        key = load_pem_private_key((certs / service / "current" / f"{service}.key").read_bytes(), None)
        assert spki(key.public_key()) == spki(leaf(certs, service).public_key())


KILL_BEFORE_SWITCH = """
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("issue_certs", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.switch = lambda directory, generation: os.kill(os.getpid(), signal.SIGKILL)
services = {name: module.Service(service.names, os.getgid()) for name, service in module.SERVICES.items()}
module.main(["--certs", sys.argv[2], "issue", "--reissue"], services)
"""


def test_a_sigkill_before_the_switch_leaves_the_current_set(certs):
    assert run(certs, "issue") == 0
    before = {name: snapshot(certs / name / "current") for name in NAMES}
    result = subprocess.run(
        [sys.executable, "-c", KILL_BEFORE_SWITCH, str(QUICKSTART / "issue_certs.py"), str(certs)],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == -9, result.stderr
    assert {current(certs, name) for name in NAMES} == {"gen-0001"}
    assert {name: snapshot(certs / name / "current") for name in NAMES} == before
    assert all((certs / name / "gen-0002").is_dir() for name in NAMES)
    assert run(certs, "issue") == 1
    assert run(certs, "issue", "--reissue") == 0
    assert {current(certs, name) for name in NAMES} == {"gen-0003"}
    assert all(sorted(os.listdir(certs / name)) == ["current", "gen-0003"] for name in NAMES)


KILL_AFTER_SWITCH = """
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location("issue_certs", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
switch, switched = module.switch, []
def killing(directory, generation):
    switch(directory, generation)
    switched.append(directory)
    if len(switched) == int(sys.argv[3]):
        os.kill(os.getpid(), signal.SIGKILL)
module.switch = killing
services = {name: module.Service(service.names, os.getgid()) for name, service in module.SERVICES.items()}
module.main(["--certs", sys.argv[2], "issue", "--reissue"], services)
"""


@pytest.mark.parametrize("switches", range(1, len(NAMES) + 1))
def test_a_sigkill_after_each_switch_is_refused_on_rerun_and_recovered_by_reissue(certs, capsys, switches):
    assert run(certs, "issue") == 0
    result = subprocess.run(
        [sys.executable, "-c", KILL_AFTER_SWITCH, str(QUICKSTART / "issue_certs.py"), str(certs), str(switches)],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == -9, result.stderr
    assert [current(certs, name) for name in NAMES] == [
        "gen-0002" if index < switches else "gen-0001" for index in range(len(NAMES))
    ]
    interrupted = snapshot(certs)
    capsys.readouterr()
    assert run(certs, "issue") == 1
    assert "docker compose run --rm certs issue --reissue" in capsys.readouterr().err
    assert snapshot(certs) == interrupted
    assert run(certs, "issue", "--reissue") == 0
    assert all(sorted(os.listdir(certs / name)) == ["current", "gen-0003"] for name in NAMES)
    assert certs_module.check(certs, SERVICES, datetime.datetime.now(datetime.UTC), 30, keys=True) == []
    assert run(certs, "issue") == 0


class FullDisk:
    def __init__(self, writes_before_full):
        self.left = writes_before_full

    def write(self, fd, data):
        if self.left == 0:
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        self.left -= 1
        return os.write(fd, data)

    def __getattr__(self, name):
        return getattr(os, name)


@pytest.mark.parametrize("writes_before_full", [0, 3, 6])
def test_a_full_disk_leaves_the_current_set_and_no_new_generation(certs, monkeypatch, capsys, writes_before_full):
    assert run(certs, "issue") == 0
    before = snapshot(certs)
    monkeypatch.setattr(certs_module, "os", FullDisk(writes_before_full))
    assert run(certs, "issue", "--reissue") == 1
    monkeypatch.undo()
    assert "No space left on device" in capsys.readouterr().err
    assert snapshot(certs) == before


def test_check_passes_on_a_healthy_set(certs):
    assert run(certs, "issue") == 0
    assert run(certs, "check", "--keys") == 0


def test_check_fails_on_a_set_that_expires_within_the_margin(certs, capsys):
    assert run(certs, "issue", "--days", "20") == 0
    assert run(certs, "check", "--margin-days", "10") == 0
    capsys.readouterr()
    assert run(certs, "check") == 1
    assert "gateway.pem expires at" in capsys.readouterr().err


@pytest.mark.parametrize("damage", [drop_public_leaf, swap_gateway_key])
def test_check_fails_on_a_missing_leaf_or_a_mismatched_key(certs, damage):
    assert run(certs, "issue") == 0
    damage(certs)
    assert run(certs, "check", "--keys") == 1


def test_check_names_a_leaf_another_ca_signed_under_the_same_ca_name(certs, capsys):
    assert run(certs, "issue") == 0
    other = certs.parent / "other"
    for name in NAMES:
        (other / name).mkdir(parents=True)
    assert run(other, "issue") == 0
    public = certs / "public" / "current" / "gateway.pem"
    make_writable(public)
    public.write_bytes((other / "public" / "current" / "gateway.pem").read_bytes())
    assert leaf(certs, "gateway").issuer == ca(certs).subject
    capsys.readouterr()
    assert run(certs, "check") == 1
    assert "gateway.pem is not signed by the install CA" in capsys.readouterr().err


def test_check_fails_on_an_expired_ca(certs):
    past = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=10)
    certs_module.issue(certs, SERVICES, 1, now=lambda: past)
    problems = certs_module.check(certs, SERVICES, datetime.datetime.now(datetime.UTC), 0)
    assert any(problem.startswith("the CA expires at") for problem in problems)


def test_check_without_a_set_fails(certs):
    assert run(certs, "check") == 1


def test_a_probe_of_the_current_served_certificate_passes(certs):
    assert run(certs, "issue") == 0
    server = serve_leaf(certs, "gateway")
    try:
        assert run(certs, "check", "--probe", f"gateway=localhost:{server.port}") == 0
    finally:
        server.close()


def test_a_probe_of_another_services_certificate_fails(certs, capsys):
    assert run(certs, "issue") == 0
    server = serve_leaf(certs, "stub-upstream")
    try:
        assert run(certs, "check", "--probe", f"stub-upstream=localhost:{server.port}") == 1
    finally:
        server.close()
    assert "failed TLS with the install CA" in capsys.readouterr().err


def test_a_probe_of_a_service_still_serving_the_previous_generation_fails(certs, capsys):
    assert run(certs, "issue") == 0
    server = serve_leaf(certs, "gateway")
    try:
        assert run(certs, "issue", "--reissue") == 0
        assert run(certs, "check", "--probe", f"gateway=localhost:{server.port}") == 1
    finally:
        server.close()
    assert "failed TLS with the install CA" in capsys.readouterr().err


def test_a_probe_of_a_certificate_the_ca_signed_for_another_service_names_it(certs, capsys):
    assert run(certs, "issue") == 0
    gateway = certs / "gateway" / "current"
    server = TlsServer(gateway / "gateway.pem", gateway / "gateway.key")
    try:
        assert run(certs, "check", "--probe", f"stub-upstream=127.0.0.1:{server.port}") == 1
    finally:
        server.close()
    assert "serves a certificate other than the current one" in capsys.readouterr().err


def test_a_probe_needs_a_known_service():
    with pytest.raises(SystemExit):
        certs_module.main(["check", "--probe", "jaeger=jaeger:4318"])


def write_upstream(tmp_path, url):
    path = tmp_path / "upstream.json"
    path.write_text(json.dumps({"url": url}))
    return path


@pytest.mark.parametrize(
    ("url", "probes"),
    [
        ("https://gitea-mcp-tls:8443/mcp", [("gitea-mcp-tls", "gitea-mcp-tls:8443")]),
        ("https://stub-upstream:8443/mcp", [("stub-upstream", "stub-upstream:8443")]),
        ("https://gitea-mcp-tls/mcp", [("gitea-mcp-tls", "gitea-mcp-tls:443")]),
        ("https://mcp.example.com/mcp", []),
        ("http://gitea-mcp-tls:8443/mcp", []),
    ],
)
def test_the_upstream_probe_covers_only_an_https_server_in_the_stack(tmp_path, url, probes):
    assert certs_module.upstream_probe(write_upstream(tmp_path, url)) == probes


@pytest.mark.parametrize("content", ["{", "{}", '{"url": 1}', '{"url": "https://gitea-mcp-tls:port/mcp"}'])
def test_an_upstream_config_without_a_url_fails_the_check(tmp_path, certs, capsys, content):
    assert run(certs, "issue") == 0
    path = tmp_path / "upstream.json"
    path.write_text(content)
    assert run(certs, "check", "--probe-upstream", str(path)) == 1
    assert "names no upstream url" in capsys.readouterr().err


def test_the_check_probes_the_configured_upstream_with_the_explicit_probes_once(tmp_path, certs, monkeypatch):
    assert run(certs, "issue") == 0
    probed = []
    monkeypatch.setattr(certs_module, "probe", lambda _certs, service, address: probed.append((service, address)) or [])
    path = write_upstream(tmp_path, "https://gitea-mcp-tls:8443/mcp")
    arguments = ("--probe", "stub-upstream=stub-upstream:8443", "--probe", "gateway=gateway:8080")
    assert run(certs, "check", *arguments, "--probe-upstream", str(path)) == 0
    assert probed == [
        ("gateway", "gateway:8080"),
        ("gitea-mcp-tls", "gitea-mcp-tls:8443"),
        ("stub-upstream", "stub-upstream:8443"),
    ]
    probed.clear()
    path = write_upstream(tmp_path, "https://stub-upstream:8443/mcp")
    assert run(certs, "check", *arguments, "--probe-upstream", str(path)) == 0
    assert probed == [("gateway", "gateway:8080"), ("stub-upstream", "stub-upstream:8443")]
