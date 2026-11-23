import dataclasses
import json
import os
import shutil
import socket
import tempfile
from pathlib import Path

import pytest
from test_effector import post

from agent_bailiff.effector.catalog import shipped_catalog
from agent_bailiff.effector.drift import RbacDrift, RbacGate
from agent_bailiff.keys import generate_signing_key
from agent_bailiff.service import run
from agent_bailiff.service.init import init_effector
from agent_bailiff.service.settings import ConfigError, load_effector, parse_effector

UID = os.geteuid()
GID = os.getegid()


@pytest.fixture
def root():
    path = Path(tempfile.mkdtemp(prefix="be-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


def private(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def self_signed_ca():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def effector_config(root, port, platform="upstream"):
    keys = private(root / "keys")
    custodian = generate_signing_key(keys / "custodian.key", "custodian.example")
    decide = generate_signing_key(keys / "decide.key", "decide.example")
    ca = root / "ca.pem"
    ca.write_bytes(self_signed_ca())
    token = root / "token"
    token.write_text("t")
    os.chmod(token, 0o600)
    init_effector(
        private(root / "effector"),
        name="effector.homelab",
        custodian=custodian,
        decide=decide,
        ledger=root / "ledger" / "ledger.db",
        ledger_uid=UID,
        ledger_group=GID,
        port=port,
        platform=platform,
        kubernetes={"host": "127.0.0.1", "port": 6443, "ca": ca, "token_file": token, "audit_token_file": token},
        rbac={
            "namespace": "bailiff-system",
            "service_account": "effector",
            "applier": "gitops",
            "webhook_namespace": "bailiff-webhook",
            "tenants": {"tenant-a": ["staging"]},
        },
        docket={"socket": str(root / "run" / "d.sock"), "sink_uid": UID},
    )
    return root / "effector" / "config.json"


def test_init_writes_an_effector_config_that_loads(root):
    path = effector_config(root, 18080)
    settings = load_effector(path)
    assert (settings.name, settings.custodian, settings.decider, settings.port) == (
        "effector.homelab",
        "custodian.example",
        "decide.example",
        18080,
    )
    assert settings.suspension_dir == root / "ledger" / "ledger.db.suspension"
    assert settings.platform == "upstream"
    assert settings.catalog.name == "kubernetes.json" and settings.catalog.is_file()
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_the_effector_config_refuses_unknown_and_missing_keys(root):
    document = json.loads(effector_config(root, 18081).read_text())
    with pytest.raises(ConfigError):
        parse_effector({**document, "extra": 1})
    without = dict(document)
    del without["kubernetes"]
    with pytest.raises(ConfigError):
        parse_effector(without)
    with pytest.raises(ConfigError):
        parse_effector({**document, "port": 0})


@pytest.mark.parametrize("platform", ["gke", "eks"])
def test_init_on_a_managed_platform_writes_the_read_catalog(root, platform):
    settings = load_effector(effector_config(root, 18083, platform=platform))
    assert settings.platform == platform
    assert settings.catalog.name == "kubernetes-read.json" and settings.catalog.is_file()


@pytest.mark.parametrize("platform", ["gke", "eks"])
def test_a_managed_platform_effector_refuses_a_write_catalog_before_contacting_kubernetes(root, monkeypatch, platform):
    monkeypatch.setattr(RbacGate, "verify", lambda self: pytest.fail("the RBAC gate ran"))
    settings = load_effector(effector_config(root, free_port(), platform=platform))
    with pytest.raises(ValueError, match="managed platforms support read-only catalogs only"):
        run.start_effector(dataclasses.replace(settings, catalog=shipped_catalog("kubernetes")))


def test_a_managed_platform_effector_serves_the_read_catalog(root, monkeypatch):
    monkeypatch.setattr(RbacGate, "verify", lambda self: None)
    port = free_port()
    service = run.start_effector(load_effector(effector_config(root, port, platform="gke")))
    try:
        status, body = post(port, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert status == 200
        assert [tool["name"] for tool in body["result"]["tools"]] == ["list_pods", "read_pod_log", "get_deployment"]
    finally:
        service.close()


@pytest.mark.parametrize("platform", ["aks", "GKE", None])
def test_the_effector_config_refuses_an_unknown_platform(root, platform):
    document = json.loads(effector_config(root, 18084).read_text())
    with pytest.raises(ConfigError, match="effector.platform: platform must be one of"):
        parse_effector({**document, "platform": platform})


def test_the_effector_refuses_to_start_when_its_rbac_cannot_be_verified(root):
    with pytest.raises(RbacDrift, match="the RBAC check failed"):
        run.start_effector(load_effector(effector_config(root, free_port())))


def test_an_effector_that_fails_to_start_releases_its_docket_writer(root, monkeypatch):
    monkeypatch.setattr(RbacGate, "verify", lambda self: None)
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        settings = load_effector(effector_config(root, taken.getsockname()[1]))
        with pytest.raises(OSError):
            run.start_effector(settings)
    run.start_effector(dataclasses.replace(settings, port=free_port())).close()


def test_a_started_effector_serves_its_catalog_on_localhost(root, monkeypatch):
    monkeypatch.setattr(RbacGate, "verify", lambda self: None)
    port = free_port()
    service = run.start_effector(load_effector(effector_config(root, port)))
    try:
        status, body = post(port, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert status == 200
        assert {tool["name"] for tool in body["result"]["tools"]} == {
            "list_pods",
            "read_pod_log",
            "get_deployment",
            "scale_deployment",
            "restart_deployment",
        }
        status, body = post(
            port,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "scale_deployment", "arguments": {}},
            },
        )
        assert body["result"]["isError"] is True
    finally:
        service.close()


def test_the_effector_config_refuses_unsafe_rbac_inputs(root):
    document = json.loads(effector_config(root, 18082).read_text())
    for tenants in ({}, {"Tenant": ["staging"]}, {"tenant-a": ["bailiff-system"]}, {"tenant-a": "staging"}):
        with pytest.raises(ConfigError):
            parse_effector({**document, "rbac": {**document["rbac"], "tenants": tenants}})
