import http.client
import json
import socket
import ssl
import threading
import time
from dataclasses import replace

import pytest
from test_effector import CATALOG, CONFIG, NOW
from test_webhook_admission import review
from test_webhook_cluster import _pins

from agent_bailiff.webhook.admission import Admission
from agent_bailiff.webhook.certs import issue_serving_certificate
from agent_bailiff.webhook.cli import main as webhook_main
from agent_bailiff.webhook.manifests import NAME, generate_manifests
from agent_bailiff.webhook.server import WebhookServer


def test_a_single_bundle_for_enforce_mode_is_refused(tmp_path, capsys):
    issue_serving_certificate(tmp_path / "certs", NAME, "bailiff-webhook")
    (tmp_path / "pins.json").write_text(json.dumps(_pins()))
    with pytest.raises(ValueError, match="do not apply Enforce as one bundle"):
        generate_manifests(
            namespace="bailiff-webhook",
            image="registry.example/bailiff@sha256:" + "a" * 64,
            ca_pem=(tmp_path / "certs" / "ca.crt").read_bytes(),
            pins=_pins(),
            catalog=CATALOG,
            deployers=["gitops"],
            enforce=True,
        )
    with pytest.raises(SystemExit) as error:
        webhook_main(
            [
                "manifests",
                "--namespace",
                "bailiff-webhook",
                "--image",
                "registry.example/bailiff@sha256:" + "a" * 64,
                "--ca",
                str(tmp_path / "certs" / "ca.crt"),
                "--pins",
                str(tmp_path / "pins.json"),
                "--deployer",
                "gitops",
                "--enforce",
            ]
        )
    assert error.value.code == 2
    assert "do not apply Enforce as one bundle" in capsys.readouterr().err


def test_tls_review_and_manifest_keep_private_keys_out(tmp_path, monkeypatch):
    directory = tmp_path / "certs"
    issue_serving_certificate(directory, NAME, "bailiff-system")
    ca = (directory / "ca.crt").read_bytes()
    pins = {"catalog_digest": CATALOG.digest}
    document = generate_manifests(
        namespace="bailiff-system",
        image="registry.example/bailiff@sha256:" + "a" * 64,
        ca_pem=ca,
        pins=pins,
        catalog=CATALOG,
        deployers=["gitops"],
        enforce=False,
    )
    serialized = json.dumps(document)
    assert "PRIVATE KEY" not in serialized
    webhook = next(item for item in document["items"] if item["kind"] == "ValidatingWebhookConfiguration")
    assert webhook["webhooks"][0]["failurePolicy"] == "Ignore"
    assert webhook["webhooks"][0]["rules"][0]["resources"] == ["*/*"]
    deployment = next(item for item in document["items"] if item["kind"] == "Deployment")
    assert deployment["spec"]["template"]["metadata"]["annotations"]["bailiff.dev/enforce-mode"] == "false"
    audit_probe = deployment["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]
    assert audit_probe["path"] == "/readyz/audit"

    enforce_target = generate_manifests(
        namespace="bailiff-system",
        image="registry.example/bailiff@sha256:" + "a" * 64,
        ca_pem=ca,
        pins=pins,
        catalog=CATALOG,
        deployers=["gitops"],
        enforce=True,
        phase="target",
    )
    enforce_deployment = next(item for item in enforce_target["items"] if item["kind"] == "Deployment")
    enforce_probe = enforce_deployment["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]
    assert enforce_probe["path"] == "/readyz/enforce"
    assert enforce_deployment["spec"]["template"]["metadata"]["annotations"]["bailiff.dev/enforce-mode"] == "true"
    enforce_command = enforce_deployment["spec"]["template"]["spec"]["containers"][0]["command"]
    assert enforce_command[enforce_command.index("--mode") + 1] == "enforce"
    prepare = generate_manifests(
        namespace="bailiff-system",
        image="registry.example/bailiff@sha256:" + "a" * 64,
        ca_pem=ca,
        pins=pins,
        catalog=CATALOG,
        deployers=["gitops"],
        enforce=True,
        phase="prepare",
    )
    register = generate_manifests(
        namespace="bailiff-system",
        image="registry.example/bailiff@sha256:" + "a" * 64,
        ca_pem=ca,
        pins=pins,
        catalog=CATALOG,
        deployers=["gitops"],
        enforce=True,
        phase="register",
    )
    assert all(item["kind"] != "ValidatingWebhookConfiguration" for item in prepare["items"])
    assert [item["kind"] for item in register["items"]] == [
        "Service",
        "ValidatingWebhookConfiguration",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
    ]

    admission = Admission(replace(CONFIG, skew_seconds=2), CATALOG, enforce=True)
    monkeypatch.setattr("agent_bailiff.webhook.server.time.time", lambda: NOW + 2)
    server = WebhookServer(admission, "127.0.0.1", 0, directory / "tls.crt", directory / "tls.key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        context = ssl.create_default_context(cafile=str(directory / "ca.crt"))
        context.check_hostname = False
        connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=context, timeout=5)
        body = json.dumps(review()).encode()
        connection.request("POST", "/validate", body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["response"]["allowed"] is True
        connection.close()
        for path, expected_status, expected_ready in (
            ("/readyz/enforce", 200, True),
            ("/readyz/audit", 503, False),
        ):
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=context, timeout=5)
            connection.request("GET", path)
            response = connection.getresponse()
            assert response.status == expected_status
            assert json.loads(response.read())["ready"] is expected_ready
            connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _drip(port, context, stop):
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        secure = context.wrap_socket(raw, server_hostname="localhost")
        secure.sendall(b"GET /readyz/enforce HTTP/1.1\r\n")
        while not stop.is_set():
            secure.sendall(b"X")
            time.sleep(0.2)
    except OSError:
        pass


def test_slow_clients_cannot_hold_review_slots_past_the_connection_deadline(tmp_path):
    directory = tmp_path / "certs"
    issue_serving_certificate(directory, NAME, "bailiff-system")
    admission = Admission(replace(CONFIG, skew_seconds=2), CATALOG, enforce=True)
    server = WebhookServer(
        admission,
        "127.0.0.1",
        0,
        directory / "tls.crt",
        directory / "tls.key",
        max_concurrency=2,
        connection_deadline=1,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    context = ssl.create_default_context(cafile=str(directory / "ca.crt"))
    context.check_hostname = False
    stop = threading.Event()
    drippers = [threading.Thread(target=_drip, args=(server.server_port, context, stop), daemon=True) for _ in range(6)]
    try:
        for dripper in drippers:
            dripper.start()
        time.sleep(1.6)
        connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=context, timeout=3)
        connection.request("GET", "/readyz/enforce")
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_register_switches_the_service_to_enforce_pods_and_target_is_not_applyable(tmp_path):
    directory = tmp_path / "certs"
    issue_serving_certificate(directory, NAME, "bailiff-system")
    options = {
        "namespace": "bailiff-system",
        "image": "registry.example/bailiff@sha256:" + "a" * 64,
        "ca_pem": (directory / "ca.crt").read_bytes(),
        "pins": {"catalog_digest": CATALOG.digest},
        "catalog": CATALOG,
        "deployers": ["gitops"],
    }
    prepare = generate_manifests(enforce=True, phase="prepare", **options)
    register = generate_manifests(enforce=True, phase="register", **options)
    target = generate_manifests(enforce=True, phase="target", **options)
    audit = generate_manifests(enforce=False, **options)
    deployment = next(item for item in prepare["items"] if item["kind"] == "Deployment")
    assert deployment["spec"]["template"]["metadata"]["labels"]["bailiff.dev/webhook-mode"] == "enforce"
    assert "bailiff.dev/webhook-mode" not in deployment["spec"]["selector"]["matchLabels"]
    prepared_service = next(item for item in prepare["items"] if item["kind"] == "Service")
    assert "bailiff.dev/webhook-mode" not in prepared_service["spec"]["selector"]
    assert [item["kind"] for item in register["items"]] == [
        "Service",
        "ValidatingWebhookConfiguration",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
    ]
    assert register["items"][0]["spec"]["selector"]["bailiff.dev/webhook-mode"] == "enforce"
    assert register["items"][1]["webhooks"][0]["failurePolicy"] == "Fail"
    assert all(
        item["spec"]["validationActions"] == ["Deny"]
        for item in register["items"]
        if item["kind"] == "ValidatingAdmissionPolicyBinding"
    )
    assert all(
        item["spec"]["validationActions"] == ["Audit", "Warn"]
        for item in audit["items"]
        if item["kind"] == "ValidatingAdmissionPolicyBinding"
    )
    assert target["kind"] != "List"
    audit_service = next(item for item in audit["items"] if item["kind"] == "Service")
    assert "bailiff.dev/webhook-mode" not in audit_service["spec"]["selector"]


def _client_hello():
    client = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), outgoing := ssl.MemoryBIO(), server_hostname="x")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def test_a_client_that_drips_its_handshake_is_cut_at_the_deadline(tmp_path):
    directory = tmp_path / "certs"
    issue_serving_certificate(directory, NAME, "bailiff-system")
    admission = Admission(replace(CONFIG, skew_seconds=2), CATALOG, enforce=True)
    server = WebhookServer(
        admission, "127.0.0.1", 0, directory / "tls.crt", directory / "tls.key", connection_deadline=1
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        raw = socket.create_connection(("127.0.0.1", server.server_port), timeout=10)
        started = time.monotonic()
        try:
            for byte in _client_hello():
                raw.sendall(bytes([byte]))
                time.sleep(0.5)
                if time.monotonic() - started > 6:
                    break
        except OSError:
            pass
        held = time.monotonic() - started
        raw.close()
        assert held < 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
