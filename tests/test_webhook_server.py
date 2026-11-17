import http.client
import json
import ssl
import threading
from dataclasses import replace

import pytest
from test_effector import CATALOG, CONFIG, NOW
from test_webhook_admission import review

from agent_bailiff.webhook.admission import Admission
from agent_bailiff.webhook.certs import issue_serving_certificate
from agent_bailiff.webhook.cli import main as webhook_main
from agent_bailiff.webhook.manifests import NAME, generate_manifests
from agent_bailiff.webhook.server import WebhookServer


def test_cli_refuses_a_single_bundle_for_enforce_mode():
    with pytest.raises(SystemExit) as error:
        webhook_main(
            [
                "manifests",
                "--namespace",
                "bailiff-system",
                "--image",
                "registry.example/bailiff@sha256:" + "a" * 64,
                "--ca",
                "ca.crt",
                "--pins",
                "pins.json",
                "--enforce",
            ]
        )
    assert error.value.code == 2


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
        enforce=True,
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
        enforce=True,
        phase="prepare",
    )
    register = generate_manifests(
        namespace="bailiff-system",
        image="registry.example/bailiff@sha256:" + "a" * 64,
        ca_pem=ca,
        pins=pins,
        catalog=CATALOG,
        enforce=True,
        phase="register",
    )
    assert all(item["kind"] != "ValidatingWebhookConfiguration" for item in prepare["items"])
    assert [item["kind"] for item in register["items"]] == ["ValidatingWebhookConfiguration"]

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
