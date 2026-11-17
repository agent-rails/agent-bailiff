import http.client
import json
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest
from agent_warrant.identity import encode_public_key
from test_effector import CATALOG, CUSTODIAN_KEY, DECIDE_KEY, clearance_for
from test_effector_cluster import apply, kubectl

from agent_bailiff.custodian.release import ReleaseSigner
from agent_bailiff.decide.clearance import encode_clearance
from agent_bailiff.decide.identity import snapshot_args
from agent_bailiff.keys import key_id
from agent_bailiff.webhook.certs import issue_serving_certificate
from agent_bailiff.webhook.manifests import NAME, generate_manifests

IMAGE = os.environ.get("AGENT_BAILIFF_TEST_WEBHOOK_IMAGE")
pytest_plugins = ["test_effector_cluster"]
pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BAILIFF_TEST_KUBE_CONTEXT") or not IMAGE,
    reason="set disposable cluster context and a locally available pinned webhook image",
)


def _release(namespace, replicas):
    now = int(time.time())
    arguments = {"namespace": namespace, "name": "api", "replicas": replicas}
    clearance = replace(
        clearance_for(arguments=arguments), iat=now, exp=now + 60, tenant="ta",
        op_id="A" * 43, args_digest=snapshot_args(arguments).digest,
    )
    decide_kid = key_id("decide.example", DECIDE_KEY.public_key())
    custodian_kid = key_id("custodian.example", CUSTODIAN_KEY.public_key())
    encoded = encode_clearance(clearance, DECIDE_KEY, decide_kid)
    return ReleaseSigner("custodian.example", CUSTODIAN_KEY, custodian_kid).sign(
        clearance, encoded, "effector.homelab", CATALOG.digest, "f" * 32, now
    )


def _pins():
    return {
        "effector_id": "effector.homelab", "custodian_id": "custodian.example", "decider_id": "decide.example",
        "custodian_keys": {key_id("custodian.example", CUSTODIAN_KEY.public_key()):
                           encode_public_key(CUSTODIAN_KEY.public_key())},
        "decide_keys": {key_id("decide.example", DECIDE_KEY.public_key()):
                        encode_public_key(DECIDE_KEY.public_key())},
        "catalog_digest": CATALOG.digest, "skew_seconds": 2, "max_clearance_lifetime": 60,
    }


def _patch(cluster, release=None):
    namespace = cluster["names"]["stg"]
    token = (cluster["directory"] / "effector").read_text()
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/merge-patch+json",
        "Impersonate-User": "bailiff:ta:scale",
        "Impersonate-Extra-bailiff.dev%2Fop-id": "A" * 43,
    }
    if release:
        headers["Impersonate-Extra-bailiff.dev%2Frelease"] = release
    transport = cluster["transport"]
    connection = http.client.HTTPSConnection(transport._host, transport._port, context=transport._context, timeout=10)
    try:
        connection.request(
            "PATCH", f"/apis/apps/v1/namespaces/{namespace}/deployments/api/scale",
            b'{"spec":{"replicas":3}}', headers,
        )
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        connection.close()


def test_release_reaches_real_https_admission_and_enforce_blocks_token_only(cluster):
    namespace = cluster["names"]["sys"]
    if kubectl("get", "validatingwebhookconfiguration", NAME, "--ignore-not-found", "-o", "name").stdout.strip():
        pytest.fail("webhook registration already exists; use a disposable cluster")
    directory = Path(cluster["directory"]) / "webhook-certs"
    issue_serving_certificate(directory, NAME, namespace)
    kubectl("-n", namespace, "create", "secret", "tls", NAME + "-tls", "--cert=" + str(directory / "tls.crt"),
            "--key=" + str(directory / "tls.key"))
    manifests = generate_manifests(
        namespace=namespace, image=IMAGE, ca_pem=(directory / "ca.crt").read_bytes(),
        pins=_pins(), catalog=CATALOG, enforce=False,
    )
    path = Path(cluster["directory"]) / "webhook.json"
    path.write_text(json.dumps(manifests))
    try:
        apply(path.read_text())
        kubectl("-n", namespace, "rollout", "status", "deployment/" + NAME, "--timeout=90s")
        time.sleep(3)
        assert _patch(cluster)[0] == 200  # Audit mode: the VAP still checks op-id and range.
        manifests["items"][-1]["webhooks"][0]["failurePolicy"] = "Fail"
        manifests["items"][0]["data"]["webhook.json"] = json.dumps({**_pins(), "enforce": True}, sort_keys=True)
        apply(json.dumps(manifests))
        kubectl("-n", namespace, "rollout", "restart", "deployment/" + NAME)
        kubectl("-n", namespace, "rollout", "status", "deployment/" + NAME, "--timeout=90s")
        time.sleep(3)
        denied = _patch(cluster)
        assert denied[0] == 403, (
            json.loads(denied[1]).get("message"),
            kubectl("-n", namespace, "get", "service", NAME, "-o", "yaml", check=False).stdout,
            kubectl("-n", namespace, "get", "endpoints", NAME, "-o", "yaml", check=False).stdout,
            kubectl(
                "-n", namespace, "get", "pods", "-l", "app.kubernetes.io/name=" + NAME,
                "-o", "wide", check=False,
            ).stdout,
            kubectl("-n", namespace, "logs", "deployment/" + NAME, "--all-pods=true", "--tail=100", check=False).stdout,
            kubectl("get", "validatingwebhookconfiguration", NAME, "-o", "yaml", check=False).stdout,
        )
        allowed = _patch(cluster, _release(cluster["names"]["stg"], 3))
        assert allowed[0] == 200, (
            allowed[1], kubectl("-n", namespace, "logs", "deployment/" + NAME, "--all-pods=true",
                                "--tail=100", check=False).stdout,
        )
    finally:
        kubectl("delete", "-f", str(path), "--ignore-not-found", "--wait=false", check=False)
        kubectl("-n", namespace, "delete", "secret", NAME + "-tls", "--ignore-not-found", check=False)
