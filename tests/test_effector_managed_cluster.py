import base64
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agent_bailiff.effector import drift
from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import RbacAudit, RbacGate
from agent_bailiff.effector.kubernetes import HttpsTransport, PooledTransport
from agent_bailiff.effector.platform import ACCEPTED_INCOMPLETE
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests, render, service_account_user
from agent_bailiff.service.init import DEFAULT_CATALOG

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_KIND_MANAGED") != "1",
    reason="set AGENT_BAILIFF_TEST_KIND_MANAGED=1 to create a disposable kind cluster with a stub webhook authorizer",
)

NODE_IMAGE = "kindest/node:v1.36.4"
CATALOG = OperationCatalog.load(DEFAULT_CATALOG)
SETTLE_SECONDS = 3
CACHE_SECONDS = 2
[PINNED_ERROR] = ACCEPTED_INCOMPLETE["gke"]
WEBHOOK_KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- name: authz
  cluster:
    server: http://host.docker.internal:{port}/authorize
users:
- name: apiserver
  user: {{}}
contexts:
- name: authz
  context: {{cluster: authz, user: apiserver}}
current-context: authz
"""
KIND_CONFIG = """kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {authz}
    containerPath: /etc/authz
    readOnly: true
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
      - name: authorization-mode
        value: Node,RBAC,Webhook
      - name: authorization-webhook-config-file
        value: /etc/authz/webhook.kubeconfig
      - name: authorization-webhook-version
        value: v1
      - name: authorization-webhook-cache-authorized-ttl
        value: 1s
      - name: authorization-webhook-cache-unauthorized-ttl
        value: 1s
      extraVolumes:
      - name: authz
        hostPath: /etc/authz
        mountPath: /etc/authz
        readOnly: true
        pathType: Directory
"""


class StubAuthorizer(ThreadingHTTPServer):
    request_queue_size = 128

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _AuthorizerHandler)
        self.allowed: set[tuple[str, str, str, str | None]] = set()


class _AuthorizerHandler(BaseHTTPRequestHandler):
    server: StubAuthorizer
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        review = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        spec = review.get("spec") or {}
        attributes = spec.get("resourceAttributes") or {}
        key = (spec.get("user"), attributes.get("verb"), attributes.get("resource"), attributes.get("namespace"))
        status = {"allowed": key in self.server.allowed}
        body = json.dumps({"apiVersion": review["apiVersion"], "kind": review["kind"], "status": status}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class Kind:
    def __init__(self, name: str, kubeconfig: Path) -> None:
        self.name, self.kubeconfig = name, kubeconfig

    def kubectl(self, *args, stdin=None):
        command = ["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", f"kind-{self.name}", *args]
        result = subprocess.run(command, input=stdin, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise AssertionError(f"{' '.join(command)}: {result.stderr}")
        return result.stdout


@pytest.fixture(scope="module")
def stub():
    server = StubAuthorizer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def cluster(stub):
    work = Path(tempfile.mkdtemp(prefix="bxm-", dir="/tmp"))
    (work / "authz").mkdir()
    (work / "authz" / "webhook.kubeconfig").write_text(WEBHOOK_KUBECONFIG.format(port=stub.server_address[1]))
    (work / "kind.yaml").write_text(KIND_CONFIG.format(authz=work / "authz"))
    kind = Kind(f"bxm-{secrets.token_hex(3)}", work / "kubeconfig")
    create = [
        "kind",
        "create",
        "cluster",
        "--name",
        kind.name,
        "--image",
        NODE_IMAGE,
        "--config",
        str(work / "kind.yaml"),
        "--kubeconfig",
        str(kind.kubeconfig),
        "--wait",
        "120s",
    ]
    try:
        subprocess.run(create, check=True, capture_output=True, text=True, timeout=300)
        names = {key: f"bxm-{key}" for key in ("sys", "stg", "hook")}
        tenants = {"ta": [names["stg"]]}
        manifests = generate_manifests(CATALOG, identity_for(names), tenants)
        for namespace in (names["stg"], names["hook"]):
            kind.kubectl("create", "namespace", namespace)
        kind.kubectl("apply", "-f", "-", stdin=render(manifests))
        time.sleep(SETTLE_SECONDS)
        for account, file in (("effector", "effector"), ("effector-audit", "audit")):
            token = kind.kubectl("-n", names["sys"], "create", "token", account, "--duration=10m").strip()
            (work / file).write_text(token)
            os.chmod(work / file, 0o600)
        view = json.loads(kind.kubectl("config", "view", "--minify", "--raw", "-o", "json"))
        entry = view["clusters"][0]["cluster"]
        (work / "ca.crt").write_bytes(base64.b64decode(entry["certificate-authority-data"]))
        url = urllib.parse.urlsplit(entry["server"])
        details = {"host": url.hostname, "port": url.port, "names": names, "tenants": tenants}
        (work / "cluster.json").write_text(json.dumps(details))
        yield {"work": work, **details}
    finally:
        subprocess.run(
            ["kind", "delete", "cluster", "--name", kind.name, "--kubeconfig", str(kind.kubeconfig)],
            capture_output=True,
            timeout=300,
        )
        shutil.rmtree(work)


@pytest.fixture
def allow(stub):
    yield stub.allowed
    stub.allowed.clear()
    time.sleep(CACHE_SECONDS)


def identity_for(names) -> EffectorIdentity:
    return EffectorIdentity(names["sys"], "effector", "kubernetes-admin", names["hook"])


def gke_audit(work: Path, details) -> RbacAudit:
    identity = identity_for(details["names"])
    return RbacAudit(
        PooledTransport(details["host"], details["port"], work / "ca.crt", 4),
        work / "effector",
        work / "audit",
        identity,
        generate_manifests(CATALOG, identity, details["tenants"]),
        details["tenants"],
        CATALOG.operations,
        platform="gke",
    )


@pytest.fixture
def kind_version_as_gke(monkeypatch):
    monkeypatch.setattr(drift, "check_version", lambda platform, version: [])


def test_the_webhook_authorizer_reports_the_pinned_evaluation_error(cluster):
    transport = HttpsTransport(cluster["host"], cluster["port"], cluster["work"] / "ca.crt")
    review = {
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "spec": {"namespace": cluster["names"]["stg"]},
    }
    headers = {
        "Authorization": f"Bearer {(cluster['work'] / 'effector').read_text()}",
        "Content-Type": "application/json",
    }
    status, data = transport.request(
        "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", headers, json.dumps(review).encode()
    )
    assert status == 201
    result = json.loads(data)["status"]
    assert result["incomplete"] is True
    assert result["evaluationError"] == PINNED_ERROR, "the pinned GKE error no longer matches: stop and re-decide"


def test_the_pinned_incomplete_review_passes_the_gke_drift_check(cluster, kind_version_as_gke):
    assert gke_audit(cluster["work"], cluster).check() == []


def test_a_dangerous_action_the_managed_authorizer_allows_is_drift(cluster, kind_version_as_gke, allow):
    allow.add((service_account_user(cluster["names"]["sys"], "effector"), "get", "secrets", None))
    time.sleep(CACHE_SECONDS)
    problems = gke_audit(cluster["work"], cluster).check()
    assert problems == ["effector may get core secrets cluster-wide, a dangerous action outside the generated set"]


def test_a_refusal_recorded_before_a_sigkill_survives_in_the_docket(cluster, allow):
    allow.add((service_account_user(cluster["names"]["sys"], "effector"), "get", "secrets", None))
    time.sleep(CACHE_SECONDS)
    docket = Path(tempfile.mkdtemp(prefix="bxd-", dir="/tmp"))
    try:
        child = subprocess.run(
            [sys.executable, __file__, str(cluster["work"]), str(docket)],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)},
        )
        assert child.returncode == -signal.SIGKILL, child.stderr
        assert "acked refuse rbac_unverified" in child.stdout
        from agent_bailiff.docket.report import RecordFilter, verify_records

        lines = []
        report = verify_records(docket / "docket.log", writers(), RecordFilter(), lines.append)
        assert (report.ok, report.entries) == (True, 1)
        [line] = lines
        assert (line.record.entry.decision, line.record.entry.reason) == ("refuse", "rbac_unverified")
        assert line.record.entry.performed is False
    finally:
        shutil.rmtree(docket)


def writers():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return {"effector.homelab": {"effector-1": Ed25519PrivateKey.from_private_bytes(DOCKET_SEED).public_key()}}


DOCKET_SEED = bytes(range(40, 72))


def refuse_then_die(work: Path, docket: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from test_docket import RunningSink
    from test_effector import CONFIG, NOW, release_for, scale_params

    from agent_bailiff.docket import DocketClient, DocketSink
    from agent_bailiff.effector.drift import RbacDrift
    from agent_bailiff.effector.kubernetes import KubernetesClient
    from agent_bailiff.effector.release import ReleaseCheck
    from agent_bailiff.effector.server import Effector, EffectorConfig

    drift.check_version = lambda platform, version: []
    details = json.loads((work / "cluster.json").read_text())
    gate = RbacGate(gke_audit(work, details), lambda: NOW + 2)
    try:
        gate.verify()
    except RbacDrift:
        pass
    (docket / "state").mkdir(mode=0o700)
    RunningSink(DocketSink(docket / "docket.log", docket / "s" / "d.sock", writers(), allowed_uids={os.getuid()}))
    client = DocketClient(
        docket / "s" / "d.sock",
        "effector.homelab",
        "effector-1",
        Ed25519PrivateKey.from_private_bytes(DOCKET_SEED),
        sink_uid=os.getuid(),
        state_dir=docket / "state",
    )

    class KillAfterAck:
        def append(self, entry):
            client.append(entry)
            print("acked", entry.decision, entry.reason, flush=True)
            os.kill(os.getpid(), signal.SIGKILL)

    kubernetes = KubernetesClient(HttpsTransport(details["host"], details["port"], work / "ca.crt"), work / "effector")
    test_catalog = OperationCatalog.load(
        Path(__file__).resolve().parent.parent / "agent_bailiff" / "effector" / "catalogs" / "kubernetes.json"
    )
    effector = Effector(
        EffectorConfig("effector.homelab", "effector.homelab"),
        test_catalog,
        ReleaseCheck(CONFIG, test_catalog, NOW - 1),
        kubernetes,
        type("Running", (), {"suspended": False})(),
        KillAfterAck(),
        gate,
    )
    effector.call(scale_params(), release_for(), NOW + 2)
    print("survived", flush=True)


if __name__ == "__main__":
    refuse_then_die(Path(sys.argv[1]), Path(sys.argv[2]))
