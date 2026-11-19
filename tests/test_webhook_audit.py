import copy
import json

import pytest
from test_effector import CATALOG

from agent_bailiff.webhook.audit import PROTECTED_REVIEWS, WebhookAudit, _path
from agent_bailiff.webhook.manifests import NAME, generate_manifests


class FakeApi:
    def __init__(self, manifests):
        self.objects = {_path(item): copy.deepcopy(item) for item in manifests["items"]}
        self.allowed = False
        self.reviews = []
        deployment = next(item for item in manifests["items"] if item["kind"] == "Deployment")
        namespace = deployment["metadata"]["namespace"]
        live = self.objects[_path(deployment)]
        live["metadata"]["generation"] = 2
        live["status"] = {
            "observedGeneration": 2,
            "replicas": 2,
            "updatedReplicas": 2,
            "readyReplicas": 2,
            "availableReplicas": 2,
        }
        endpoints = []
        for index in range(2):
            name = f"{NAME}-abc-{index}"
            ip = f"10.0.0.{index + 1}"
            template = copy.deepcopy(deployment["spec"]["template"])
            self.objects[f"/api/v1/namespaces/{namespace}/pods/{name}"] = {
                "metadata": {"name": name, "namespace": namespace, "labels": template["metadata"]["labels"]},
                "spec": template["spec"],
                "status": {"podIPs": [{"ip": ip}]},
            }
            endpoints.append(
                {
                    "addresses": [ip],
                    "conditions": {"ready": True},
                    "targetRef": {"kind": "Pod", "namespace": namespace, "name": name},
                }
            )
        self.slices_path = (
            f"/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices"
            f"?labelSelector=kubernetes.io%2Fservice-name%3D{NAME}"
        )
        self.objects[self.slices_path] = {"items": [{"metadata": {"name": NAME + "-x"}, "endpoints": endpoints}]}

    def pod(self, index=0):
        return next(value for path, value in self.objects.items() if path.endswith(f"/pods/{NAME}-abc-{index}"))

    def endpoints(self):
        return self.objects[self.slices_path]["items"][0]["endpoints"]

    def request(self, method, path, headers, body):
        if method == "GET":
            return (200, json.dumps(self.objects[path]).encode()) if path in self.objects else (404, b"")
        review = json.loads(body)
        self.reviews.append(review["spec"])
        return 200, json.dumps({"status": {"allowed": self.allowed}}).encode()


def test_drift_and_access_reviews_cover_the_webhook_assets():
    manifests = generate_manifests(
        namespace="bailiff-system",
        image="example/release@sha256:" + "a" * 64,
        ca_pem=b"-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n",
        pins={"catalog_digest": CATALOG.digest},
        catalog=CATALOG,
        enforce=True,
    )
    api = FakeApi(manifests)
    audit = WebhookAudit(api, "audit-token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"])
    assert audit.check() == []
    assert len(api.reviews) == 2 * sum(len(verbs) for *_, verbs in PROTECTED_REVIEWS)
    webhook_path = "/validatingwebhookconfigurations/bailiff-release-webhook"
    webhook = next(path for path in api.objects if path.endswith(webhook_path))
    api.objects[webhook]["webhooks"][0]["namespaceSelector"] = {}
    api.objects[webhook]["webhooks"][0]["objectSelector"] = {}
    assert audit.check() == []  # Kubernetes API-server defaults.
    deployment = next(path for path in api.objects if path.endswith("/deployments/bailiff-release-webhook"))
    api.objects[deployment]["spec"]["template"]["spec"]["containers"][0]["image"] = "other"
    assert any("drift: Deployment bailiff-system/bailiff-release-webhook" in issue for issue in audit.check())
    api.objects[deployment]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
    assert any("drift: Deployment bailiff-system/bailiff-release-webhook" in issue for issue in audit.check())
    api.objects[deployment]["spec"]["template"]["spec"]["hostAliases"] = [{"ip": "127.0.0.1", "hostnames": ["spoof"]}]
    assert any("drift: Deployment bailiff-system/bailiff-release-webhook" in issue for issue in audit.check())
    service = next(path for path in api.objects if path.endswith("/services/bailiff-release-webhook"))
    api.objects[service]["spec"]["publishNotReadyAddresses"] = True
    assert any("drift: Service bailiff-system/bailiff-release-webhook" in issue for issue in audit.check())
    api.objects[webhook]["webhooks"][0]["namespaceSelector"] = {"matchLabels": {"exclude": "bailiff"}}
    assert any(
        "drift: ValidatingWebhookConfiguration <cluster>/bailiff-release-webhook" in issue for issue in audit.check()
    )
    api.allowed = True
    assert any("may patch secrets/bailiff-release-webhook-tls" in issue for issue in audit.check())


def manifests_in(namespace):
    return generate_manifests(
        namespace=namespace,
        image="example/release@sha256:" + "a" * 64,
        ca_pem=b"-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n",
        pins={"catalog_digest": CATALOG.digest},
        catalog=CATALOG,
        enforce=True,
    )


def test_access_reviews_target_the_webhook_namespace_and_its_attack_surface():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"])
    assert audit.check() == []
    namespaces = {review["resourceAttributes"].get("namespace") for review in api.reviews}
    assert namespaces == {None, "webhook-ns"}
    reviewed = {
        (
            review["resourceAttributes"]["resource"],
            review["resourceAttributes"].get("subresource"),
            review["resourceAttributes"]["verb"],
        )
        for review in api.reviews
    }
    assert ("deployments", "scale", "patch") in reviewed
    assert ("pods", None, "create") in reviewed
    assert ("pods", "exec", "create") in reviewed
    assert ("endpointslices", None, "create") in reviewed
    assert ("pods", None, "patch") in reviewed
    for workload in ("replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs", "replicationcontrollers"):
        assert (workload, None, "create") in reviewed
    assert ("rolebindings", None, "create") in reviewed
    namespace_reviews = [review for review in api.reviews if review["resourceAttributes"]["resource"] == "namespaces"]
    assert {
        review["resourceAttributes"]["name"] for review in namespace_reviews if "name" in review["resourceAttributes"]
    } == {"webhook-ns"}


def test_a_service_selector_wider_than_generated_is_drift():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    service = next(path for path in api.objects if path.endswith("/services/bailiff-release-webhook"))
    api.objects[service]["spec"]["selector"]["extra"] = "x"
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"])
    assert any("drift: Service webhook-ns/bailiff-release-webhook" in issue for issue in audit.check())


def test_the_webhook_namespace_as_a_tenant_namespace_is_reported():
    manifests = manifests_in("webhook-ns")
    audit = WebhookAudit(FakeApi(manifests), "token", manifests, "bailiff-system", "effector", [], ["webhook-ns"])
    assert any("webhook namespace webhook-ns is also a tenant namespace" in issue for issue in audit.check())


def test_a_phase_manifest_is_not_an_audit_target():
    for phase in ("prepare", "register"):
        manifests = generate_manifests(
            namespace="webhook-ns",
            image="example/release@sha256:" + "a" * 64,
            ca_pem=b"-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n",
            pins={"catalog_digest": CATALOG.digest},
            catalog=CATALOG,
            enforce=True,
            phase=phase,
        )
        with pytest.raises(ValueError, match="full webhook manifest set"):
            WebhookAudit(FakeApi(manifests_in("webhook-ns")), "token", manifests, "bailiff-system", "e", [], ["s"])


def test_the_webhook_may_not_use_a_reserved_namespace():
    for namespace in ("default", "kube-system"):
        with pytest.raises(ValueError, match="dedicated namespace"):
            manifests_in(namespace)


def audit_problems(mutate):
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    mutate(api)
    return WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check()


def test_a_clean_cluster_has_no_endpoint_or_rollout_problems():
    assert audit_problems(lambda api: None) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda api: api.pod()["spec"]["containers"][0].update(image="attacker/webhook@sha256:" + "b" * 64),
        lambda api: api.pod()["spec"]["containers"][0]["command"].__setitem__(7, "audit"),
        lambda api: api.pod()["spec"]["volumes"][0]["configMap"].update(name="attacker-pins"),
        lambda api: api.pod()["spec"].update(initContainers=[{"name": "x", "image": "x"}]),
        lambda api: api.pod()["spec"].update(hostNetwork=True),
        lambda api: api.pod()["spec"].update(shareProcessNamespace=True),
        lambda api: api.pod()["spec"]["containers"][0].update(args=["--mode", "audit"]),
        lambda api: api.pod()["spec"]["containers"][0].update(env=[{"name": "PYTHONPATH", "value": "/tmp"}]),
        lambda api: api.pod()["spec"]["containers"][0]["securityContext"].update(privileged=True),
        lambda api: api.pod()["metadata"]["labels"].update({"bailiff.dev/webhook-mode": "audit"}),
        lambda api: api.pod()["status"].update(podIPs=[{"ip": "10.9.9.9"}]),
        lambda api: api.endpoints()[0].pop("targetRef"),
        lambda api: api.endpoints()[0]["targetRef"].update(namespace="other"),
    ],
)
def test_an_endpoint_that_is_not_a_generated_webhook_pod_is_reported(mutate):
    assert any(problem.startswith("endpoint: ") for problem in audit_problems(mutate))


def test_no_ready_endpoint_is_reported():
    def unready(api):
        for endpoint in api.endpoints():
            endpoint["conditions"]["ready"] = False

    assert any("no ready webhook pod" in problem for problem in audit_problems(unready))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda api: api.objects[next(p for p in api.objects if p.endswith("/deployments/" + NAME))]["status"].update(
            updatedReplicas=1
        ),
        lambda api: api.objects[next(p for p in api.objects if p.endswith("/deployments/" + NAME))]["status"].update(
            observedGeneration=1
        ),
        lambda api: api.objects[next(p for p in api.objects if p.endswith("/deployments/" + NAME))].pop("status"),
    ],
)
def test_an_unconverged_rollout_is_reported(mutate):
    assert any(problem.startswith("rollout: ") for problem in audit_problems(mutate))


def _live(api, suffix):
    return next(value for path, value in api.objects.items() if path.endswith(suffix))
