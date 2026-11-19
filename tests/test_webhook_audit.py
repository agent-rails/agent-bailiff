import copy
import json

from test_effector import CATALOG

from agent_bailiff.webhook.audit import PROTECTED_REVIEWS, WebhookAudit, _path
from agent_bailiff.webhook.manifests import generate_manifests


class FakeApi:
    def __init__(self, manifests):
        self.objects = {_path(item): copy.deepcopy(item) for item in manifests["items"]}
        self.allowed = False
        self.reviews = []

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
