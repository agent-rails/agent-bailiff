import copy
import json

from test_effector import CATALOG

from agent_bailiff.webhook.audit import WebhookAudit, _path
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
    audit = WebhookAudit(api, "audit-token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"])
    assert audit.check() == []
    assert len(api.reviews) == 70  # two users, seven protected assets, five write verbs
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
    api.objects[webhook]["webhooks"][0]["namespaceSelector"] = {"matchLabels": {"exclude": "bailiff"}}
    assert any(
        "drift: ValidatingWebhookConfiguration <cluster>/bailiff-release-webhook" in issue for issue in audit.check()
    )
    api.allowed = True
    assert any("may patch secrets/bailiff-release-webhook-tls" in issue for issue in audit.check())
