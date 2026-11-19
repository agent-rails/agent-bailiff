import copy
import json
import threading
import time

import pytest
from test_effector import CATALOG

from agent_bailiff.webhook import audit as audit_module
from agent_bailiff.webhook import cli as webhook_cli
from agent_bailiff.webhook.audit import PROTECTED_REVIEWS, WebhookAudit, _path
from agent_bailiff.webhook.guard import REGISTRATION_GUARD
from agent_bailiff.webhook.manifests import NAME, generate_manifests


def with_server_defaults(pod_spec):
    pod_spec.update(
        dnsPolicy="ClusterFirst",
        enableServiceLinks=True,
        preemptionPolicy="PreemptLowerPriority",
        restartPolicy="Always",
        schedulerName="default-scheduler",
        serviceAccountName="default",
        terminationGracePeriodSeconds=30,
    )
    for container in pod_spec["containers"]:
        container.update(terminationMessagePath="/dev/termination-log", terminationMessagePolicy="File")
        container["readinessProbe"].update(failureThreshold=3, periodSeconds=10, successThreshold=1, timeoutSeconds=1)
        for port in container["ports"]:
            port["protocol"] = "TCP"
    for volume in pod_spec["volumes"]:
        for source in ("configMap", "secret"):
            if source in volume:
                volume[source]["defaultMode"] = 420
    return pod_spec


def scheduled(pod_spec):
    pod_spec.update(
        nodeName="node-a",
        priority=0,
        serviceAccount="default",
        tolerations=[
            {"effect": "NoExecute", "key": key, "operator": "Exists", "tolerationSeconds": 300}
            for key in ("node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable")
        ],
    )
    return pod_spec


class FakeApi:
    def __init__(self, manifests):
        self.objects = {_path(item): copy.deepcopy(item) for item in manifests["items"]}
        self.allowed = False
        self.reviews = []
        deployment = next(item for item in manifests["items"] if item["kind"] == "Deployment")
        namespace = deployment["metadata"]["namespace"]
        live = self.objects[_path(deployment)]
        live["metadata"]["generation"] = 2
        live["spec"].update(progressDeadlineSeconds=600, revisionHistoryLimit=10)
        with_server_defaults(live["spec"]["template"]["spec"])
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
                "spec": scheduled(with_server_defaults(template["spec"])),
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
    manifests = manifests_in("bailiff-system")
    api = FakeApi(manifests)
    audit = WebhookAudit(
        api, "audit-token", manifests, "bailiff-effector", "effector", ["bailiff:ta:scale"], ["staging"]
    )
    assert audit.check() == []
    service_proxy = 9 * 2
    per_pod = 6 * 2 + 13 * 2
    assert len(api.reviews) == 2 * (
        sum(len(verbs) for *_, verbs in PROTECTED_REVIEWS) + 2 + 3 + service_proxy + 2 * per_pod
    )
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
        deployers=["gitops"],
        enforce=True,
        phase="target",
    )


def test_access_reviews_target_the_webhook_namespace_and_its_attack_surface():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"])
    assert audit.check() == []
    namespaces = {review["resourceAttributes"].get("namespace") for review in api.reviews}
    assert namespaces == {None, "webhook-ns", "kube-system"}
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
    for subresource in ("exec", "attach", "portforward"):
        assert ("pods", subresource, "create") in reviewed
        assert ("pods", subresource, "get") in reviewed
    assert ("nodes", "proxy", "get") in reviewed
    assert ("nodes", "proxy", "create") in reviewed
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
            deployers=["gitops"],
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
        lambda api: api.pod()["spec"].update(hostAliases=[{"ip": "10.9.9.9", "hostnames": ["kubernetes.default"]}]),
        lambda api: api.pod()["spec"].update(dnsPolicy="None", dnsConfig={"nameservers": ["10.9.9.9"]}),
        lambda api: api.pod()["spec"].update(runtimeClassName="attacker"),
        lambda api: api.pod()["spec"].update(hostUsers=True),
        lambda api: api.pod()["spec"].update(serviceAccountName="attacker", serviceAccount="attacker"),
        lambda api: api.pod()["spec"].update(serviceAccount="attacker"),
        lambda api: api.pod()["spec"].update(readinessGates=[{"conditionType": "x"}]),
        lambda api: api.pod()["spec"].update(priority=1000),
        lambda api: api.pod()["spec"]["tolerations"].append({"operator": "Exists"}),
        lambda api: api.pod()["spec"]["volumes"][1]["secret"].update(optional=True),
        lambda api: api.pod()["spec"]["volumes"][0]["configMap"].update(items=[{"key": "x", "path": "webhook.json"}]),
        lambda api: api.pod()["spec"]["volumes"].append({"name": "x", "emptyDir": {}}),
        lambda api: api.pod()["spec"]["containers"][0]["volumeMounts"][0].update(subPath="x"),
        lambda api: api.pod()["spec"]["containers"][0]["volumeMounts"][1].update(mountPropagation="Bidirectional"),
        lambda api: api.pod()["spec"]["containers"][0]["ports"][0].update(hostPort=9443, hostIP="0.0.0.0"),
        lambda api: api.pod()["spec"]["containers"][0]["resources"]["limits"].update({"nvidia.com/gpu": "1"}),
        lambda api: api.pod()["spec"]["containers"][0]["readinessProbe"]["httpGet"].update(host="203.0.113.5"),
        lambda api: api.pod()["spec"]["containers"][0]["readinessProbe"]["httpGet"].update(
            httpHeaders=[{"name": "Host", "value": "x"}]
        ),
        lambda api: api.pod()["spec"]["containers"][0]["readinessProbe"].update(timeoutSeconds=30),
        lambda api: api.pod()["spec"]["containers"][0]["ports"][0].update(protocol="UDP"),
        lambda api: api.pod()["spec"]["affinity"].update(
            nodeAffinity={"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": []}}
        ),
        lambda api: api.pod()["spec"].update(imagePullSecrets=[{"name": "x", "extra": "y"}]),
    ],
)
def test_an_endpoint_that_is_not_a_generated_webhook_pod_is_reported(mutate):
    assert any(problem.startswith("endpoint: ") for problem in audit_problems(mutate))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda spec: spec.update(paused=True),
        lambda spec: spec.update(minReadySeconds=3600),
        lambda spec: spec["template"]["spec"]["volumes"].append({"name": "x", "emptyDir": {}}),
        lambda spec: spec["template"]["spec"].update(runtimeClassName="attacker"),
        lambda spec: spec["template"]["spec"]["containers"][0]["ports"][0].update(hostPort=9443),
    ],
)
def test_a_deployment_that_differs_from_the_generated_one_is_drift(mutate):
    def change(api):
        mutate(_live(api, "/deployments/" + NAME)["spec"])

    assert any(problem.startswith("drift: Deployment ") for problem in audit_problems(change))


def test_image_pull_secrets_from_the_service_account_are_accepted():
    assert audit_problems(lambda api: api.pod()["spec"].update(imagePullSecrets=[{"name": "registry"}])) == []


def test_the_webhook_namespace_as_the_effector_namespace_is_reported():
    manifests = manifests_in("bailiff-system")
    audit = WebhookAudit(FakeApi(manifests), "token", manifests, "bailiff-system", "effector", [], ["staging"])
    assert any("bailiff-system is also the effector namespace" in issue for issue in audit.check())


def test_an_endpoint_slice_list_failure_is_reported():
    problems = audit_problems(lambda api: api.objects.pop(api.slices_path))
    assert any(problem.startswith("endpoint: webhook audit API returned 404") for problem in problems)


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


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("namespace", lambda spec: spec.update(validationActions=["Audit"])),
        ("namespace", lambda spec: spec["matchResources"].update(namespaceSelector={})),
        ("namespace", lambda spec: spec["matchResources"].update(excludeResourceRules=[{"resources": ["pods"]}])),
        ("registration", lambda spec: spec.update(paramRef={"name": "x"})),
    ],
)
def test_a_changed_guard_binding_is_drift(name, mutate):
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"])
    path = f"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/bailiff-release-webhook-{name}"
    mutate(api.objects[path]["spec"])
    assert any(
        f"drift: ValidatingAdmissionPolicyBinding <cluster>/bailiff-release-webhook-{name}" in issue
        for issue in audit.check()
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda spec: spec["validations"].pop(),
        lambda spec: spec["validations"][0].update(expression="true"),
        lambda spec: spec.update(matchConditions=[{"name": "skip", "expression": "false"}]),
        lambda spec: spec["matchConstraints"].update(excludeResourceRules=[{"resources": ["pods"]}]),
        lambda spec: spec.update(failurePolicy="Ignore"),
        lambda spec: spec["variables"][4].update(expression="true"),
    ],
)
def test_a_changed_guard_policy_is_drift(mutate):
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"])
    path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/bailiff-release-webhook-namespace"
    mutate(api.objects[path]["spec"])
    assert any(
        "drift: ValidatingAdmissionPolicy <cluster>/bailiff-release-webhook-namespace" in issue
        for issue in audit.check()
    )


def test_a_missing_guard_is_reported():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"])
    del api.objects[
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/bailiff-release-webhook-registration"
    ]
    assert any("validatingadmissionpolicies/bailiff-release-webhook-registration" in issue for issue in audit.check())


def test_access_reviews_cover_writes_to_the_guards():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"]).check()
    reviewed = {
        (
            review["resourceAttributes"]["resource"],
            review["resourceAttributes"].get("name"),
            review["resourceAttributes"]["verb"],
        )
        for review in api.reviews
    }
    for resource in ("validatingadmissionpolicies", "validatingadmissionpolicybindings"):
        for guard in ("bailiff-release-webhook-namespace", "bailiff-release-webhook-registration"):
            assert (resource, guard, "delete") in reviewed
            assert (resource, guard, "patch") in reviewed


def test_access_reviews_cover_minting_and_impersonating_controller_identities():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    WebhookAudit(api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"]).check()
    reviewed = {
        (
            review["resourceAttributes"].get("namespace"),
            review["resourceAttributes"]["resource"],
            review["resourceAttributes"].get("subresource"),
            review["resourceAttributes"].get("name"),
            review["resourceAttributes"]["verb"],
        )
        for review in api.reviews
    }
    assert ("kube-system", "serviceaccounts", "token", None, "create") in reviewed
    assert ("kube-system", "serviceaccounts", None, None, "create") in reviewed
    assert ("kube-system", "pods", None, None, "create") in reviewed
    assert ("kube-system", "secrets", None, None, "list") in reviewed
    assert (None, "users", None, "system:kube-controller-manager", "impersonate") in reviewed
    assert ("kube-system", "serviceaccounts", None, "replicaset-controller", "impersonate:serviceaccount") in reviewed
    assert (None, "groups", None, "system:nodes", "impersonate") in reviewed
    assert (None, "certificatesigningrequests", "approval", None, "update") in reviewed
    assert (None, "signers", None, "kubernetes.io/kube-apiserver-client-kubelet", "approve") in reviewed


def test_a_cluster_scoped_access_finding_names_cluster_scope():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    api.allowed = True
    problems = WebhookAudit(
        api, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"]
    ).check()
    assert any("nodes/proxy/* in cluster scope" in problem for problem in problems)
    assert any("serviceaccounts/token/* in kube-system" in problem for problem in problems)


def reviewed_with_groups(api):
    return {
        (
            review["resourceAttributes"]["group"],
            review["resourceAttributes"].get("namespace"),
            review["resourceAttributes"]["resource"],
            review["resourceAttributes"].get("subresource"),
            review["resourceAttributes"].get("name"),
            review["resourceAttributes"]["verb"],
        )
        for review in api.reviews
    }


def test_impersonation_reviews_use_the_api_group_each_mode_is_authorized_in():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    assert WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check() == []
    reviewed = reviewed_with_groups(api)
    constrained = "authentication.k8s.io"
    assert ("", None, "users", None, "system:kube-scheduler", "impersonate") in reviewed
    assert (constrained, None, "users", None, "system:kube-scheduler", "impersonate:user-info") in reviewed
    assert ("", "kube-system", "serviceaccounts", None, "replicaset-controller", "impersonate") in reviewed
    assert (
        constrained,
        "kube-system",
        "serviceaccounts",
        None,
        "replicaset-controller",
        "impersonate:serviceaccount",
    ) in reviewed
    assert ("", None, "groups", None, "system:nodes", "impersonate") in reviewed
    assert (constrained, None, "groups", None, "system:nodes", "impersonate:user-info") in reviewed
    assert ("", None, "users", None, None, "impersonate") in reviewed
    assert (constrained, None, "users", None, None, "impersonate:user-info") in reviewed
    assert not any(group == "" and verb.startswith("impersonate:") for group, *_, verb in reviewed)


def test_access_reviews_cover_impersonating_the_deployer_and_the_serving_nodes():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    assert WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check() == []
    reviewed = reviewed_with_groups(api)
    constrained = "authentication.k8s.io"
    assert ("", None, "users", None, "gitops", "impersonate") in reviewed
    assert (constrained, None, "users", None, "gitops", "impersonate:user-info") in reviewed
    assert ("", None, "users", None, "system:node:node-a", "impersonate") in reviewed
    for verb in ("impersonate:arbitrary-node", "impersonate:associated-node"):
        assert (constrained, None, "nodes", None, "node-a", verb) in reviewed
        assert (constrained, None, "nodes", None, None, verb) in reviewed


def test_a_service_account_deployer_is_reviewed_as_a_service_account():
    manifests = generate_manifests(
        namespace="webhook-ns",
        image="example/release@sha256:" + "a" * 64,
        ca_pem=b"-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----\n",
        pins={"catalog_digest": CATALOG.digest},
        catalog=CATALOG,
        deployers=["system:serviceaccount:argocd:applier"],
        enforce=False,
    )
    api = FakeApi(manifests)
    assert WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check() == []
    reviewed = reviewed_with_groups(api)
    assert ("", "argocd", "serviceaccounts", None, "applier", "impersonate") in reviewed
    assert (
        "authentication.k8s.io",
        "argocd",
        "serviceaccounts",
        None,
        "applier",
        "impersonate:serviceaccount",
    ) in reviewed


def test_guards_that_differ_from_the_generated_guards_are_refused():
    manifests = manifests_in("webhook-ns")
    guard = next(item for item in manifests["items"] if item["metadata"]["name"] == REGISTRATION_GUARD)
    guard["spec"]["validations"][0]["expression"] = 'variables.user in ["gitops", "intruder"]'
    with pytest.raises(ValueError, match="guards"):
        WebhookAudit(FakeApi(manifests), "token", manifests, "bailiff-system", "effector", [], ["staging"])


def test_access_reviews_cover_proxying_to_the_webhook_and_watching_kube_system_secrets():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check()
    reviewed = reviewed_with_groups(api)
    for verb in ("create", "get"):
        assert ("", "webhook-ns", "pods", "proxy", None, verb) in reviewed
        for name in (
            NAME,
            f"{NAME}:443",
            f"https:{NAME}:443",
            f"https:{NAME}:",
            f"http:{NAME}:443",
            f":{NAME}:443",
            f":{NAME}:",
        ):
            assert ("", "webhook-ns", "services", "proxy", name, verb) in reviewed
    assert ("", "kube-system", "secrets", None, None, "watch") in reviewed


def test_access_reviews_cover_impersonating_any_group_and_system_masters():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check()
    reviewed = reviewed_with_groups(api)
    for group in (None, "system:masters"):
        assert ("", None, "groups", None, group, "impersonate") in reviewed
        assert ("authentication.k8s.io", None, "groups", None, group, "impersonate:user-info") in reviewed


def test_access_reviews_cover_grants_scoped_to_a_serving_pod():
    manifests = manifests_in("webhook-ns")
    api = FakeApi(manifests)
    WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"]).check()
    reviewed = reviewed_with_groups(api)
    pod = f"{NAME}-abc-1"
    for verb in ("update", "patch"):
        assert ("", "webhook-ns", "pods", None, pod, verb) in reviewed
        assert ("", "webhook-ns", "pods", "status", pod, verb) in reviewed
        assert ("", "webhook-ns", "pods", "ephemeralcontainers", pod, verb) in reviewed
    for verb in ("create", "get"):
        for subresource in ("exec", "attach", "portforward"):
            assert ("", "webhook-ns", "pods", subresource, pod, verb) in reviewed
        for name in (pod, f"{pod}:9443", f"{pod}:https", f"https:{pod}:9443", f"http:{pod}:", f":{pod}:9443"):
            assert ("", "webhook-ns", "pods", "proxy", name, verb) in reviewed
    assert ("", "webhook-ns", "pods", None, pod, "create") not in reviewed


class SlowReviews(FakeApi):
    def __init__(self, manifests, delay=0.0):
        super().__init__(manifests)
        self.delay = delay
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0

    def request(self, method, path, headers, body):
        if method == "GET":
            return super().request(method, path, headers, body)
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.delay)
            return super().request(method, path, headers, body)
        finally:
            with self.lock:
                self.active -= 1


def test_access_reviews_run_concurrently_up_to_the_worker_cap():
    manifests = manifests_in("webhook-ns")
    api = SlowReviews(manifests, delay=0.002)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"], review_workers=4)
    assert audit.check() == []
    assert api.peak == 4


def test_access_review_problems_keep_review_order_under_concurrency():
    manifests = manifests_in("webhook-ns")
    serial = FakeApi(manifests)
    serial.allowed = True
    expected = WebhookAudit(
        serial, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"], review_workers=1
    ).check()
    concurrent = SlowReviews(manifests, delay=0.001)
    concurrent.allowed = True
    problems = WebhookAudit(
        concurrent, "token", manifests, "bailiff-system", "effector", ["bailiff:ta:scale"], ["staging"]
    ).check()
    assert len(expected) == len(serial.reviews)
    assert problems == expected


def test_access_reviews_past_the_deadline_fail_the_audit():
    manifests = manifests_in("webhook-ns")
    api = SlowReviews(manifests, delay=0.05)
    audit = WebhookAudit(
        api, "token", manifests, "bailiff-system", "effector", [], ["staging"], review_workers=2, review_deadline=0.1
    )
    with pytest.raises(RuntimeError, match="access reviews did not finish within 0.1 seconds"):
        audit.check()
    assert len(api.reviews) < 20


class FailingReviews(FakeApi):
    def request(self, method, path, headers, body):
        if method == "GET":
            return super().request(method, path, headers, body)
        return 500, b""


def test_an_access_review_api_error_fails_the_audit():
    manifests = manifests_in("webhook-ns")
    audit = WebhookAudit(FailingReviews(manifests), "token", manifests, "bailiff-system", "effector", [], ["staging"])
    with pytest.raises(RuntimeError, match="webhook audit API returned 500 for /apis/authorization.k8s.io"):
        audit.check()


class ThrottledApi(FakeApi):
    def __init__(self, manifests, throttled, methods=("POST",)):
        super().__init__(manifests)
        self.throttled = throttled
        self.methods = methods
        self.lock = threading.Lock()
        self.throttles = 0

    def request(self, method, path, headers, body):
        if method in self.methods:
            with self.lock:
                if self.throttles < self.throttled:
                    self.throttles += 1
                    return 429, b""
        return super().request(method, path, headers, body)


@pytest.fixture
def fast_retries(monkeypatch):
    monkeypatch.setattr(audit_module, "RETRY_BASE_SECONDS", 0.001)
    monkeypatch.setattr(audit_module, "RETRY_MAX_SECONDS", 0.002)


@pytest.mark.parametrize("methods", [("POST",), ("GET",)])
def test_throttled_requests_are_retried(fast_retries, methods):
    manifests = manifests_in("webhook-ns")
    api = ThrottledApi(manifests, throttled=audit_module.THROTTLE_RETRIES, methods=methods)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"], review_workers=1)
    assert audit.check() == []
    assert api.throttles == audit_module.THROTTLE_RETRIES


def test_a_review_still_throttled_after_every_retry_fails_the_audit(fast_retries):
    manifests = manifests_in("webhook-ns")
    api = ThrottledApi(manifests, throttled=10**6)
    audit = WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"], review_workers=1)
    with pytest.raises(RuntimeError, match="429 for /apis/authorization.k8s.io/v1/subjectaccessreviews after 5 "):
        audit.check()
    assert audit_module.THROTTLE_RETRIES + 1 <= api.throttles <= audit_module.THROTTLE_RETRIES + 2
    assert api.reviews == []


def test_the_review_deadline_stops_retries_that_are_waiting(monkeypatch):
    monkeypatch.setattr(audit_module, "RETRY_BASE_SECONDS", 30.0)
    monkeypatch.setattr(audit_module, "RETRY_MAX_SECONDS", 30.0)
    monkeypatch.setattr(audit_module.random, "uniform", lambda low, high: high)
    manifests = manifests_in("webhook-ns")
    api = ThrottledApi(manifests, throttled=10**6)
    audit = WebhookAudit(
        api, "token", manifests, "bailiff-system", "effector", [], ["staging"], review_workers=2, review_deadline=0.1
    )
    with pytest.raises(RuntimeError, match="access reviews did not finish within 0.1 seconds"):
        audit.check()
    finish = time.monotonic() + 2
    while time.monotonic() < finish and any(
        thread.name.startswith("webhook-audit-review") for thread in threading.enumerate()
    ):
        time.sleep(0.01)
    assert not any(thread.name.startswith("webhook-audit-review") for thread in threading.enumerate())
    assert api.throttles == 2


def test_backoff_grows_with_full_jitter_up_to_the_cap(monkeypatch):
    bounds = []
    monkeypatch.setattr(audit_module.random, "uniform", lambda low, high: bounds.append((low, high)) or 0.0)
    manifests = manifests_in("webhook-ns")
    api = ThrottledApi(manifests, throttled=audit_module.THROTTLE_RETRIES)
    WebhookAudit(api, "token", manifests, "bailiff-system", "effector", [], ["staging"], review_workers=1).check()
    assert bounds == [(0, 0.5), (0, 1.0), (0, 2.0), (0, 4.0), (0, 8.0)]


@pytest.mark.parametrize(
    ("workers", "deadline", "message"),
    [
        (0, 300.0, "review_workers"),
        (-1, 300.0, "review_workers"),
        (True, 300.0, "review_workers"),
        (8, 0, "review_deadline"),
        (8, -1.0, "review_deadline"),
        (8, float("nan"), "review_deadline"),
        (8, float("inf"), "review_deadline"),
        (8, None, "review_deadline"),
    ],
)
def test_review_workers_and_deadline_are_validated(workers, deadline, message):
    manifests = manifests_in("webhook-ns")
    with pytest.raises(ValueError, match=message):
        WebhookAudit(
            FakeApi(manifests),
            "token",
            manifests,
            "bailiff-system",
            "effector",
            [],
            ["staging"],
            review_workers=workers,
            review_deadline=deadline,
        )


def audit_argv(tmp_path, *extra):
    return [
        "audit",
        "--manifest",
        str(tmp_path / "manifest.json"),
        "--kube-host",
        "127.0.0.1",
        "--kube-ca",
        str(tmp_path / "ca.crt"),
        "--token-file",
        str(tmp_path / "token"),
        "--effector-namespace",
        "bailiff-system",
        "--effector-account",
        "effector",
        "--tenant",
        "ta=staging",
        *extra,
    ]


def test_audit_cli_passes_review_workers_and_deadline(tmp_path, monkeypatch):
    seen = {}

    class RecordingAudit:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

        def check(self):
            return []

    monkeypatch.setattr(webhook_cli, "WebhookAudit", RecordingAudit)
    monkeypatch.setattr(webhook_cli, "HttpsTransport", lambda *args: None)
    monkeypatch.setattr(webhook_cli, "read_token", lambda path: "token")
    monkeypatch.setattr(webhook_cli, "_pins", lambda path: {})
    assert webhook_cli.main(audit_argv(tmp_path)) == 0
    assert seen == {"review_workers": 8, "review_deadline": 300.0}
    assert webhook_cli.main(audit_argv(tmp_path, "--review-workers", "2", "--review-deadline", "900")) == 0
    assert seen == {"review_workers": 2, "review_deadline": 900.0}


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (("--review-workers", "0"), "--review-workers must be at least 1"),
        (("--review-deadline", "0"), "--review-deadline must be a positive number of seconds"),
        (("--review-deadline", "nan"), "--review-deadline must be a positive number of seconds"),
    ],
)
def test_audit_cli_refuses_bad_review_settings(tmp_path, capsys, extra, message):
    with pytest.raises(SystemExit) as exited:
        webhook_cli.main(audit_argv(tmp_path, *extra))
    assert exited.value.code == 2
    assert message in capsys.readouterr().err
