from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from typing import Any

from agent_bailiff.effector.kubernetes import Transport
from agent_bailiff.webhook.guard import NAMESPACE_GUARD, REGISTRATION_GUARD

NAME = "bailiff-release-webhook"
CONTAINER_DEFAULTS = {
    "terminationMessagePath": "/dev/termination-log",
    "terminationMessagePolicy": "File",
}
POD_DEFAULTS = {
    "dnsPolicy": "ClusterFirst",
    "enableServiceLinks": True,
    "preemptionPolicy": "PreemptLowerPriority",
    "restartPolicy": "Always",
    "schedulerName": "default-scheduler",
    "serviceAccountName": "default",
    "terminationGracePeriodSeconds": 30,
}
DEPLOYMENT_DEFAULTS = {"progressDeadlineSeconds": 600, "revisionHistoryLimit": 10}
PROBE_DEFAULTS = {"failureThreshold": 3, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 1}
PORT_DEFAULTS = {"protocol": "TCP"}
SCHEDULED_TOLERATIONS = [
    {"effect": "NoExecute", "key": "node.kubernetes.io/not-ready", "operator": "Exists", "tolerationSeconds": 300},
    {"effect": "NoExecute", "key": "node.kubernetes.io/unreachable", "operator": "Exists", "tolerationSeconds": 300},
]
REQUIRED_KINDS = (
    "ConfigMap",
    "Deployment",
    "PodDisruptionBudget",
    "Service",
    "ValidatingAdmissionPolicy",
    "ValidatingAdmissionPolicy",
    "ValidatingAdmissionPolicyBinding",
    "ValidatingAdmissionPolicyBinding",
    "ValidatingWebhookConfiguration",
)
POLICY_KINDS = ("ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding")
WRITE_VERBS = ("create", "update", "patch", "delete", "deletecollection")
PROTECTED_REVIEWS: tuple[tuple[str, str, str | None, bool, str | None, tuple[str, ...]], ...] = (
    ("admissionregistration.k8s.io", "validatingwebhookconfigurations", None, False, NAME, WRITE_VERBS),
    ("", "namespaces", None, False, "<namespace>", WRITE_VERBS),
    ("apps", "deployments", None, True, NAME, WRITE_VERBS),
    ("apps", "deployments", "scale", True, NAME, ("update", "patch")),
    ("policy", "poddisruptionbudgets", None, True, NAME, WRITE_VERBS),
    ("", "services", None, True, NAME, WRITE_VERBS),
    ("", "configmaps", None, True, NAME + "-pins", WRITE_VERBS),
    ("", "secrets", None, True, NAME + "-tls", WRITE_VERBS + ("get", "list", "watch")),
    ("", "pods", None, True, None, ("create", "update", "patch")),
    ("", "pods", "status", True, None, ("update", "patch")),
    ("", "pods", "portforward", True, None, ("create", "get")),
    ("", "serviceaccounts", "token", True, None, ("create",)),
    ("apps", "replicasets", None, True, None, ("create", "update", "patch")),
    ("apps", "statefulsets", None, True, None, ("create",)),
    ("apps", "daemonsets", None, True, None, ("create",)),
    ("batch", "jobs", None, True, None, ("create",)),
    ("batch", "cronjobs", None, True, None, ("create",)),
    ("", "replicationcontrollers", None, True, None, ("create",)),
    ("rbac.authorization.k8s.io", "roles", None, True, None, ("create", "update", "patch")),
    ("rbac.authorization.k8s.io", "rolebindings", None, True, None, ("create", "update", "patch")),
    ("", "pods", "exec", True, None, ("create", "get")),
    ("", "nodes", "proxy", False, None, ("create", "get")),
    ("", "pods", "attach", True, None, ("create", "get")),
    ("", "pods", "ephemeralcontainers", True, None, ("update", "patch")),
    ("discovery.k8s.io", "endpointslices", None, True, None, ("create", "update", "patch")),
    ("", "endpoints", None, True, None, ("create", "update", "patch")),
    ("admissionregistration.k8s.io", "mutatingwebhookconfigurations", None, False, None, ("create", "update", "patch")),
    ("admissionregistration.k8s.io", "mutatingadmissionpolicies", None, False, None, ("create", "update", "patch")),
    (
        "admissionregistration.k8s.io",
        "mutatingadmissionpolicybindings",
        None,
        False,
        None,
        ("create", "update", "patch"),
    ),
    *(
        ("admissionregistration.k8s.io", resource, None, False, guard, WRITE_VERBS)
        for resource in ("validatingadmissionpolicies", "validatingadmissionpolicybindings")
        for guard in (NAMESPACE_GUARD, REGISTRATION_GUARD)
    ),
)


def _contains(expected: object, actual: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _contains(value, actual[key]) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(_contains(left, right) for left, right in zip(expected, actual, strict=True))
        )
    return expected == actual


def _security_drift(kind: str, expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    if kind == "ValidatingWebhookConfiguration":
        # Extra selectors, rules or conditions can silently take bailiff writes
        # out of the webhook's scope, so this list must match exactly.
        expected_webhooks = copy.deepcopy(expected.get("webhooks"))
        actual_webhooks = copy.deepcopy(actual.get("webhooks"))
        if not isinstance(expected_webhooks, list) or not isinstance(actual_webhooks, list):
            return True
        # Kubernetes defaults omitted selectors to empty objects on create.
        for expected_webhook, actual_webhook in zip(expected_webhooks, actual_webhooks, strict=False):
            if not isinstance(expected_webhook, dict) or not isinstance(actual_webhook, dict):
                return True
            for selector in ("namespaceSelector", "objectSelector"):
                if selector not in expected_webhook and actual_webhook.get(selector) == {}:
                    actual_webhook.pop(selector)
        return expected_webhooks != actual_webhooks
    if kind in POLICY_KINDS:
        return bool(expected["spec"] != actual.get("spec"))
    if kind == "ConfigMap":
        return expected.get("data") != actual.get("data")
    if kind == "Service":
        spec = actual.get("spec")
        if not isinstance(spec, dict):
            return True
        return (
            spec.get("selector") != expected["spec"]["selector"]
            or spec.get("type", "ClusterIP") != "ClusterIP"
            or bool(spec.get("externalIPs"))
            or bool(spec.get("externalName"))
            or bool(spec.get("loadBalancerClass"))
            or spec.get("publishNotReadyAddresses", False) is not False
        )
    if kind != "Deployment":
        return False
    expected_spec = expected.get("spec")
    actual_spec = actual.get("spec")
    if not isinstance(expected_spec, dict) or not isinstance(actual_spec, dict):
        return True
    if any(key not in expected_spec and value != DEPLOYMENT_DEFAULTS.get(key) for key, value in actual_spec.items()):
        return True
    expected_template = expected_spec.get("template")
    actual_template = actual_spec.get("template")
    if not isinstance(expected_template, dict) or not isinstance(actual_template, dict):
        return True
    expected_pod = expected_template.get("spec")
    actual_pod = actual_template.get("spec")
    if not isinstance(expected_pod, dict) or not isinstance(actual_pod, dict):
        return True
    return _pod_spec_drift(expected_pod, actual_pod)


def _without_defaults(
    actual: Mapping[str, Any], expected: Mapping[str, Any], defaults: Mapping[str, Any]
) -> dict[str, Any]:
    return {key: value for key, value in actual.items() if key in expected or value != defaults.get(key)}


def _normalized_container(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    container = _without_defaults(copy.deepcopy(dict(actual)), expected, CONTAINER_DEFAULTS)
    for probe in ("readinessProbe", "livenessProbe", "startupProbe"):
        if isinstance(container.get(probe), dict) and isinstance(expected.get(probe), dict):
            container[probe] = _without_defaults(container[probe], expected[probe], PROBE_DEFAULTS)
    ports = container.get("ports")
    expected_ports = expected.get("ports")
    if isinstance(ports, list) and isinstance(expected_ports, list) and len(ports) == len(expected_ports):
        container["ports"] = [
            _without_defaults(port, expected_port, PORT_DEFAULTS) if isinstance(port, dict) else port
            for port, expected_port in zip(ports, expected_ports, strict=True)
        ]
    return container


def _pod_spec_drift(expected_pod: Mapping[str, Any], actual_pod: Mapping[str, Any]) -> bool:
    pod = _without_defaults(copy.deepcopy(dict(actual_pod)), expected_pod, POD_DEFAULTS)
    expected_containers = expected_pod.get("containers")
    containers = pod.get("containers")
    if not isinstance(expected_containers, list) or not isinstance(containers, list):
        return True
    if len(expected_containers) != len(containers):
        return True
    if not all(isinstance(container, dict) for container in containers):
        return True
    pod["containers"] = [
        _normalized_container(container, expected_container)
        for container, expected_container in zip(containers, expected_containers, strict=True)
    ]
    expected_volumes = expected_pod.get("volumes")
    volumes = pod.get("volumes")
    if not isinstance(expected_volumes, list) or not isinstance(volumes, list):
        return True
    if len(expected_volumes) != len(volumes) or not all(isinstance(volume, dict) for volume in volumes):
        return True
    for expected_volume, volume in zip(expected_volumes, volumes, strict=True):
        for source in ("configMap", "secret"):
            expected_source = expected_volume.get(source)
            actual_source = volume.get(source)
            if (
                isinstance(expected_source, dict)
                and isinstance(actual_source, dict)
                and "defaultMode" not in expected_source
                and actual_source.get("defaultMode") == 420
            ):
                actual_source.pop("defaultMode")
    return pod != expected_pod


def _unscheduled_pod_spec(spec: Mapping[str, Any]) -> dict[str, Any] | None:
    unscheduled = dict(spec)
    if not isinstance(unscheduled.pop("nodeName", ""), str):
        return None
    if unscheduled.pop("priority", 0) != 0:
        return None
    if unscheduled.pop("serviceAccount", spec.get("serviceAccountName")) != spec.get("serviceAccountName"):
        return None
    if unscheduled.pop("tolerations", SCHEDULED_TOLERATIONS) != SCHEDULED_TOLERATIONS:
        return None
    pull_secrets = unscheduled.pop("imagePullSecrets", [])
    if not isinstance(pull_secrets, list) or not all(
        isinstance(secret, dict) and set(secret) == {"name"} and isinstance(secret["name"], str)
        for secret in pull_secrets
    ):
        return None
    return unscheduled


def _is_webhook_pod(pod: Mapping[str, Any], template: Mapping[str, Any], addresses: Sequence[str]) -> bool:
    metadata = pod.get("metadata")
    spec = pod.get("spec")
    status = pod.get("status")
    if not isinstance(metadata, dict) or not isinstance(spec, dict) or not isinstance(status, dict):
        return False
    if not _contains(template["metadata"]["labels"], metadata.get("labels")):
        return False
    unscheduled = _unscheduled_pod_spec(spec)
    expected = template["spec"]
    if unscheduled is None or _pod_spec_drift(expected, unscheduled):
        return False
    pod_ips = {entry.get("ip") for entry in status.get("podIPs") or [] if isinstance(entry, dict)}
    return bool(addresses) and set(addresses) <= pod_ips


def _path(item: Mapping[str, Any]) -> str:
    kind = item["kind"]
    name = item["metadata"]["name"]
    namespace = item["metadata"].get("namespace")
    if kind == "ValidatingWebhookConfiguration":
        return f"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/{name}"
    if kind in POLICY_KINDS:
        plural = (
            "validatingadmissionpolicies"
            if kind == "ValidatingAdmissionPolicy"
            else "validatingadmissionpolicybindings"
        )
        return f"/apis/admissionregistration.k8s.io/v1/{plural}/{name}"
    prefix = f"/namespaces/{namespace}"
    if kind == "Deployment":
        return f"/apis/apps/v1{prefix}/deployments/{name}"
    if kind == "PodDisruptionBudget":
        return f"/apis/policy/v1{prefix}/poddisruptionbudgets/{name}"
    if kind in {"ConfigMap", "Service"}:
        return f"/api/v1{prefix}/{kind.lower()}s/{name}"
    raise ValueError(f"unexpected webhook object kind {kind}")


class WebhookAudit:
    def __init__(
        self,
        transport: Transport,
        token: str,
        manifests: Mapping[str, Any],
        effector_namespace: str,
        effector_account: str,
        synthetic_users: Sequence[str],
        tenant_namespaces: Sequence[str],
    ) -> None:
        self._transport = transport
        self._token = token
        self._manifests = manifests
        self._namespace = effector_namespace
        self._account = effector_account
        self._users = synthetic_users
        self._tenant_namespaces = tenant_namespaces
        if sorted(item["kind"] for item in manifests["items"]) != list(REQUIRED_KINDS):
            raise ValueError(
                "audit needs the full webhook manifest set; render it without --phase in Audit mode "
                "or with --enforce --phase target, never a prepare or register phase"
            )
        namespaces = {item["metadata"].get("namespace") for item in manifests["items"]} - {None}
        if len(namespaces) != 1:
            raise ValueError("webhook manifests must place every namespaced object in one namespace")
        self._webhook_namespace = namespaces.pop()

    def _request(self, method: str, path: str, body: object | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
        status, response = self._transport.request(method, path, headers, data)
        if status not in (200, 201):
            raise RuntimeError(f"webhook audit API returned {status} for {path}")
        result = json.loads(response)
        if not isinstance(result, dict):
            raise RuntimeError("webhook audit API returned a non-object")
        return result

    def check(self) -> list[str]:
        problems: list[str] = []
        if self._webhook_namespace == self._namespace:
            problems.append(
                f"namespace: webhook namespace {self._webhook_namespace} is also the effector namespace; "
                "move the webhook to a dedicated namespace, then rerun audit"
            )
        if self._webhook_namespace in self._tenant_namespaces:
            problems.append(
                f"namespace: webhook namespace {self._webhook_namespace} is also a tenant namespace; "
                "move the webhook to a dedicated namespace, then rerun audit"
            )
        for item in self._manifests["items"]:
            path = _path(item)
            try:
                live = self._request("GET", path)
            except RuntimeError as exc:
                problems.append(str(exc))
                continue
            if item["kind"] == "Deployment":
                problems.extend(self._rollout(live))
                problems.extend(self._serving_endpoints(item["spec"]["template"]))
            fields = {key: item[key] for key in ("spec", "data", "webhooks") if key in item}
            if not _contains(fields, live) or _security_drift(item["kind"], item, live):
                problems.append(
                    f"drift: {item['kind']} {item['metadata'].get('namespace', '<cluster>')}/"
                    f"{item['metadata']['name']} differs from generated manifest; restore the generated object "
                    "or move webhook to Audit mode, investigate, then rerun audit"
                )
        problems.extend(self._access_reviews())
        return problems

    def _rollout(self, live: Mapping[str, Any]) -> list[str]:
        status = live.get("status")
        spec = live.get("spec")
        metadata = live.get("metadata")
        if not isinstance(status, dict) or not isinstance(spec, dict) or not isinstance(metadata, dict):
            return [
                f"rollout: Deployment {self._webhook_namespace}/{NAME} has no status; wait for it, then rerun audit"
            ]
        replicas = spec.get("replicas")
        counts = [status.get(field) for field in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas")]
        if status.get("observedGeneration") != metadata.get("generation") or any(count != replicas for count in counts):
            return [
                f"rollout: Deployment {self._webhook_namespace}/{NAME} has not converged on the generated template; "
                "wait for rollout status to complete, then rerun audit"
            ]
        return []

    def _serving_endpoints(self, template: Mapping[str, Any]) -> list[str]:
        try:
            slices = self._request(
                "GET",
                f"/apis/discovery.k8s.io/v1/namespaces/{self._webhook_namespace}/endpointslices"
                f"?labelSelector=kubernetes.io%2Fservice-name%3D{NAME}",
            ).get("items")
        except RuntimeError as exc:
            return [
                f"endpoint: {exc}; grant the audit account list on EndpointSlices with "
                "agent-bailiff effector manifests --webhook-namespace, then rerun audit"
            ]
        if not isinstance(slices, list):
            return ["endpoint: webhook audit API returned EndpointSlices without items; rerun audit"]
        problems: list[str] = []
        ready = 0
        for endpoint_slice in slices:
            slice_name = endpoint_slice.get("metadata", {}).get("name", "<unnamed>")
            for endpoint in endpoint_slice.get("endpoints") or []:
                addresses = endpoint.get("addresses") or []
                reference = endpoint.get("targetRef") or {}
                pod_name = reference.get("name")
                if (
                    reference.get("kind") != "Pod"
                    or reference.get("namespace") != self._webhook_namespace
                    or not isinstance(pod_name, str)
                ):
                    problems.append(
                        f"endpoint: {addresses} in EndpointSlice {self._webhook_namespace}/{slice_name} does not "
                        "target a webhook pod; delete the EndpointSlice, find who created it, then rerun audit"
                    )
                    continue
                try:
                    pod = self._request("GET", f"/api/v1/namespaces/{self._webhook_namespace}/pods/{pod_name}")
                except RuntimeError as exc:
                    problems.append(str(exc))
                    continue
                if not _is_webhook_pod(pod, template, addresses):
                    problems.append(
                        f"endpoint: pod {self._webhook_namespace}/{pod_name} serves the webhook Service but does not "
                        "match the generated pod template; delete the pod, find who created it, then rerun audit"
                    )
                    continue
                if (endpoint.get("conditions") or {}).get("ready") is not False:
                    ready += 1
        if ready == 0:
            problems.append(
                f"endpoint: no ready webhook pod serves {self._webhook_namespace}/{NAME}; in Enforce every bailiff "
                "write is denied and in Audit none is checked; fix the rollout, then rerun audit"
            )
        return problems

    def _access_reviews(self) -> list[str]:
        problems: list[str] = []
        effector = f"system:serviceaccount:{self._namespace}:{self._account}"
        for user in [effector, *self._users]:
            groups = (
                ["system:serviceaccounts", f"system:serviceaccounts:{self._namespace}", "system:authenticated"]
                if user == effector
                else ["system:authenticated"]
            )
            for group, resource, subresource, namespaced, name, verbs in PROTECTED_REVIEWS:
                target = self._webhook_namespace if name == "<namespace>" else name
                for verb in verbs:
                    attributes = {"group": group, "resource": resource, "verb": verb}
                    if subresource:
                        attributes["subresource"] = subresource
                    if namespaced:
                        attributes["namespace"] = self._webhook_namespace
                    if target is not None and verb not in {"create", "deletecollection", "list", "watch"}:
                        attributes["name"] = target
                    review = {
                        "apiVersion": "authorization.k8s.io/v1",
                        "kind": "SubjectAccessReview",
                        "spec": {"user": user, "groups": groups, "resourceAttributes": attributes},
                    }
                    result = self._request("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", review)
                    status = result.get("status")
                    if not isinstance(status, dict) or status.get("allowed") is not False:
                        shown = f"{resource}/{subresource}" if subresource else resource
                        problems.append(
                            f"access: {user} may {verb} {shown}/{target or '*'} in {self._webhook_namespace}; "
                            "remove the grant, keep webhook in Enforce only after a clean audit, then rerun audit"
                        )
        return problems
