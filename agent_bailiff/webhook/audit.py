from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from typing import Any

from agent_bailiff.effector.kubernetes import Transport

NAME = "bailiff-release-webhook"


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
    if kind == "ConfigMap":
        return expected.get("data") != actual.get("data")
    if kind == "Service":
        spec = actual.get("spec")
        if not isinstance(spec, dict):
            return True
        return (
            spec.get("type", "ClusterIP") != "ClusterIP"
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
    expected_template = expected_spec.get("template")
    actual_template = actual_spec.get("template")
    if not isinstance(expected_template, dict) or not isinstance(actual_template, dict):
        return True
    expected_pod = expected_template.get("spec")
    actual_pod = actual_template.get("spec")
    if not isinstance(expected_pod, dict) or not isinstance(actual_pod, dict):
        return True
    pod_defaults = {
        "dnsPolicy": "ClusterFirst",
        "enableServiceLinks": True,
        "preemptionPolicy": "PreemptLowerPriority",
        "restartPolicy": "Always",
        "schedulerName": "default-scheduler",
        "serviceAccountName": "default",
        "terminationGracePeriodSeconds": 30,
    }
    if any(key not in expected_pod and value != pod_defaults.get(key) for key, value in actual_pod.items()):
        return True
    if actual_pod.get("securityContext") != expected_pod.get("securityContext"):
        return True
    for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        if actual_pod.get(field, False) is not False:
            return True
    expected_containers = expected_pod.get("containers")
    actual_containers = actual_pod.get("containers")
    if not isinstance(expected_containers, list) or not isinstance(actual_containers, list):
        return True
    if len(expected_containers) != len(actual_containers):
        return True
    for expected_container, actual_container in zip(expected_containers, actual_containers, strict=True):
        if not isinstance(expected_container, dict) or not isinstance(actual_container, dict):
            return True
        if actual_container.get("securityContext") != expected_container.get("securityContext"):
            return True
        container_defaults = {
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
        }
        if any(
            key not in expected_container and value != container_defaults.get(key)
            for key, value in actual_container.items()
        ):
            return True
        if actual_container.get("volumeMounts") != expected_container.get("volumeMounts"):
            return True
    expected_volumes = expected_pod.get("volumes")
    actual_volumes = actual_pod.get("volumes")
    if not isinstance(expected_volumes, list) or not isinstance(actual_volumes, list):
        return True
    normalized_volumes = copy.deepcopy(actual_volumes)
    for expected_volume, actual_volume in zip(expected_volumes, normalized_volumes, strict=True):
        for source in ("configMap", "secret"):
            expected_source = expected_volume.get(source)
            actual_source = actual_volume.get(source)
            if (
                isinstance(expected_source, dict)
                and isinstance(actual_source, dict)
                and "defaultMode" not in expected_source
                and actual_source.get("defaultMode") == 420
            ):
                actual_source.pop("defaultMode")
    return normalized_volumes != expected_volumes


def _path(item: Mapping[str, Any]) -> str:
    kind = item["kind"]
    name = item["metadata"]["name"]
    namespace = item["metadata"].get("namespace")
    if kind == "ValidatingWebhookConfiguration":
        return f"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/{name}"
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
    ) -> None:
        self._transport = transport
        self._token = token
        self._manifests = manifests
        self._namespace = effector_namespace
        self._account = effector_account
        self._users = synthetic_users

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
        for item in self._manifests["items"]:
            path = _path(item)
            try:
                live = self._request("GET", path)
            except RuntimeError as exc:
                problems.append(str(exc))
                continue
            fields = {key: item[key] for key in ("spec", "data", "webhooks") if key in item}
            if not _contains(fields, live) or _security_drift(item["kind"], item, live):
                problems.append(
                    f"drift: {item['kind']} {item['metadata'].get('namespace', '<cluster>')}/"
                    f"{item['metadata']['name']} differs from generated manifest; restore the generated object "
                    "or move webhook to Audit mode, investigate, then rerun audit"
                )
        problems.extend(self._access_reviews())
        return problems

    def _access_reviews(self) -> list[str]:
        problems: list[str] = []
        targets = [
            ("admissionregistration.k8s.io", "validatingwebhookconfigurations", None, NAME),
            ("", "namespaces", None, self._namespace),
            ("apps", "deployments", self._namespace, NAME),
            ("policy", "poddisruptionbudgets", self._namespace, NAME),
            ("", "services", self._namespace, NAME),
            ("", "configmaps", self._namespace, NAME + "-pins"),
            ("", "secrets", self._namespace, NAME + "-tls"),
        ]
        effector = f"system:serviceaccount:{self._namespace}:{self._account}"
        for user in [effector, *self._users]:
            groups = (
                ["system:serviceaccounts", f"system:serviceaccounts:{self._namespace}", "system:authenticated"]
                if user == effector
                else ["system:authenticated"]
            )
            for group, resource, namespace, name in targets:
                for verb in ("create", "update", "patch", "delete", "deletecollection"):
                    attributes = {"group": group, "resource": resource, "verb": verb}
                    if namespace:
                        attributes["namespace"] = namespace
                    if verb not in {"create", "deletecollection"}:
                        attributes["name"] = name
                    review = {
                        "apiVersion": "authorization.k8s.io/v1",
                        "kind": "SubjectAccessReview",
                        "spec": {"user": user, "groups": groups, "resourceAttributes": attributes},
                    }
                    result = self._request("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", review)
                    status = result.get("status")
                    if not isinstance(status, dict) or status.get("allowed") is not False:
                        problems.append(
                            f"access: {user} may {verb} {resource}/{name}; remove the grant, keep webhook "
                            "in Enforce only after a clean audit, then rerun audit"
                        )
        return problems
