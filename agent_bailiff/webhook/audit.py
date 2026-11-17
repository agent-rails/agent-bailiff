from __future__ import annotations

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
        return isinstance(actual, list) and len(expected) == len(actual) and all(
            _contains(left, right) for left, right in zip(expected, actual, strict=True)
        )
    return expected == actual


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
        self, transport: Transport, token: str, manifests: Mapping[str, Any],
        effector_namespace: str, effector_account: str, synthetic_users: Sequence[str],
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
        if status != 200:
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
            if not _contains(fields, live):
                problems.append(f"{item['kind']} {item['metadata']['name']} drifted")
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
                if user == effector else ["system:authenticated"]
            )
            for group, resource, namespace, name in targets:
                for verb in ("create", "update", "patch", "delete", "deletecollection"):
                    attributes = {"group": group, "resource": resource, "verb": verb}
                    if namespace:
                        attributes["namespace"] = namespace
                    if verb not in {"create", "deletecollection"}:
                        attributes["name"] = name
                    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                              "spec": {"user": user, "groups": groups, "resourceAttributes": attributes}}
                    result = self._request("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", review)
                    status = result.get("status")
                    if not isinstance(status, dict) or status.get("allowed") is not False:
                        problems.append(f"{user} may {verb} {resource}/{name}")
        return problems
