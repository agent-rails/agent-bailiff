from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

ADMISSION = "admissionregistration.k8s.io/v1"
NAMESPACE_GUARD = "bailiff-release-webhook-namespace"
REGISTRATION_GUARD = "bailiff-release-webhook-registration"
CONTROLLER_ACCOUNTS = (
    "deployment-controller",
    "disruption-controller",
    "endpoint-controller",
    "endpointslice-controller",
    "ephemeral-volume-controller",
    "generic-garbage-collector",
    "node-controller",
    "pod-garbage-collector",
    "replicaset-controller",
    "resource-claim-controller",
    "root-ca-cert-publisher",
)
CONTROLLERS = (
    "system:kube-controller-manager",
    "system:kube-scheduler",
    *(f"system:serviceaccount:kube-system:{account}" for account in CONTROLLER_ACCOUNTS),
)
DERIVED = ("pods", "replicasets", "endpointslices", "endpoints")
UNUSED_WORKLOADS = ("statefulsets", "daemonsets", "jobs", "cronjobs", "replicationcontrollers")
NAMESPACE_RULES = (
    (
        "",
        (
            "pods",
            "pods/status",
            "pods/ephemeralcontainers",
            "pods/exec",
            "pods/attach",
            "pods/portforward",
            "services",
            "services/status",
            "endpoints",
            "secrets",
            "configmaps",
            "serviceaccounts/token",
            "replicationcontrollers",
        ),
    ),
    (
        "apps",
        (
            "deployments",
            "deployments/scale",
            "deployments/status",
            "replicasets",
            "replicasets/scale",
            "replicasets/status",
            "statefulsets",
            "daemonsets",
        ),
    ),
    ("batch", ("jobs", "cronjobs")),
    ("discovery.k8s.io", ("endpointslices",)),
    ("policy", ("poddisruptionbudgets", "poddisruptionbudgets/status")),
    ("rbac.authorization.k8s.io", ("roles", "rolebindings")),
)


def guard_policies(namespace: str, webhook: str, deployers: Sequence[str], enforce: bool) -> list[dict[str, Any]]:
    if not deployers or any(
        not deployer or any(character in deployer for character in "'\\\n") for deployer in deployers
    ):
        raise ValueError("deployers must be non-empty user names without quotes or backslashes")
    if any(deployer in CONTROLLERS or deployer.startswith("system:node:") for deployer in deployers):
        raise ValueError("a deployer may not be a controller or node identity")
    actions = ["Deny"] if enforce else ["Audit", "Warn"]
    deployer_list = json.dumps(sorted(set(deployers)))
    return [
        _policy(
            NAMESPACE_GUARD,
            [
                {
                    "apiGroups": [group],
                    "apiVersions": ["*"],
                    "operations": ["CREATE", "UPDATE", "CONNECT"],
                    "resources": list(resources),
                    "scope": "Namespaced",
                }
                for group, resources in NAMESPACE_RULES
            ],
            _namespace_variables(deployer_list),
            _namespace_validations(),
        ),
        _binding(
            NAMESPACE_GUARD,
            actions,
            {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
        ),
        _policy(
            REGISTRATION_GUARD,
            [
                {
                    "apiGroups": ["admissionregistration.k8s.io"],
                    "apiVersions": ["*"],
                    "operations": ["CREATE", "UPDATE", "DELETE"],
                    "resources": ["validatingwebhookconfigurations"],
                    "resourceNames": [webhook],
                    "scope": "Cluster",
                }
            ],
            [{"name": "user", "expression": "request.userInfo.username"}],
            [
                {
                    "expression": f"variables.user in {deployer_list}",
                    "messageExpression": (
                        f"{json.dumps(webhook + ' may be changed or deleted only by the deployer; denied for ')}"
                        " + variables.user"
                    ),
                }
            ],
        ),
        _binding(REGISTRATION_GUARD, actions, {}),
    ]


def _namespace_variables(deployer_list: str) -> list[dict[str, str]]:
    return [
        {"name": "user", "expression": "request.userInfo.username"},
        {"name": "resource", "expression": "request.resource.resource"},
        {"name": "subresource", "expression": "request.?subResource.orValue('')"},
        {"name": "status", "expression": "variables.subresource == 'status'"},
        {"name": "controller", "expression": f"variables.user in {json.dumps(list(CONTROLLERS))}"},
        {"name": "deployer", "expression": f"variables.user in {deployer_list}"},
        {
            "name": "ownNode",
            "expression": (
                "variables.resource == 'pods' && variables.status"
                " && variables.user == 'system:node:' + object.spec.?nodeName.orValue('')"
            ),
        },
    ]


def _namespace_validations() -> list[dict[str, str]]:
    checks = (
        ("request.operation != 'CONNECT'", "exec, attach and port-forward are denied in the webhook namespace"),
        ("variables.subresource != 'ephemeralcontainers'", "ephemeral containers are denied in the webhook namespace"),
        (
            f"!(request.operation == 'CREATE' && variables.resource in {json.dumps(list(UNUSED_WORKLOADS))})",
            "only the generated Deployment may run Pods in the webhook namespace",
        ),
        (
            "!variables.status || variables.controller || variables.ownNode",
            "status may be written only by the control plane or the Pod's own node",
        ),
        (
            "!variables.status || variables.resource != 'pods' || variables.ownNode"
            " || (object.status.?podIP.orValue('') == oldObject.status.?podIP.orValue('')"
            " && object.status.?podIPs.orValue([]) == oldObject.status.?podIPs.orValue([]))",
            "only the Pod's own node may set its IPs",
        ),
        (
            f"variables.status || !(variables.resource in {json.dumps(list(DERIVED))}) || variables.controller",
            "Pods, ReplicaSets and endpoints here may be written only by the controller manager",
        ),
        (
            f"variables.status || variables.resource in {json.dumps(list(DERIVED))}"
            " || variables.deployer || variables.controller",
            "the webhook's objects may be changed only by the deployer",
        ),
    )
    return [
        {"expression": expression, "messageExpression": f"{json.dumps(message + '; denied for ')} + variables.user"}
        for expression, message in checks
    ]


def _policy(
    name: str, rules: list[dict[str, Any]], variables: list[dict[str, str]], validations: list[dict[str, str]]
) -> dict[str, Any]:
    return {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "matchPolicy": "Equivalent",
                "namespaceSelector": {},
                "objectSelector": {},
                "resourceRules": rules,
            },
            "variables": variables,
            "validations": validations,
        },
    }


def _binding(name: str, actions: list[str], namespace_selector: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {
            "policyName": name,
            "validationActions": actions,
            "matchResources": {
                "matchPolicy": "Equivalent",
                "namespaceSelector": namespace_selector,
                "objectSelector": {},
            },
        },
    }
