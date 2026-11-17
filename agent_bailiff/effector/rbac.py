from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_bailiff.effector.catalog import LABEL, CatalogError, CatalogOperation, OperationCatalog
from agent_bailiff.effector.kubernetes import OP_ID_EXTRA, TRACE_EXTRA, USER_PREFIX

GENERATED_LABEL = "bailiff.dev/generated"
LABELS = {"app.kubernetes.io/managed-by": "agent-bailiff", GENERATED_LABEL: "true"}
RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION = "admissionregistration.k8s.io/v1"
OP_ID_PATTERN = "^[A-Za-z0-9_-]{43}$"
IMPERSONATE = "impersonate:user-info"
RBAC_WRITE_RESOURCES = ("rolebindings", "clusterrolebindings", "roles", "clusterroles")


@dataclass(frozen=True)
class EffectorIdentity:
    namespace: str
    service_account: str
    applier: str


def synthetic_user(tenant: str, identity: str) -> str:
    return f"{USER_PREFIX}:{tenant}:{identity}"


def generate_manifests(
    catalog: OperationCatalog, effector: EffectorIdentity, tenants: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    _check(effector, tenants)
    operations = catalog.operations
    identities = sorted({operation.identity for operation in operations})
    users = sorted(synthetic_user(tenant, identity) for tenant in tenants for identity in identities)
    namespaces = sorted({namespace for allowed in tenants.values() for namespace in allowed})
    subject = {"kind": "ServiceAccount", "name": effector.service_account, "namespace": effector.namespace}
    items: list[dict[str, Any]] = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": _metadata(effector.namespace)},
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": _metadata(effector.service_account, effector.namespace),
        },
        _cluster_role(
            "bailiff-effector-impersonate",
            [
                {
                    "apiGroups": ["authentication.k8s.io"],
                    "resources": ["users"],
                    "resourceNames": users,
                    "verbs": [IMPERSONATE],
                },
                {
                    "apiGroups": ["authentication.k8s.io"],
                    "resources": [f"userextras/{OP_ID_EXTRA}", f"userextras/{TRACE_EXTRA}"],
                    "verbs": [IMPERSONATE],
                },
            ],
        ),
        _binding("ClusterRoleBinding", "bailiff-effector-impersonate", None, "ClusterRole", [subject]),
    ]
    for namespace in namespaces:
        items.append(_role("bailiff-effector-on", namespace, _rules(operations, "impersonate-on:user-info:")))
        items.append(_binding("RoleBinding", "bailiff-effector-on", namespace, "Role", [subject]))
    for tenant in sorted(tenants):
        for identity in identities:
            owned = [operation for operation in operations if operation.identity == identity]
            name = f"bailiff-{tenant}-{identity}"
            user = {"kind": "User", "name": synthetic_user(tenant, identity), "apiGroup": "rbac.authorization.k8s.io"}
            for namespace in sorted(set(tenants[tenant])):
                items.append(_role(name, namespace, _rules(owned, "")))
                items.append(_binding("RoleBinding", name, namespace, "Role", [user]))
    items.extend(_guard_policy(operations))
    for operation in operations:
        if operation.call.body_argument is not None:
            items.extend(_range_policy(operation))
    items.extend(_binding_policy(effector))
    return {"apiVersion": "v1", "kind": "List", "items": items}


def render(manifests: Mapping[str, Any]) -> str:
    return json.dumps(manifests, indent=2, sort_keys=True) + "\n"


def _check(effector: EffectorIdentity, tenants: Mapping[str, Sequence[str]]) -> None:
    for value in (effector.namespace, effector.service_account):
        if LABEL.fullmatch(value) is None:
            raise CatalogError(f"{value!r} is not a Kubernetes name")
    if not effector.applier or any(character in effector.applier for character in "'\\\n"):
        raise CatalogError("the applier must be a non-empty user name without quotes or backslashes")
    if not tenants:
        raise CatalogError("at least one tenant is required")
    for tenant, namespaces in tenants.items():
        if LABEL.fullmatch(tenant) is None or len(f"bailiff-{tenant}-scale") > 63:
            raise CatalogError(f"tenant {tenant!r} must be a short Kubernetes name")
        if not namespaces or any(LABEL.fullmatch(namespace) is None for namespace in namespaces):
            raise CatalogError(f"tenant {tenant!r} needs one or more valid namespaces")
        if effector.namespace in namespaces:
            raise CatalogError("the effector's namespace must hold nothing but the effector")


def _rules(operations: Sequence[CatalogOperation], prefix: str) -> list[dict[str, Any]]:
    grants: dict[tuple[str, str], set[str]] = {}
    for operation in operations:
        call = operation.call
        resource = f"{call.resource}/{call.subresource}" if call.subresource else call.resource
        grants.setdefault((call.group, resource), set()).add(prefix + call.verb)
    return [
        {"apiGroups": [group], "resources": [resource], "verbs": sorted(verbs)}
        for (group, resource), verbs in sorted(grants.items())
    ]


def _guard_policy(operations: Sequence[CatalogOperation]) -> list[dict[str, Any]]:
    writes = sorted(
        {
            (operation.call.group, operation.call.resource, operation.call.subresource or "", operation.identity)
            for operation in operations
            if operation.call.verb == "patch"
        }
    )
    allowed = " || ".join(
        f"(request.resource.group == '{group}' && request.resource.resource == '{resource}'"
        f" && request.subResource == '{subresource}' && request.operation == 'UPDATE'"
        f" && request.userInfo.username.endsWith(':{identity}'))"
        for group, resource, subresource, identity in writes
    )
    op_id = (
        f"has(request.userInfo.extra) && '{OP_ID_EXTRA}' in request.userInfo.extra"
        f" && size(request.userInfo.extra['{OP_ID_EXTRA}']) == 1"
        f" && request.userInfo.extra['{OP_ID_EXTRA}'][0].matches('{OP_ID_PATTERN}')"
    )
    policy = {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": _metadata("bailiff-effector-guard"),
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {"apiGroups": ["*"], "apiVersions": ["*"], "operations": ["*"], "resources": ["*/*"]}
                ]
            },
            "matchConditions": [_synthetic_condition()],
            "validations": [
                {"expression": op_id, "message": "a synthetic user request must carry exactly one valid op-id"},
                {
                    "expression": allowed or "false",
                    "message": "synthetic users may write only through the catalog's write operations",
                },
            ],
        },
    }
    return [policy, _policy_binding("bailiff-effector-guard")]


def _range_policy(operation: CatalogOperation) -> list[dict[str, Any]]:
    call = operation.call
    argument = operation.argument(call.body_argument or "")
    if argument is None or argument.minimum is None or argument.maximum is None:
        raise CatalogError(f"{operation.name}: the body argument needs a range")
    name = f"bailiff-{operation.name.replace('_', '-')}"
    policy = {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": _metadata(name),
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": [call.group],
                        "apiVersions": ["*"],
                        "operations": ["UPDATE"],
                        "resources": [f"{call.resource}/{call.subresource}" if call.subresource else call.resource],
                    }
                ]
            },
            "matchConditions": [
                _synthetic_condition(),
                {
                    "name": "operation-identity",
                    "expression": f"request.userInfo.username.endsWith(':{operation.identity}')",
                },
            ],
            "validations": [
                {
                    "expression": (
                        f"has(object.spec.replicas) && object.spec.replicas >= {argument.minimum}"
                        f" && object.spec.replicas <= {argument.maximum}"
                    ),
                    "message": f"replicas must be between {argument.minimum} and {argument.maximum}",
                }
            ],
        },
    }
    return [policy, _policy_binding(name)]


def _binding_policy(effector: EffectorIdentity) -> list[dict[str, Any]]:
    reaches = (
        f"(s.kind == 'ServiceAccount' && s.name == '{effector.service_account}'"
        f" && s.namespace == '{effector.namespace}')"
        f" || (s.kind == 'User' && s.name.startsWith('{USER_PREFIX}:'))"
    )
    generated = f"(has({{0}}.metadata.labels) && '{GENERATED_LABEL}' in {{0}}.metadata.labels)"
    expression = (
        f"(!(has(object.subjects) && object.subjects.exists(s, {reaches}))"
        f" && !{generated.format('object')}"
        f" && !(oldObject != null && {generated.format('oldObject')}))"
        f" || request.userInfo.username == '{effector.applier}'"
    )
    policy = {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": _metadata("bailiff-effector-rbac"),
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": ["rbac.authorization.k8s.io"],
                        "apiVersions": ["*"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": list(RBAC_WRITE_RESOURCES),
                    }
                ]
            },
            "validations": [
                {
                    "expression": expression,
                    "message": "only the applier may grant to the effector or synthetic users or change generated RBAC",
                }
            ],
        },
    }
    return [policy, _policy_binding("bailiff-effector-rbac")]


def _synthetic_condition() -> dict[str, str]:
    return {"name": "synthetic-user", "expression": f"request.userInfo.username.startsWith('{USER_PREFIX}:')"}


def _policy_binding(policy: str) -> dict[str, Any]:
    return {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": _metadata(policy),
        "spec": {"policyName": policy, "validationActions": ["Deny"]},
    }


def _metadata(name: str, namespace: str | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name, "labels": dict(LABELS)}
    if namespace is not None:
        metadata["namespace"] = namespace
    return metadata


def _cluster_role(name: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {"apiVersion": RBAC, "kind": "ClusterRole", "metadata": _metadata(name), "rules": rules}


def _role(name: str, namespace: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {"apiVersion": RBAC, "kind": "Role", "metadata": _metadata(name, namespace), "rules": rules}


def _binding(
    kind: str, name: str, namespace: str | None, role_kind: str, subjects: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "apiVersion": RBAC,
        "kind": kind,
        "metadata": _metadata(name, namespace),
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": name},
        "subjects": subjects,
    }
