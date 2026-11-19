from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_bailiff.effector.catalog import (
    LABEL,
    RESTART_OP,
    RESTARTED_AT,
    CatalogError,
    CatalogOperation,
    OperationCatalog,
)
from agent_bailiff.effector.kubernetes import FIELD_MANAGER, OP_ID_EXTRA, RELEASE_EXTRA, TRACE_EXTRA, USER_PREFIX

GENERATED_LABEL = "bailiff.dev/generated"
LABELS = {"app.kubernetes.io/managed-by": "agent-bailiff", GENERATED_LABEL: "true"}
RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION = "admissionregistration.k8s.io/v1"
OP_ID_PATTERN = "^[A-Za-z0-9_-]{43}$"
IMPERSONATE = "impersonate:user-info"
RBAC_WRITE_RESOURCES = ("rolebindings", "clusterrolebindings", "roles", "clusterroles")
AUDIT_SUFFIX = "-audit"
DEPLOYMENT_SPEC_FIELDS = (
    "minReadySeconds",
    "paused",
    "progressDeadlineSeconds",
    "replicas",
    "revisionHistoryLimit",
    "selector",
    "strategy",
    "template",
)
DEPLOYMENT_FIELDS = ("apiVersion", "kind", "metadata", "spec", "status")
POD_TEMPLATE_FIELDS = ("metadata", "spec")
OBJECT_META_FIELDS = (
    "annotations",
    "creationTimestamp",
    "deletionGracePeriodSeconds",
    "deletionTimestamp",
    "finalizers",
    "generateName",
    "generation",
    "labels",
    "managedFields",
    "name",
    "namespace",
    "ownerReferences",
    "resourceVersion",
    "selfLink",
    "uid",
)
SERVER_OWNED_META = ("generation", "managedFields", "resourceVersion")
AUDIT_RULES = [
    {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["list"]},
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": sorted(RBAC_WRITE_RESOURCES), "verbs": ["list"]},
    {
        "apiGroups": ["admissionregistration.k8s.io"],
        "resources": ["validatingadmissionpolicies", "validatingadmissionpolicybindings"],
        "verbs": ["list"],
    },
    {"apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"]},
    {
        "apiGroups": ["admissionregistration.k8s.io"],
        "resources": ["validatingwebhookconfigurations"],
        "resourceNames": ["bailiff-release-webhook"],
        "verbs": ["get"],
    },
    {
        "apiGroups": ["apps"],
        "resources": ["deployments"],
        "resourceNames": ["bailiff-release-webhook"],
        "verbs": ["get"],
    },
    {
        "apiGroups": ["policy"],
        "resources": ["poddisruptionbudgets"],
        "resourceNames": ["bailiff-release-webhook"],
        "verbs": ["get"],
    },
    {
        "apiGroups": [""],
        "resources": ["services", "configmaps"],
        "resourceNames": ["bailiff-release-webhook", "bailiff-release-webhook-pins"],
        "verbs": ["get"],
    },
]
WEBHOOK_AUDIT_ROLE = "bailiff-release-webhook-audit"
WEBHOOK_AUDIT_RULES = [
    {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
    {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["list"]},
]


@dataclass(frozen=True)
class EffectorIdentity:
    namespace: str
    service_account: str
    applier: str
    webhook_namespace: str

    @property
    def audit_account(self) -> str:
        return self.service_account + AUDIT_SUFFIX


def synthetic_user(tenant: str, identity: str) -> str:
    return f"{USER_PREFIX}:{tenant}:{identity}"


def generate_manifests(
    catalog: OperationCatalog, effector: EffectorIdentity, tenants: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    check_inputs(effector, tenants)
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
                    "resources": [
                        f"userextras/{OP_ID_EXTRA}",
                        f"userextras/{TRACE_EXTRA}",
                        f"userextras/{RELEASE_EXTRA}",
                    ],
                    "verbs": [IMPERSONATE],
                },
            ],
        ),
        _binding("ClusterRoleBinding", "bailiff-effector-impersonate", None, "ClusterRole", [subject]),
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": _metadata(effector.audit_account, effector.namespace),
        },
        _cluster_role("bailiff-effector-audit", AUDIT_RULES),
        _binding(
            "ClusterRoleBinding",
            "bailiff-effector-audit",
            None,
            "ClusterRole",
            [{"kind": "ServiceAccount", "name": effector.audit_account, "namespace": effector.namespace}],
        ),
    ]
    items.append(_role(WEBHOOK_AUDIT_ROLE, effector.webhook_namespace, WEBHOOK_AUDIT_RULES))
    items.append(
        _binding(
            "RoleBinding",
            WEBHOOK_AUDIT_ROLE,
            effector.webhook_namespace,
            "Role",
            [{"kind": "ServiceAccount", "name": effector.audit_account, "namespace": effector.namespace}],
        )
    )
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
    items.extend(_guard_policy(operations, tenants))
    for operation in operations:
        if operation.call.body_argument is not None:
            items.extend(_range_policy(operation))
        if operation.call.restarts:
            items.extend(_restart_policy(operation))
    items.extend(_binding_policy(effector))
    return {"apiVersion": "v1", "kind": "List", "items": items}


def render(manifests: Mapping[str, Any]) -> str:
    return json.dumps(manifests, indent=2, sort_keys=True) + "\n"


def reserved_namespace(namespace: str) -> bool:
    return namespace == "default" or namespace.startswith("kube-")


def check_inputs(effector: EffectorIdentity, tenants: Mapping[str, Sequence[str]]) -> None:
    for value in (effector.namespace, effector.service_account):
        if LABEL.fullmatch(value) is None or len(value) > 63 - len(AUDIT_SUFFIX):
            raise CatalogError(f"{value!r} is not a Kubernetes name")
    if reserved_namespace(effector.namespace):
        raise CatalogError(f"the effector may not run in the reserved namespace {effector.namespace!r}")
    if LABEL.fullmatch(effector.webhook_namespace) is None or reserved_namespace(effector.webhook_namespace):
        raise CatalogError("the release webhook needs a dedicated namespace, not default or kube-*")
    if effector.webhook_namespace == effector.namespace:
        raise CatalogError("the release webhook may not share the effector's namespace")
    if not effector.applier or any(character in effector.applier for character in "'\\\n"):
        raise CatalogError("the applier must be a non-empty user name without quotes or backslashes")
    if not tenants:
        raise CatalogError("at least one tenant is required")
    for tenant, namespaces in tenants.items():
        if LABEL.fullmatch(tenant) is None or len(f"bailiff-{tenant}-scale") > 63:
            raise CatalogError(f"tenant {tenant!r} must be a short Kubernetes name")
        if not namespaces or any(LABEL.fullmatch(namespace) is None for namespace in namespaces):
            raise CatalogError(f"tenant {tenant!r} needs one or more valid namespaces")
        if any(reserved_namespace(namespace) for namespace in namespaces):
            raise CatalogError(f"tenant {tenant!r} may not use default or kube-* namespaces")
        if effector.namespace in namespaces:
            raise CatalogError("the effector's namespace must hold nothing but the effector")
        if effector.webhook_namespace in namespaces:
            raise CatalogError("the release webhook's namespace may not be a tenant namespace")


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


def _guard_policy(operations: Sequence[CatalogOperation], tenants: Mapping[str, Sequence[str]]) -> list[dict[str, Any]]:
    writes = sorted(
        {
            (operation.call.group, operation.call.resource, operation.call.subresource or "", operation.identity)
            for operation in operations
            if operation.call.verb == "patch"
        }
    )
    allowed = " || ".join(
        f"(request.resource.group == '{group}' && request.resource.resource == '{resource}'"
        f" && request.?subResource.orValue('') == '{subresource}' && request.operation == 'UPDATE'"
        f" && request.userInfo.username.endsWith(':{identity}'))"
        for group, resource, subresource, identity in writes
    )
    op_id = (
        f"has(request.userInfo.extra) && '{OP_ID_EXTRA}' in request.userInfo.extra"
        f" && size(request.userInfo.extra['{OP_ID_EXTRA}']) == 1"
        f" && request.userInfo.extra['{OP_ID_EXTRA}'][0].matches('{OP_ID_PATTERN}')"
    )
    owned = " || ".join(
        f"(request.userInfo.username.startsWith('{USER_PREFIX}:{tenant}:')"
        f" && request.namespace in {json.dumps(sorted(set(tenants[tenant])))})"
        for tenant in sorted(tenants)
    )
    policy = {
        "apiVersion": ADMISSION,
        "kind": "ValidatingAdmissionPolicy",
        "metadata": _metadata("bailiff-effector-guard"),
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [{"apiGroups": ["*"], "apiVersions": ["*"], "operations": ["*"], "resources": ["*/*"]}]
            },
            "matchConditions": [_synthetic_condition()],
            "validations": [
                {"expression": op_id, "message": "a synthetic user request must carry exactly one valid op-id"},
                {
                    "expression": allowed or "false",
                    "message": "synthetic users may write only through the catalog's write operations",
                },
                {"expression": owned, "message": "synthetic users may write only in their tenant's namespaces"},
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


def _restart_policy(operation: CatalogOperation) -> list[dict[str, Any]]:
    call = operation.call
    old_annotation_fields: dict[str, Any] = {f"f:{RESTARTED_AT}": {}}
    annotation_fields: dict[str, Any] = {**old_annotation_fields, f"f:{RESTART_OP}": {}}
    old_field_set = {"f:spec": {"f:template": {"f:metadata": {"f:annotations": old_annotation_fields}}}}
    old_field_set_with_map = {
        "f:spec": {"f:template": {"f:metadata": {"f:annotations": {".": {}, **old_annotation_fields}}}}
    }
    field_set = {"f:spec": {"f:template": {"f:metadata": {"f:annotations": annotation_fields}}}}
    owns = json.dumps(field_set, separators=(",", ":"))
    field_set_with_map = {"f:spec": {"f:template": {"f:metadata": {"f:annotations": {".": {}, **annotation_fields}}}}}
    owns_map = json.dumps(field_set_with_map, separators=(",", ":"))
    released = '{"f:spec":{"f:template":{"f:metadata":{"f:annotations":{}}}}}'
    released_map = '{"f:spec":{"f:template":{"f:metadata":{"f:annotations":{".":{}}}}}}'
    others_new = f"object.metadata.?managedFields.orValue([]).filter(m, m.manager != '{FIELD_MANAGER}')"
    others_old = f"oldObject.metadata.?managedFields.orValue([]).filter(m, m.manager != '{FIELD_MANAGER}')"
    restart_only = (
        "({0}.fieldsV1 == {1} || {0}.fieldsV1 == {2} || {0}.fieldsV1 == {3}"
        " || {0}.fieldsV1 == {4} || {0}.fieldsV1 == {5} || {0}.fieldsV1 == {6})"
    )
    shapes = (
        owns,
        owns_map,
        json.dumps(old_field_set, separators=(",", ":")),
        json.dumps(old_field_set_with_map, separators=(",", ":")),
        released,
        released_map,
    )
    old_restart_only, new_restart_only = restart_only.format("o", *shapes), restart_only.format("n", *shapes)
    kept_new = f"{others_new}.filter(n, !{new_restart_only})"
    kept_old = f"{others_old}.filter(o, !{old_restart_only})"
    restart_new = f"{others_new}.filter(n, {new_restart_only})"
    restart_old = f"{others_old}.filter(o, {old_restart_only})"
    slot = (
        "o.manager == n.manager && o.operation == n.operation && o.?subresource == n.?subresource"
        " && o.apiVersion == n.apiVersion && o.fieldsType == n.fieldsType"
    )
    checks = [
        (
            f"object.spec.?{field} == oldObject.spec.?{field}",
            f"a restart may not change spec.{field}",
        )
        for field in DEPLOYMENT_SPEC_FIELDS
        if field != "template"
    ]
    checks.append(
        ("object.spec.template.spec == oldObject.spec.template.spec", "a restart may not change the pod spec")
    )
    checks += [
        (
            f"object.spec.template.metadata.?{field} == oldObject.spec.template.metadata.?{field}",
            f"a restart may not change spec.template.metadata.{field}",
        )
        for field in OBJECT_META_FIELDS
        if field != "annotations"
    ]
    checks += [
        (f"object.metadata.?{field} == oldObject.metadata.?{field}", f"a restart may not change metadata.{field}")
        for field in OBJECT_META_FIELDS
        if field not in SERVER_OWNED_META
    ]
    checks += [
        (
            f"variables.annotations.all(k, k in ['{RESTARTED_AT}', '{RESTART_OP}']"
            " || (k in variables.previous && variables.previous[k] == variables.annotations[k]))"
            f" && variables.previous.all(k, k in ['{RESTARTED_AT}', '{RESTART_OP}'] || k in variables.annotations)",
            "a restart may change only its two pod template annotations",
        ),
        (
            f"'{RESTARTED_AT}' in variables.annotations && '{RESTART_OP}' in variables.annotations"
            f" && variables.annotations['{RESTART_OP}'] == request.userInfo.extra['{OP_ID_EXTRA}'][0]",
            "a restart must bind both annotations to its op-id",
        ),
        (
            f"{kept_new}.size() == {kept_old}.size()"
            f" && {kept_new}.all(n, {kept_new}.filter(x, x == n).size() == {kept_old}.filter(x, x == n).size())"
            f" && {restart_new}.all(n, {others_old}.exists(o, {old_restart_only} && {slot}))"
            f" && {restart_new}.size() <= {restart_old}.size()",
            "a restart may not change other field managers' entries",
        ),
        (
            f"object.metadata.?managedFields.orValue([]).all(m, m.manager != '{FIELD_MANAGER}'"
            " || (m.operation == 'Apply' && !has(m.subresource) && m.apiVersion == 'apps/v1'"
            f" && m.fieldsType == 'FieldsV1' && (m.fieldsV1 == {owns} || m.fieldsV1 == {owns_map})))",
            f"the {FIELD_MANAGER} field manager may own only the two restart pod template annotations",
        ),
    ]
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
                        "resources": [call.resource],
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
            "variables": [
                {"name": "annotations", "expression": "object.spec.template.metadata.?annotations.orValue({})"},
                {"name": "previous", "expression": "oldObject.spec.template.metadata.?annotations.orValue({})"},
            ],
            "validations": [{"expression": expression, "message": message} for expression, message in checks],
        },
    }
    return [policy, _policy_binding(name)]


def _binding_policy(effector: EffectorIdentity) -> list[dict[str, Any]]:
    reaches = (
        f"(s.kind == 'ServiceAccount' && s.namespace == '{effector.namespace}'"
        f" && (s.name == '{effector.service_account}' || s.name == '{effector.audit_account}'))"
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


def parse_tenants(items: Sequence[str]) -> dict[str, list[str]]:
    tenants: dict[str, list[str]] = {}
    for item in items:
        tenant, separator, namespaces = item.partition("=")
        if not separator or tenant in tenants:
            raise CatalogError(f"tenant {item!r} must be tenant=namespace[,namespace...], once per tenant")
        tenants[tenant] = namespaces.split(",")
    return tenants
