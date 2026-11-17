import copy
import json
import os
import urllib.parse

import pytest
from test_effector import AUDIT_TOKEN, EFFECTOR_TOKEN

from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import (
    APPS_SCHEMA_PATH,
    BASELINE_NON_RESOURCE,
    BASELINE_RULES,
    PINNED_REFERENCES,
    PINNED_SCHEMAS,
    RbacAudit,
    RbacDrift,
    RbacGate,
)
from agent_bailiff.effector.kubernetes import KubernetesUnavailable
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests
from agent_bailiff.service.init import DEFAULT_CATALOG

IDENTITY = EffectorIdentity("bailiff-system", "effector", "gitops")
TENANTS = {"tenant-a": ["staging"]}
CATALOG = OperationCatalog.load(DEFAULT_CATALOG)
MANIFESTS = generate_manifests(CATALOG, IDENTITY, TENANTS)
TOKENS = {f"Bearer {EFFECTOR_TOKEN}": "effector", f"Bearer {AUDIT_TOKEN}": "effector-audit"}
PLURALS = {
    "rolebindings": "RoleBinding",
    "clusterrolebindings": "ClusterRoleBinding",
    "roles": "Role",
    "clusterroles": "ClusterRole",
    "validatingadmissionpolicies": "ValidatingAdmissionPolicy",
    "validatingadmissionpolicybindings": "ValidatingAdmissionPolicyBinding",
}


def served(item):
    item = copy.deepcopy(item)
    if item["kind"] == "ValidatingAdmissionPolicy":
        constraints = item["spec"]["matchConstraints"]
        constraints.update({"matchPolicy": "Equivalent", "namespaceSelector": {}, "objectSelector": {}})
        for rule in constraints["resourceRules"]:
            rule["scope"] = "*"
    return item


def apps_schema():
    schemas = {
        name: {"properties": {field: {"type": "string"} for field in fields}} for name, fields in PINNED_SCHEMAS.items()
    }
    for owner, field, target in PINNED_REFERENCES:
        schemas[owner]["properties"][field] = {"default": {}, "allOf": [{"$ref": f"#/components/schemas/{target}"}]}
    return {"components": {"schemas": schemas}}


def rules_for(account, namespace):
    granted = [rule for rule in BASELINE_RULES]
    by_key = {
        (item["kind"], item["metadata"].get("namespace"), item["metadata"]["name"]): item for item in MANIFESTS["items"]
    }
    for item in MANIFESTS["items"]:
        if item["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        if item["subjects"] != [{"kind": "ServiceAccount", "name": account, "namespace": "bailiff-system"}]:
            continue
        scope = item["metadata"].get("namespace")
        if scope not in (None, namespace):
            continue
        granted.extend(by_key[(item["roleRef"]["kind"], scope, item["roleRef"]["name"])]["rules"])
    return granted


class FakeApi:
    def __init__(self, tmp_path):
        self.namespaces = ["default", "kube-system", "staging", "bailiff-system"]
        self.objects = [
            served(item) for item in MANIFESTS["items"] if item["kind"] not in ("Namespace", "ServiceAccount")
        ]
        self.objects.append(
            {
                "kind": "ClusterRoleBinding",
                "metadata": {"name": "system:basic-user"},
                "roleRef": {"kind": "ClusterRole", "name": "system:basic-user"},
                "subjects": [{"kind": "Group", "name": "system:authenticated"}],
            }
        )
        self.extra_rules = {}
        self.audit_extra_rules = {}
        self.extra_non_resource = []
        self.sar_overrides = {}
        self.incomplete = set()
        self.status = {}
        self.page_size = None
        self.requests = []
        self.schema = apps_schema()

    def request(self, method, path, headers, body):
        self.requests.append((method, path, headers["Authorization"]))
        url = urllib.parse.urlsplit(path)
        query = dict(urllib.parse.parse_qsl(url.query))
        if url.path == APPS_SCHEMA_PATH:
            return self.status.get("openapi", 200), json.dumps(self.schema).encode()
        plural = url.path.rsplit("/", 1)[-1]
        if plural in self.status:
            return self.status[plural], b"{}"
        if method == "POST" and plural == "subjectaccessreviews":
            spec = json.loads(body)["spec"]
            attributes = spec["resourceAttributes"]
            key = (
                spec["user"],
                attributes["namespace"],
                attributes["verb"],
                attributes["resource"] + ("/" + attributes["subresource"] if "subresource" in attributes else ""),
            )
            tenant, identity = spec["user"].split(":")[1:]
            allowed = attributes["namespace"] in TENANTS.get(tenant, []) and any(
                operation.identity == identity
                and operation.call.verb == attributes["verb"]
                and operation.call.resource == attributes["resource"]
                and (operation.call.subresource or None) == attributes.get("subresource")
                for operation in CATALOG.operations
            )
            assert spec["groups"] == ["system:authenticated"]
            return 201, json.dumps({"status": {"allowed": self.sar_overrides.get(key, allowed)}}).encode()
        if method == "POST":
            namespace = json.loads(body)["spec"]["namespace"]
            account = TOKENS[headers["Authorization"]]
            extra = (self.extra_rules if account == "effector" else self.audit_extra_rules).get(namespace, [])
            status = {
                "resourceRules": rules_for(account, namespace) + extra,
                "nonResourceRules": list(BASELINE_NON_RESOURCE) + self.extra_non_resource,
                "incomplete": namespace in self.incomplete,
            }
            return 201, json.dumps({"status": status}).encode()
        if plural == "namespaces":
            items = [{"metadata": {"name": name}} for name in self.namespaces]
        else:
            items = [item for item in self.objects if item["kind"] == PLURALS[plural]]
        start = int(query.get("continue") or 0)
        size = self.page_size or len(items) or 1
        page = items[start : start + size]
        token = str(start + size) if start + size < len(items) else ""
        return 200, json.dumps({"items": page, "metadata": {"continue": token}}).encode()

    def find(self, kind, name, namespace=None):
        [item] = [
            item
            for item in self.objects
            if item["kind"] == kind
            and item["metadata"]["name"] == name
            and item["metadata"].get("namespace") == namespace
        ]
        return item


@pytest.fixture
def api(tmp_path):
    return FakeApi(tmp_path)


@pytest.fixture
def audit(api, tmp_path):
    for name, value in (("effector", EFFECTOR_TOKEN), ("audit", AUDIT_TOKEN)):
        (tmp_path / name).write_text(value)
        os.chmod(tmp_path / name, 0o600)
    return RbacAudit(api, tmp_path / "effector", tmp_path / "audit", IDENTITY, MANIFESTS, TENANTS, CATALOG.operations)


def test_the_generated_set_with_server_defaults_is_clean(api, audit):
    assert audit.check() == []
    reviews = [auth for method, path, auth in api.requests if path.endswith("selfsubjectrulesreviews")]
    access = [auth for method, path, auth in api.requests if path.endswith("/subjectaccessreviews")]
    lists = [auth for method, _, auth in api.requests if method == "GET"]
    assert sorted(reviews) == sorted([f"Bearer {AUDIT_TOKEN}"] * 4 + [f"Bearer {EFFECTOR_TOKEN}"] * 4)
    assert set(access) == {f"Bearer {AUDIT_TOKEN}"} and len(access) == 15
    assert set(lists) == {f"Bearer {AUDIT_TOKEN}"}


@pytest.mark.parametrize(
    "rule",
    [
        {"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]},
        {"apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": ["admin"], "verbs": ["impersonate"]},
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["impersonate-on:user-info:delete"]},
        {
            "apiGroups": ["authentication.k8s.io"],
            "resources": ["users"],
            "resourceNames": ["system:admin"],
            "verbs": ["impersonate:user-info"],
        },
    ],
)
def test_a_grant_outside_the_generated_set_in_any_namespace_is_drift(api, audit, rule):
    api.extra_rules["kube-system"] = [rule]
    [problem] = audit.check()
    assert problem.startswith("effector holds a grant outside the generated set in kube-system")


def test_an_incomplete_rules_review_is_drift(api, audit):
    api.incomplete.add("default")
    assert audit.check() == [
        "the rules of effector in default could not be listed completely",
        "the rules of effector-audit in default could not be listed completely",
    ]


def test_every_namespace_page_is_reviewed(api, audit):
    api.page_size = 1
    api.extra_rules["bailiff-system"] = [{"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]}]
    assert len(audit.check()) == 1
    assert len([path for _, path, _ in api.requests if path.endswith("selfsubjectrulesreviews")]) == 8


@pytest.mark.parametrize(
    "subject",
    [
        {"kind": "ServiceAccount", "name": "effector", "namespace": "bailiff-system"},
        {"kind": "ServiceAccount", "name": "effector-audit", "namespace": "bailiff-system"},
        {"kind": "User", "name": "bailiff:tenant-a:scale", "apiGroup": "rbac.authorization.k8s.io"},
    ],
)
def test_a_foreign_binding_reaching_the_effector_or_a_synthetic_user_is_drift(api, audit, subject):
    api.objects.append(
        {
            "kind": "RoleBinding",
            "metadata": {"name": "sneak", "namespace": "kube-system"},
            "roleRef": {"kind": "ClusterRole", "name": "edit"},
            "subjects": [subject],
        }
    )
    assert audit.check() == ["the RoleBinding kube-system/sneak grants to the effector or a synthetic user"]


def test_a_missing_generated_binding_or_policy_is_drift(api, audit):
    api.objects.remove(api.find("RoleBinding", "bailiff-tenant-a-scale", "staging"))
    api.objects.remove(api.find("ValidatingAdmissionPolicyBinding", "bailiff-effector-guard"))
    assert audit.check() == [
        "the generated RoleBinding staging/bailiff-tenant-a-scale is missing",
        "the generated ValidatingAdmissionPolicyBinding bailiff-effector-guard is missing",
    ]


def test_changed_generated_rbac_is_drift(api, audit):
    api.find("Role", "bailiff-tenant-a-scale", "staging")["rules"][0]["verbs"].append("delete")
    api.find("RoleBinding", "bailiff-tenant-a-read", "staging")["subjects"].append({"kind": "Group", "name": "x"})
    api.find("ClusterRole", "bailiff-effector-audit")["aggregationRule"] = {"clusterRoleSelectors": []}
    assert audit.check() == [
        "the generated RoleBinding staging/bailiff-tenant-a-read was changed",
        "the generated Role staging/bailiff-tenant-a-scale was changed",
        "the generated ClusterRole bailiff-effector-audit was changed",
    ]


@pytest.mark.parametrize(
    ("kind", "name", "change"),
    [
        ("ValidatingAdmissionPolicy", "bailiff-scale-deployment", lambda spec: spec.update(failurePolicy="Ignore")),
        ("ValidatingAdmissionPolicy", "bailiff-effector-guard", lambda spec: spec["validations"].pop()),
        (
            "ValidatingAdmissionPolicy",
            "bailiff-effector-rbac",
            lambda spec: spec["matchConstraints"].update(namespaceSelector={"matchLabels": {"a": "b"}}),
        ),
        (
            "ValidatingAdmissionPolicyBinding",
            "bailiff-effector-guard",
            lambda spec: spec.update(validationActions=["Warn"]),
        ),
        (
            "ValidatingAdmissionPolicyBinding",
            "bailiff-scale-deployment",
            lambda spec: spec.update(matchResources={"namespaceSelector": {"matchLabels": {"a": "b"}}}),
        ),
    ],
)
def test_weakened_admission_is_drift(api, audit, kind, name, change):
    change(api.find(kind, name)["spec"])
    assert audit.check() == [f"the generated {kind} {name} was changed"]


def test_an_api_error_fails_the_check(api, audit):
    api.status["rolebindings"] = 403
    with pytest.raises(KubernetesUnavailable):
        audit.check()


class Clock:
    def __init__(self):
        self.now = 1000

    def __call__(self):
        return self.now


def test_the_gate_is_healthy_only_after_a_clean_check_and_while_fresh(api, audit):
    clock = Clock()
    gate = RbacGate(audit, clock, interval=60)
    assert gate.healthy(1000) is False
    gate.verify()
    assert gate.healthy(1000) and gate.healthy(1120)
    assert gate.healthy(1121) is False


def test_drift_or_an_error_makes_the_gate_unhealthy(api, audit):
    gate = RbacGate(audit, Clock(), interval=60)
    gate.verify()
    api.extra_rules["default"] = [{"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]}]
    with pytest.raises(RbacDrift):
        gate.verify()
    assert gate.healthy(1000) is False
    api.extra_rules.clear()
    gate.verify()
    api.status["namespaces"] = 500
    with pytest.raises(RbacDrift, match="the RBAC check failed"):
        gate.verify()
    assert gate.healthy(1000) is False


def test_a_non_resource_grant_outside_the_baseline_is_drift(api, audit):
    api.extra_non_resource.append({"verbs": ["get"], "nonResourceURLs": ["/metrics"]})
    problems = audit.check()
    assert len(problems) == 8 and all("'/metrics'" in problem for problem in problems)


def test_a_non_resource_rule_added_to_a_generated_role_is_drift(api, audit):
    api.find("ClusterRole", "bailiff-effector-audit")["rules"].append({"verbs": ["get"], "nonResourceURLs": ["/logs"]})
    assert audit.check() == ["the generated ClusterRole bailiff-effector-audit was changed"]


def test_a_grant_to_the_audit_account_outside_the_generated_set_is_drift(api, audit):
    api.audit_extra_rules["kube-system"] = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    assert audit.check() == [
        "effector-audit holds a grant outside the generated set in kube-system: ('get', '', 'secrets', None)"
    ]


def test_a_policy_narrowed_to_cluster_scope_is_drift(api, audit):
    api.find("ValidatingAdmissionPolicy", "bailiff-scale-deployment")["spec"]["matchConstraints"]["resourceRules"][0][
        "scope"
    ] = "Cluster"
    assert audit.check() == ["the generated ValidatingAdmissionPolicy bailiff-scale-deployment was changed"]


def test_a_synthetic_user_allowed_outside_its_tenant_or_identity_is_drift(api, audit):
    api.sar_overrides[("bailiff:tenant-a:read", "staging", "patch", "deployments/scale")] = True
    assert audit.check() == ["bailiff:tenant-a:read may scale_deployment in staging"]


def test_a_synthetic_user_missing_its_grant_is_drift(api, audit):
    api.sar_overrides[("bailiff:tenant-a:scale", "staging", "patch", "deployments/scale")] = False
    assert audit.check() == ["bailiff:tenant-a:scale may not scale_deployment in staging"]


def schemas(api):
    return api.schema["components"]["schemas"]


def test_the_restart_schema_is_read_with_the_audit_token(api, audit):
    assert audit.check_restart_schema() == []
    assert ("GET", APPS_SCHEMA_PATH, f"Bearer {AUDIT_TOKEN}") in api.requests


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (
            lambda s: s["io.k8s.api.apps.v1.DeploymentSpec"]["properties"].update(rolloutPolicy={}),
            "the cluster's io.k8s.api.apps.v1.DeploymentSpec fields differ from those the restart policy compares:"
            " added ['rolloutPolicy'], removed []",
        ),
        (
            lambda s: s["io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"]["properties"].pop("generateName"),
            "the cluster's io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta fields differ from those the restart"
            " policy compares: added [], removed ['generateName']",
        ),
        (
            lambda s: s["io.k8s.api.apps.v1.Deployment"]["properties"].update(rolloutHint={}),
            "the cluster's io.k8s.api.apps.v1.Deployment fields differ from those the restart policy compares:"
            " added ['rolloutHint'], removed []",
        ),
        (
            lambda s: s.pop("io.k8s.api.core.v1.PodTemplateSpec"),
            "the cluster serves no io.k8s.api.core.v1.PodTemplateSpec schema",
        ),
        (
            lambda s: s["io.k8s.api.apps.v1.DeploymentSpec"]["properties"].update(template={"type": "object"}),
            "the cluster's io.k8s.api.apps.v1.DeploymentSpec.template is not a io.k8s.api.core.v1.PodTemplateSpec",
        ),
        (
            lambda s: s["io.k8s.api.core.v1.PodTemplateSpec"]["properties"].update(
                metadata={"$ref": "#/components/schemas/io.k8s.api.core.v1.TemplateMeta"}
            ),
            "the cluster's io.k8s.api.core.v1.PodTemplateSpec.metadata is not a"
            " io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        ),
    ],
)
def test_a_deployment_schema_the_restart_policy_does_not_fully_compare_is_drift(api, audit, change, problem):
    change(schemas(api))
    assert audit.check() == []
    assert audit.check_restart_schema()[0] == problem


def test_an_unreadable_schema_fails_the_restart_check(api, audit):
    api.status["openapi"] = 403
    with pytest.raises(KubernetesUnavailable):
        audit.check_restart_schema()


@pytest.mark.parametrize("fault", ["changed", "unreadable"])
def test_a_schema_problem_withdraws_only_restart(api, audit, fault):
    if fault == "changed":
        schemas(api)["io.k8s.api.apps.v1.DeploymentSpec"]["properties"]["rolloutHint"] = {}
    else:
        api.status["openapi"] = 403
    gate = RbacGate(audit, Clock(), interval=60)
    gate.verify()
    assert gate.healthy(1000) is True
    assert gate.restart_healthy(1000) is False


def test_restart_is_healthy_only_while_both_checks_are_fresh(api, audit):
    gate = RbacGate(audit, Clock(), interval=60)
    assert gate.restart_healthy(1000) is False
    gate.verify()
    assert gate.restart_healthy(1000) and gate.restart_healthy(1120)
    assert gate.restart_healthy(1121) is False
    api.status["rolebindings"] = 403
    with pytest.raises(RbacDrift):
        gate.verify()
    assert gate.restart_healthy(1000) is False


def test_a_changed_restart_policy_variable_is_drift(api, audit):
    policy = api.find("ValidatingAdmissionPolicy", "bailiff-restart-deployment")
    policy["spec"]["variables"][0]["expression"] = "{}"
    assert audit.check() == ["the generated ValidatingAdmissionPolicy bailiff-restart-deployment was changed"]
