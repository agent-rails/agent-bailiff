import copy
import json
import os
import urllib.parse

import pytest
from test_effector import AUDIT_TOKEN, EFFECTOR_TOKEN

from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import BASELINE_NON_RESOURCE, BASELINE_RULES, RbacAudit, RbacDrift, RbacGate
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

    def request(self, method, path, headers, body):
        self.requests.append((method, path, headers["Authorization"]))
        url = urllib.parse.urlsplit(path)
        query = dict(urllib.parse.parse_qsl(url.query))
        plural = url.path.rsplit("/", 1)[-1]
        if plural in self.status:
            return self.status[plural], b"{}"
        if method == "POST" and plural == "subjectaccessreviews":
            spec = json.loads(body)["spec"]
            attributes = spec["resourceAttributes"]
            key = (spec["user"], attributes["namespace"], attributes["verb"], attributes["resource"])
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
    assert set(access) == {f"Bearer {AUDIT_TOKEN}"} and len(access) == 8
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
    api.sar_overrides[("bailiff:tenant-a:read", "staging", "patch", "deployments")] = True
    assert audit.check() == ["bailiff:tenant-a:read may scale_deployment in staging"]


def test_a_synthetic_user_missing_its_grant_is_drift(api, audit):
    api.sar_overrides[("bailiff:tenant-a:scale", "staging", "patch", "deployments")] = False
    assert audit.check() == ["bailiff:tenant-a:scale may not scale_deployment in staging"]
