import copy
import json
import os
import urllib.parse

import pytest

from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import BASELINE_RULES, RbacAudit, RbacDrift, RbacGate
from agent_bailiff.effector.kubernetes import KubernetesUnavailable
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests
from agent_bailiff.service.init import DEFAULT_CATALOG

IDENTITY = EffectorIdentity("bailiff-system", "effector", "gitops")
TENANTS = {"tenant-a": ["staging"]}
MANIFESTS = generate_manifests(OperationCatalog.load(DEFAULT_CATALOG), IDENTITY, TENANTS)
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


def rules_for(namespace):
    granted = [rule for rule in BASELINE_RULES]
    by_key = {
        (item["kind"], item["metadata"].get("namespace"), item["metadata"]["name"]): item for item in MANIFESTS["items"]
    }
    for item in MANIFESTS["items"]:
        if item["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        if item["subjects"] != [{"kind": "ServiceAccount", "name": "effector", "namespace": "bailiff-system"}]:
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
        if method == "POST":
            namespace = json.loads(body)["spec"]["namespace"]
            status = {
                "resourceRules": rules_for(namespace) + self.extra_rules.get(namespace, []),
                "nonResourceRules": [{"verbs": ["get"], "nonResourceURLs": ["/healthz"]}],
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
    for name, value in (("effector", "effector-token"), ("audit", "audit-token")):
        (tmp_path / name).write_text(value)
        os.chmod(tmp_path / name, 0o600)
    return RbacAudit(api, tmp_path / "effector", tmp_path / "audit", IDENTITY, MANIFESTS)


def test_the_generated_set_with_server_defaults_is_clean(api, audit):
    assert audit.check() == []
    reviews = [auth for method, _, auth in api.requests if method == "POST"]
    lists = [auth for method, _, auth in api.requests if method == "GET"]
    assert set(reviews) == {"Bearer effector-token"} and len(reviews) == 4
    assert set(lists) == {"Bearer audit-token"}


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
    assert "outside the generated set in kube-system" in problem


def test_an_incomplete_rules_review_is_drift(api, audit):
    api.incomplete.add("default")
    assert audit.check() == ["the effector's rules in default could not be listed completely"]


def test_every_namespace_page_is_reviewed(api, audit):
    api.page_size = 1
    api.extra_rules["bailiff-system"] = [{"apiGroups": [""], "resources": ["users"], "verbs": ["impersonate"]}]
    assert len(audit.check()) == 1
    assert len([path for method, path, _ in api.requests if method == "POST"]) == 4


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
