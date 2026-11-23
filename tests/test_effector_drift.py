import copy
import json
import logging
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
    grants,
)
from agent_bailiff.effector.kubernetes import KubernetesUnavailable, Throttled
from agent_bailiff.effector.platform import DANGEROUS_ACTIONS, VERSION_PATH
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests
from agent_bailiff.service.init import DEFAULT_CATALOG
from agent_bailiff.webhook import manifests as webhook

WEBHOOK_PATH = f"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/{webhook.NAME}"
SERVICE_PATH = f"/api/v1/namespaces/bailiff-webhook/services/{webhook.NAME}"
GKE_ERROR = "webhook authorizer does not support user rule resolution"

IDENTITY = EffectorIdentity("bailiff-system", "effector", "gitops", "bailiff-webhook")
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
        self.tenants = TENANTS
        self.extra_rules = {}
        self.audit_extra_rules = {}
        self.extra_non_resource = []
        self.sar_overrides = {}
        self.self_allowed = set()
        self.self_errors = {}
        self.self_reviews = []
        self.incomplete = set()
        self.evaluation_error = None
        self.status = {}
        self.page_size = None
        self.requests = []
        self.schema = apps_schema()
        self.registration = {
            "webhooks": [
                {
                    "name": webhook.WEBHOOK,
                    "admissionReviewVersions": ["v1"],
                    "failurePolicy": "Fail",
                    "timeoutSeconds": 3,
                    "matchPolicy": "Exact",
                    "namespaceSelector": {},
                    "objectSelector": {},
                    "matchConditions": copy.deepcopy(webhook.MATCH_CONDITIONS),
                    "rules": copy.deepcopy(webhook.RULES),
                    "clientConfig": {
                        "service": {
                            "name": webhook.NAME,
                            "namespace": "bailiff-webhook",
                            "path": webhook.SERVICE_PATH,
                            "port": webhook.SERVICE_PORT,
                        },
                        "caBundle": "Y2E=",
                    },
                }
            ]
        }
        self.service = {"spec": {"selector": {"app.kubernetes.io/name": webhook.NAME, webhook.MODE_LABEL: "enforce"}}}
        self.version = {"gitVersion": "v1.36.5"}
        self.throttled = 0
        self.retry_after = None
        self.closed = False

    def close(self):
        self.closed = True

    def request(self, method, path, headers, body):
        self.requests.append((method, path, headers["Authorization"]))
        if self.throttled:
            self.throttled -= 1
            raise Throttled(self.retry_after)
        url = urllib.parse.urlsplit(path)
        query = dict(urllib.parse.parse_qsl(url.query))
        if url.path == VERSION_PATH:
            return self.status.get("version", 200), json.dumps(self.version).encode()
        if url.path == APPS_SCHEMA_PATH:
            return self.status.get("openapi", 200), json.dumps(self.schema).encode()
        if url.path == WEBHOOK_PATH:
            return self.status.get("webhook", 200), json.dumps(self.registration).encode()
        if url.path == SERVICE_PATH:
            return self.status.get("service", 200), json.dumps(self.service).encode()
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
            allowed = attributes["namespace"] in self.tenants.get(tenant, []) and any(
                operation.identity == identity
                and operation.call.verb == attributes["verb"]
                and operation.call.resource == attributes["resource"]
                and (operation.call.subresource or None) == attributes.get("subresource")
                for operation in CATALOG.operations
            )
            assert spec["groups"] == ["system:authenticated"]
            return 201, json.dumps({"status": {"allowed": self.sar_overrides.get(key, allowed)}}).encode()
        if method == "POST" and plural == "selfsubjectaccessreviews":
            attributes = json.loads(body)["spec"]["resourceAttributes"]
            account = TOKENS[headers["Authorization"]]
            self.self_reviews.append((account, attributes))
            key = (account, attributes.get("namespace"), attributes["verb"], attributes["resource"])
            status = {"allowed": key in self.self_allowed}
            if key in self.self_errors:
                status["evaluationError"] = self.self_errors[key]
            return 201, json.dumps({"status": status}).encode()
        if method == "POST":
            namespace = json.loads(body)["spec"]["namespace"]
            account = TOKENS[headers["Authorization"]]
            extra = (self.extra_rules if account == "effector" else self.audit_extra_rules).get(namespace, [])
            status = {
                "resourceRules": rules_for(account, namespace) + extra,
                "nonResourceRules": list(BASELINE_NON_RESOURCE) + self.extra_non_resource,
                "incomplete": namespace in self.incomplete,
            }
            if namespace in self.incomplete and self.evaluation_error is not None:
                status["evaluationError"] = self.evaluation_error
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


def make_audit(api, tmp_path, platform):
    for name, value in (("effector", EFFECTOR_TOKEN), ("audit", AUDIT_TOKEN)):
        (tmp_path / name).write_text(value)
        os.chmod(tmp_path / name, 0o600)
    return RbacAudit(
        api,
        tmp_path / "effector",
        tmp_path / "audit",
        IDENTITY,
        MANIFESTS,
        TENANTS,
        CATALOG.operations,
        platform=platform,
        sleep=SLEEPS.append,
    )


@pytest.fixture
def audit(api, tmp_path):
    return make_audit(api, tmp_path, "upstream")


@pytest.fixture
def gke_audit(api, tmp_path):
    api.version = {"gitVersion": "v1.36.4-gke.2377000"}
    return make_audit(api, tmp_path, "gke")


SLEEPS: list[float] = []


@pytest.fixture(autouse=True)
def no_sleeps():
    SLEEPS.clear()


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


def test_the_webhook_audit_grant_is_part_of_the_generated_set(api, audit):
    api.namespaces.append("bailiff-webhook")
    assert audit.check() == []
    api.find("Role", "bailiff-release-webhook-audit", "bailiff-webhook")["rules"].append(
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
    )
    assert audit.check() == ["the generated Role bailiff-webhook/bailiff-release-webhook-audit was changed"]


def test_an_incomplete_rules_review_is_drift(api, audit):
    api.incomplete.add("default")
    assert audit.check() == [
        "the rules of effector in default could not be listed completely",
        "the rules of effector-audit in default could not be listed completely",
    ]


def test_the_pinned_incomplete_review_is_accepted_on_gke(api, gke_audit):
    api.incomplete.update(api.namespaces)
    api.evaluation_error = GKE_ERROR
    assert gke_audit.check() == []


def test_an_accepted_incomplete_review_still_compares_the_listed_rules(api, gke_audit):
    api.incomplete.update(api.namespaces)
    api.evaluation_error = GKE_ERROR
    api.extra_rules["kube-system"] = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    [problem] = gke_audit.check()
    assert problem.startswith("effector holds a grant outside the generated set in kube-system")


@pytest.mark.parametrize("error", ["another authorizer failed", f"[{GKE_ERROR}, another authorizer failed]"])
def test_an_incomplete_review_with_another_error_is_drift_on_gke(api, gke_audit, error):
    api.incomplete.add("default")
    api.evaluation_error = error
    assert gke_audit.check() == [
        f"the rules of effector in default could not be listed completely: {error}",
        f"the rules of effector-audit in default could not be listed completely: {error}",
    ]


def test_gke_reviews_every_dangerous_action_with_each_account_token(api, gke_audit):
    assert gke_audit.check() == []
    namespaced = sum(action.namespaced for action in DANGEROUS_ACTIONS)
    per_account = len(DANGEROUS_ACTIONS) + namespaced * 2
    reviews = [(account, attributes.get("namespace")) for account, attributes in api.self_reviews]
    assert len(reviews) == 2 * per_account
    for account in ("effector", "effector-audit"):
        assert len([review for review in reviews if review[0] == account]) == per_account
        assert {namespace for name, namespace in reviews if name == account} == {None, "bailiff-system", "staging"}


def test_upstream_sends_no_dangerous_action_review(api, audit):
    assert audit.check() == []
    assert api.self_reviews == []


@pytest.mark.parametrize(
    ("key", "problem"),
    [
        (
            ("effector", None, "get", "secrets"),
            "effector may get core secrets cluster-wide, a dangerous action outside the generated set",
        ),
        (
            ("effector-audit", "staging", "create", "pods"),
            "effector-audit may create core pods/exec in staging, a dangerous action outside the generated set",
        ),
        (
            ("effector", None, "create", "customresourcedefinitions"),
            "effector may create apiextensions.k8s.io customresourcedefinitions cluster-wide,"
            " a dangerous action outside the generated set",
        ),
    ],
)
def test_a_dangerous_action_an_account_may_take_is_drift(api, gke_audit, key, problem):
    api.self_allowed.add(key)
    assert problem in gke_audit.check()


@pytest.mark.parametrize(
    ("key", "problem"),
    [
        (
            ("effector", None, "get", "secrets"),
            "whether effector may get core secrets cluster-wide could not be decided: webhook authorizer timeout",
        ),
        (
            ("effector-audit", "staging", "create", "pods"),
            "whether effector-audit may create core pods/exec in staging could not be decided:"
            " webhook authorizer timeout",
        ),
    ],
)
def test_an_undecided_dangerous_action_review_is_drift(api, gke_audit, key, problem):
    api.self_errors[key] = "webhook authorizer timeout"
    assert problem in gke_audit.check()


def test_a_self_review_without_a_decision_fails_the_check(api, gke_audit):
    api.status["selfsubjectaccessreviews"] = 500
    with pytest.raises(KubernetesUnavailable, match="selfsubjectaccessreviews returned 500"):
        gke_audit.check()


def test_the_gke_error_is_drift_on_upstream(api, audit):
    api.incomplete.add("default")
    api.evaluation_error = GKE_ERROR
    assert audit.check() == [
        f"the rules of effector in default could not be listed completely: {GKE_ERROR}",
        f"the rules of effector-audit in default could not be listed completely: {GKE_ERROR}",
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


def test_a_gke_cluster_under_the_upstream_platform_is_drift_before_any_review(api, audit):
    api.version = {"gitVersion": "v1.36.4-gke.2377000"}
    assert audit.check() == ["the cluster runs GKE (v1.36.4-gke.2377000) but the effector platform is upstream"]
    assert api.requests == [("GET", VERSION_PATH, f"Bearer {AUDIT_TOKEN}")]


def test_an_unreadable_version_fails_the_check(api, audit):
    api.status["version"] = 403
    with pytest.raises(KubernetesUnavailable, match="GET /version returned 403"):
        audit.check()


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


def test_synthetic_users_are_reviewed_only_in_their_own_tenant_namespaces(api, tmp_path, audit):
    tenants = {"tenant-a": ["staging"], "tenant-b": ["dev", "qa"], "tenant-c": ["prod"]}
    api.tenants = tenants
    generated = generate_manifests(CATALOG, IDENTITY, tenants)
    api.objects = [served(item) for item in generated["items"] if item["kind"] not in ("Namespace", "ServiceAccount")]
    api.namespaces += ["dev", "qa", "prod"]
    wide = RbacAudit(
        api,
        tmp_path / "effector",
        tmp_path / "audit",
        IDENTITY,
        generated,
        tenants,
        CATALOG.operations,
        platform="upstream",
    )
    assert wide.check() == []
    access = [path for _, path, _ in api.requests if path.endswith("/subjectaccessreviews")]
    assert len(access) == 3 * len(CATALOG.operations) * 4


def shared(kind, namespace, role_kind, role_name, group="system:authenticated"):
    metadata = {"name": "shared"} if namespace is None else {"name": "shared", "namespace": namespace}
    return {
        "kind": kind,
        "metadata": metadata,
        "roleRef": {"kind": role_kind, "name": role_name},
        "subjects": [{"kind": "Group", "name": group}],
    }


def scale_role(kind, namespace=None):
    metadata = {"name": "scaler"} if namespace is None else {"name": "scaler", "namespace": namespace}
    return {
        "kind": kind,
        "metadata": metadata,
        "rules": [{"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["patch"]}],
    }


@pytest.mark.parametrize(
    ("binding", "role", "label"),
    [
        (
            shared("RoleBinding", "staging", "Role", "scaler"),
            scale_role("Role", "staging"),
            "RoleBinding staging/shared",
        ),
        (
            shared("RoleBinding", "staging", "ClusterRole", "scaler"),
            scale_role("ClusterRole"),
            "RoleBinding staging/shared",
        ),
        (
            shared("ClusterRoleBinding", None, "ClusterRole", "scaler"),
            scale_role("ClusterRole"),
            "ClusterRoleBinding shared",
        ),
    ],
)
def test_a_catalog_grant_to_every_authenticated_user_is_drift(api, audit, binding, role, label):
    api.objects += [binding, role]
    assert audit.check() == [
        f"the {label} grants scale_deployment to every synthetic user through system:authenticated"
    ]


def test_a_shared_grant_outside_tenant_namespaces_or_without_catalog_calls_is_not_drift(api, audit):
    api.objects += [
        shared("RoleBinding", "default", "ClusterRole", "scaler"),
        scale_role("ClusterRole"),
        shared("RoleBinding", "staging", "ClusterRole", "viewer"),
        {
            "kind": "ClusterRole",
            "metadata": {"name": "viewer"},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}],
        },
        shared("RoleBinding", "staging", "Role", "absent"),
    ]
    assert audit.check() == []


@pytest.mark.parametrize(
    ("rule", "granted"),
    [
        ({"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}, True),
        ({"apiGroups": ["apps"], "resources": ["*/scale"], "verbs": ["patch"]}, True),
        ({"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["*"]}, True),
        ({"apiGroups": ["apps"], "resources": ["deployments/*"], "verbs": ["patch"]}, False),
        ({"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"]}, False),
        ({"apiGroups": [""], "resources": ["deployments/scale"], "verbs": ["patch"]}, False),
        ({"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["get"]}, False),
        ({"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["patch"], "resourceNames": ["x"]}, True),
    ],
)
def test_shared_grants_follow_rbac_resource_matching(rule, granted):
    assert grants([rule], CATALOG.operation("scale_deployment")) is granted


@pytest.mark.parametrize("account", ["effector", "effector-audit"])
def test_a_binding_naming_the_effector_service_account_username_as_a_user_is_drift(api, audit, account):
    api.objects.append(
        {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "sneak"},
            "roleRef": {"kind": "ClusterRole", "name": "edit"},
            "subjects": [{"kind": "User", "name": f"system:serviceaccount:bailiff-system:{account}"}],
        }
    )
    assert audit.check() == ["the ClusterRoleBinding sneak grants to the effector or a synthetic user"]


@pytest.mark.parametrize(("namespace", "drift"), [("bailiff-system", True), ("staging", False)])
def test_a_service_account_subject_without_a_namespace_is_in_the_binding_namespace(api, audit, namespace, drift):
    api.objects.append(
        {
            "kind": "RoleBinding",
            "metadata": {"name": "sneak", "namespace": namespace},
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "subjects": [{"kind": "ServiceAccount", "name": "effector"}],
        }
    )
    problem = f"the RoleBinding {namespace}/sneak grants to the effector or a synthetic user"
    assert (problem in audit.check()) is drift


def test_a_throttled_request_is_retried_with_bounded_backoff(api, audit):
    api.throttled = 3
    assert audit.check() == []
    assert len(SLEEPS) == 3 and all(0 <= delay <= 8.0 for delay in SLEEPS)


def test_a_request_throttled_past_the_retries_fails_the_check(api, audit):
    api.throttled = 6
    with pytest.raises(KubernetesUnavailable, match="GET /version was throttled 6 times"):
        audit.check()
    assert len(SLEEPS) == 5


@pytest.mark.parametrize(("retry_after", "low"), [(0.0, 0.0), (3.0, 3.0), (60.0, 8.0)])
def test_a_throttled_request_waits_the_retry_after_with_jitter_up_to_the_cap(api, audit, retry_after, low):
    api.throttled = 2
    api.retry_after = retry_after
    assert audit.check() == []
    assert len(SLEEPS) == 2 and all(low <= delay <= low + 0.5 for delay in SLEEPS)


def test_the_audit_counts_its_requests_and_throttles_for_each_check(api, audit):
    api.throttled = 2
    audit.check()
    assert audit.traffic() == (len(api.requests), 2)
    api.requests.clear()
    audit.check()
    assert audit.traffic() == (len(api.requests), 0)


def test_dangerous_action_reviews_do_not_grow_with_the_cluster_namespaces(api, gke_audit):
    gke_audit.check()
    few = len(api.self_reviews)
    api.self_reviews.clear()
    api.namespaces += [f"team-{index}" for index in range(1000)]
    assert gke_audit.check() == []
    assert len(api.self_reviews) == few


@pytest.mark.parametrize(("seconds", "alarm"), [(0, False), (60, False), (61, True)])
def test_the_gate_logs_each_check_cost_and_alarms_past_half_the_window(api, audit, caplog, seconds, alarm):
    times = iter([1000, 1000 + seconds])
    gate = RbacGate(audit, lambda: next(times), interval=60)
    with caplog.at_level(logging.INFO, logger="agent_bailiff.effector.drift"):
        gate.verify()
    requests, throttled = audit.traffic()
    assert f"effector RBAC check took {seconds} s: {requests} requests, {throttled} throttled" in caplog.messages
    warned = [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]
    expected = [f"effector RBAC check took {seconds} s, over half its 120 s freshness window"]
    assert warned == (expected if alarm else [])


def test_the_release_webhook_is_read_with_the_audit_token(api, audit):
    assert audit.check_release_webhook() == []
    assert ("GET", WEBHOOK_PATH, f"Bearer {AUDIT_TOKEN}") in api.requests
    assert ("GET", SERVICE_PATH, f"Bearer {AUDIT_TOKEN}") in api.requests


def hook(api):
    return api.registration["webhooks"][0]


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda api: hook(api).update(failurePolicy="Ignore"), "release.bailiff.dev does not fail closed"),
        (
            lambda api: hook(api).update(admissionReviewVersions=["v1beta1", "v1"]),
            "release.bailiff.dev does not use the generated review version and timeout",
        ),
        (
            lambda api: hook(api).update(timeoutSeconds=1),
            "release.bailiff.dev does not use the generated review version and timeout",
        ),
        (
            lambda api: hook(api)["rules"][0].update(operations=["CREATE"]),
            "release.bailiff.dev does not match every write by a synthetic user",
        ),
        (
            lambda api: hook(api)["matchConditions"][0].update(expression="false"),
            "release.bailiff.dev does not match every write by a synthetic user",
        ),
        (
            lambda api: hook(api).update(namespaceSelector={"matchLabels": {"a": "b"}}),
            "release.bailiff.dev is narrowed by a selector",
        ),
        (
            lambda api: hook(api).update(objectSelector={"matchLabels": {"a": "b"}}),
            "release.bailiff.dev is narrowed by a selector",
        ),
        (
            lambda api: hook(api)["clientConfig"].update(url="https://example.invalid/validate"),
            "release.bailiff.dev does not call the bailiff-webhook/bailiff-release-webhook Service",
        ),
        (
            lambda api: hook(api)["clientConfig"]["service"].update(namespace="other"),
            "release.bailiff.dev does not call the bailiff-webhook/bailiff-release-webhook Service",
        ),
        (
            lambda api: api.service["spec"]["selector"].pop(webhook.MODE_LABEL),
            "the Service bailiff-webhook/bailiff-release-webhook does not select only Enforce-mode webhook pods",
        ),
        (
            lambda api: api.service["spec"]["selector"].update({"app.kubernetes.io/name": "other"}),
            "the Service bailiff-webhook/bailiff-release-webhook does not select only Enforce-mode webhook pods",
        ),
        (
            lambda api: api.service["spec"]["selector"].update(extra="x"),
            "the Service bailiff-webhook/bailiff-release-webhook does not select only Enforce-mode webhook pods",
        ),
        (
            lambda api: api.registration["webhooks"].append(copy.deepcopy(hook(api))),
            "the ValidatingWebhookConfiguration bailiff-release-webhook does not register release.bailiff.dev",
        ),
        (
            lambda api: api.registration.update(webhooks=[]),
            "the ValidatingWebhookConfiguration bailiff-release-webhook does not register release.bailiff.dev",
        ),
    ],
)
def test_a_weakened_release_webhook_is_reported(api, audit, change, problem):
    change(api)
    assert audit.check_release_webhook() == [problem]


def test_the_generated_enforce_webhook_passes_the_check(api, audit, tmp_path):
    from test_effector import CATALOG

    from agent_bailiff.webhook.certs import issue_serving_certificate

    issue_serving_certificate(tmp_path / "certs", webhook.NAME, "bailiff-webhook")
    generated = webhook.generate_manifests(
        namespace="bailiff-webhook",
        image="registry.example/bailiff@sha256:" + "a" * 64,
        ca_pem=(tmp_path / "certs" / "ca.crt").read_bytes(),
        pins={"catalog_digest": CATALOG.digest},
        catalog=CATALOG,
        deployers=["gitops"],
        enforce=True,
        phase="register",
    )
    items = {item["kind"]: item for item in generated["items"]}
    api.registration = items["ValidatingWebhookConfiguration"]
    api.service = items["Service"]
    assert audit.check_release_webhook() == []


@pytest.mark.parametrize("fault", ["changed", "unreadable", "missing service"])
def test_a_release_webhook_problem_withdraws_only_writes(api, audit, fault):
    if fault == "changed":
        hook(api).update(failurePolicy="Ignore")
    elif fault == "unreadable":
        api.status["webhook"] = 404
    else:
        api.status["service"] = 404
    gate = RbacGate(audit, Clock(), interval=60)
    gate.verify()
    assert gate.healthy(1000) and gate.restart_healthy(1000)
    assert gate.write_healthy(1000) is False


def test_writes_are_healthy_only_while_both_checks_are_fresh(api, audit):
    gate = RbacGate(audit, Clock(), interval=60)
    assert gate.write_healthy(1000) is False
    gate.verify()
    assert gate.write_healthy(1000) and gate.write_healthy(1120)
    assert gate.write_healthy(1121) is False
    api.status["rolebindings"] = 403
    with pytest.raises(RbacDrift):
        gate.verify()
    assert gate.write_healthy(1000) is False
    assert not any(path == WEBHOOK_PATH for _, path, _ in api.requests[-3:])


def slow_audit(audit, clock, seconds):
    class Slow:
        def check(self):
            clock.now += seconds
            return audit.check()

        def __getattr__(self, name):
            return getattr(audit, name)

    return Slow()


def test_freshness_is_counted_from_the_start_of_the_check(api, audit):
    clock = Clock()
    gate = RbacGate(slow_audit(audit, clock, 50), clock, interval=60)
    gate.verify()
    assert gate.healthy(1120) and gate.write_healthy(1120)
    assert gate.healthy(1121) is False and gate.write_healthy(1121) is False


def test_a_check_longer_than_twice_the_interval_never_makes_the_gate_healthy(api, audit):
    clock = Clock()
    gate = RbacGate(slow_audit(audit, clock, 121), clock, interval=60)
    gate.verify()
    assert gate.healthy(clock.now) is False


def test_each_check_starts_one_interval_after_the_previous_one_started(api, audit):
    clock = Clock()
    gate = RbacGate(slow_audit(audit, clock, 50), clock, interval=60)
    delays = []

    class Stop:
        def wait(self, delay):
            delays.append(delay)
            if len(delays) == 2:
                gate._audit = slow_audit(audit, clock, 70)
            return len(delays) > 3

    gate._stop = Stop()
    gate._run()
    assert delays == [60, 10, 0, 0]


def test_a_clock_set_back_during_a_check_does_not_delay_the_next_one(api, audit):
    clock = Clock()
    gate = RbacGate(slow_audit(audit, clock, -3600), clock, interval=60)
    delays = []

    class Stop:
        def wait(self, delay):
            delays.append(delay)
            return len(delays) > 1

    gate._stop = Stop()
    gate._run()
    assert delays == [60, 60]


def test_closing_the_gate_closes_the_audit_transport(api, audit):
    gate = RbacGate(audit, Clock(), interval=60)
    gate.close()
    assert api.closed is True
