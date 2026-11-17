import json
from pathlib import Path

import pytest

from agent_bailiff.cli import main
from agent_bailiff.effector.catalog import CatalogError, OperationCatalog
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests, render
from agent_bailiff.service.init import DEFAULT_CATALOG

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "deploy" / "kubernetes" / "effector.example.json"
CATALOG = OperationCatalog.load(DEFAULT_CATALOG)
IDENTITY = EffectorIdentity("bailiff-system", "effector", "system:serviceaccount:argocd:argocd-application-controller")


def manifests(tenants=None, catalog=CATALOG, identity=IDENTITY):
    return generate_manifests(catalog, identity, tenants or {"tenant-a": ["staging"]})["items"]


def named(items, kind, name, namespace=None):
    [item] = [
        item
        for item in items
        if item["kind"] == kind and item["metadata"]["name"] == name and item["metadata"].get("namespace") == namespace
    ]
    return item


def test_the_shipped_example_is_the_generator_output():
    assert EXAMPLE.read_text() == render(generate_manifests(CATALOG, IDENTITY, {"tenant-a": ["staging"]}))


def test_the_cli_prints_the_same_manifests(capsys):
    code = main(
        [
            "effector",
            "manifests",
            "--namespace",
            "bailiff-system",
            "--service-account",
            "effector",
            "--applier",
            IDENTITY.applier,
            "--tenant",
            "tenant-a=staging",
        ]
    )
    assert code == 0
    assert capsys.readouterr().out == EXAMPLE.read_text()


def test_no_generated_rule_grants_legacy_impersonation_or_wildcards():
    for item in manifests({"tenant-a": ["staging"], "tenant-b": ["dev", "qa"]}):
        for rule in item.get("rules", []):
            assert "impersonate" not in rule["verbs"]
            assert "*" not in rule["verbs"] + rule["resources"] + rule["apiGroups"]


def test_the_effector_may_impersonate_only_the_synthetic_users_and_extras():
    role = named(
        manifests({"tenant-a": ["staging"], "tenant-b": ["dev"]}), "ClusterRole", "bailiff-effector-impersonate"
    )
    users, extras = role["rules"]
    assert users["resourceNames"] == [
        "bailiff:tenant-a:read",
        "bailiff:tenant-a:restart",
        "bailiff:tenant-a:scale",
        "bailiff:tenant-b:read",
        "bailiff:tenant-b:restart",
        "bailiff:tenant-b:scale",
    ]
    assert users["verbs"] == extras["verbs"] == ["impersonate:user-info"]
    assert extras["resources"] == ["userextras/bailiff.dev/op-id", "userextras/bailiff.dev/trace-id"]


def test_impersonate_on_grants_mirror_the_catalog_in_each_namespace():
    items = manifests({"tenant-a": ["staging"], "tenant-b": ["dev"]})
    for namespace in ("staging", "dev"):
        assert named(items, "Role", "bailiff-effector-on", namespace)["rules"] == [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["impersonate-on:user-info:list"]},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["impersonate-on:user-info:get"]},
            {
                "apiGroups": ["apps"],
                "resources": ["deployments"],
                "verbs": ["impersonate-on:user-info:get", "impersonate-on:user-info:patch"],
            },
            {"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["impersonate-on:user-info:patch"]},
        ]


def test_each_tenant_identity_is_granted_only_its_operations_in_its_namespaces():
    items = manifests({"tenant-a": ["staging"], "tenant-b": ["dev"]})
    scale = named(items, "Role", "bailiff-tenant-a-scale", "staging")
    assert scale["rules"] == [{"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["patch"]}]
    binding = named(items, "RoleBinding", "bailiff-tenant-a-scale", "staging")
    assert binding["subjects"] == [
        {"kind": "User", "name": "bailiff:tenant-a:scale", "apiGroup": "rbac.authorization.k8s.io"}
    ]
    assert not [
        item for item in items if item["metadata"].get("namespace") == "dev" and "tenant-a" in item["metadata"]["name"]
    ]


def test_the_admission_policies_fail_closed_and_bound_the_replica_range():
    items = manifests()
    for item in items:
        if item["kind"] == "ValidatingAdmissionPolicy":
            assert item["spec"]["failurePolicy"] == "Fail"
        if item["kind"] == "ValidatingAdmissionPolicyBinding":
            assert item["spec"]["validationActions"] == ["Deny"] and "matchResources" not in item["spec"]
    scale = named(items, "ValidatingAdmissionPolicy", "bailiff-scale-deployment")
    assert "object.spec.replicas >= 1 && object.spec.replicas <= 10" in scale["spec"]["validations"][0]["expression"]
    guard = named(items, "ValidatingAdmissionPolicy", "bailiff-effector-guard")
    assert guard["spec"]["matchConstraints"]["resourceRules"][0]["resources"] == ["*/*"]
    op_id, writes, owned = guard["spec"]["validations"]
    assert "has(request.userInfo.extra)" in op_id["expression"]
    assert "request.?subResource.orValue('') == 'scale'" in writes["expression"]
    assert "endsWith(':scale')" in writes["expression"]
    assert (
        owned["expression"]
        == "(request.userInfo.username.startsWith('bailiff:tenant-a:') && request.namespace in [\"staging\"])"
    )


def test_the_binding_policy_names_the_effector_and_the_applier():
    policy = named(manifests(), "ValidatingAdmissionPolicy", "bailiff-effector-rbac")
    expression = policy["spec"]["validations"][0]["expression"]
    assert "s.namespace == 'bailiff-system' && (s.name == 'effector' || s.name == 'effector-audit')" in expression
    assert "s.name.startsWith('bailiff:')" in expression
    assert expression.endswith(
        "request.userInfo.username == 'system:serviceaccount:argocd:argocd-application-controller'"
    )


def test_every_object_is_labelled_generated():
    assert all(item["metadata"]["labels"]["bailiff.dev/generated"] == "true" for item in manifests())


@pytest.mark.parametrize(
    ("tenants", "identity"),
    [
        ({}, IDENTITY),
        ({"Tenant_A": ["staging"]}, IDENTITY),
        ({"tenant-a": []}, IDENTITY),
        ({"tenant-a": ["Staging"]}, IDENTITY),
        ({"tenant-a": ["bailiff-system"]}, IDENTITY),
        ({"t" * 60: ["staging"]}, IDENTITY),
        ({"tenant-a": ["staging"]}, EffectorIdentity("bailiff-system", "effector", "x' || true || '")),
        ({"tenant-a": ["staging"]}, EffectorIdentity("bailiff_system", "effector", "gitops")),
    ],
)
def test_unsafe_inputs_are_refused(tenants, identity):
    with pytest.raises(CatalogError):
        generate_manifests(CATALOG, identity, tenants)


def test_the_cli_refuses_a_malformed_tenant(capsys):
    args = ["effector", "manifests", "--namespace", "bailiff-system", "--service-account", "effector"]
    assert main([*args, "--applier", "gitops", "--tenant", "tenant-a"]) != 0
    assert "refused" in capsys.readouterr().err


def test_the_example_is_valid_json_list():
    document = json.loads(EXAMPLE.read_text())
    assert document["kind"] == "List" and len(document["items"]) == 23


def test_the_audit_identity_may_only_list_and_ask_access_reviews():
    items = manifests()
    role = named(items, "ClusterRole", "bailiff-effector-audit")
    writes = [rule for rule in role["rules"] if rule["verbs"] != ["list"]]
    assert writes == [
        {"apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"]}
    ]
    binding = named(items, "ClusterRoleBinding", "bailiff-effector-audit")
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "effector-audit", "namespace": "bailiff-system"}]


def test_the_guard_ties_each_tenant_to_its_own_namespaces():
    guard = named(
        manifests({"tenant-a": ["staging"], "tenant-b": ["dev", "qa"]}),
        "ValidatingAdmissionPolicy",
        "bailiff-effector-guard",
    )
    owned = guard["spec"]["validations"][2]["expression"]
    assert "startsWith('bailiff:tenant-a:') && request.namespace in [\"staging\"]" in owned
    assert 'startsWith(\'bailiff:tenant-b:\') && request.namespace in ["dev", "qa"]' in owned


def test_a_restart_operation_gets_a_full_comparison_policy_and_its_own_role():
    from test_effector_catalog import with_restart

    items = manifests(catalog=OperationCatalog(with_restart()))
    policy = named(items, "ValidatingAdmissionPolicy", "bailiff-restart-deployment")
    spec = policy["spec"]
    assert spec["failurePolicy"] == "Fail"
    assert spec["matchConstraints"]["resourceRules"] == [
        {"apiGroups": ["apps"], "apiVersions": ["*"], "operations": ["UPDATE"], "resources": ["deployments"]}
    ]
    assert [item["expression"] for item in spec["matchConditions"]] == [
        "request.userInfo.username.startsWith('bailiff:')",
        "request.userInfo.username.endsWith(':restart')",
    ]
    expressions = [item["expression"] for item in spec["validations"]]
    for field in ("minReadySeconds", "paused", "progressDeadlineSeconds", "replicas", "revisionHistoryLimit"):
        assert f"object.spec.?{field} == oldObject.spec.?{field}" in expressions
    assert "object.spec.template.spec == oldObject.spec.template.spec" in expressions
    assert "object.spec.template.metadata.?labels == oldObject.spec.template.metadata.?labels" in expressions
    assert "object.metadata.?generateName == oldObject.metadata.?generateName" in expressions
    assert not any("object.metadata.?generation" in item for item in expressions)
    assert any("m.manager != 'bailiff-effector'" in item for item in expressions)
    binding = named(items, "ValidatingAdmissionPolicyBinding", "bailiff-restart-deployment")
    assert binding["spec"]["validationActions"] == ["Deny"]
    role = named(items, "Role", "bailiff-tenant-a-restart", "staging")
    assert role["rules"] == [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"]}]
    guard = named(items, "ValidatingAdmissionPolicy", "bailiff-effector-guard")
    assert (
        "request.?subResource.orValue('') == '' && request.operation == 'UPDATE'"
        in guard["spec"]["validations"][1]["expression"]
    )
    assert "endsWith(':restart')" in guard["spec"]["validations"][1]["expression"]
