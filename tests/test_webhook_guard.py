import pytest

from agent_bailiff.webhook.guard import CONTROLLERS, NAMESPACE_GUARD, REGISTRATION_GUARD, guard_policies


def _by_name(items, kind):
    return {item["metadata"]["name"]: item for item in items if item["kind"] == kind}


def test_the_namespace_guard_binds_only_to_the_webhook_namespace():
    bindings = _by_name(guard_policies("webhook-ns", "hook", ["gitops"], False), "ValidatingAdmissionPolicyBinding")
    namespace = bindings[NAMESPACE_GUARD]["spec"]["matchResources"]["namespaceSelector"]
    assert namespace == {"matchLabels": {"kubernetes.io/metadata.name": "webhook-ns"}}
    assert bindings[REGISTRATION_GUARD]["spec"]["matchResources"]["namespaceSelector"] == {}


def test_audit_mode_warns_and_enforce_mode_denies():
    for enforce, actions in ((False, ["Audit", "Warn"]), (True, ["Deny"])):
        bindings = _by_name(guard_policies("ns", "hook", ["gitops"], enforce), "ValidatingAdmissionPolicyBinding")
        assert {name: binding["spec"]["validationActions"] for name, binding in bindings.items()} == {
            NAMESPACE_GUARD: actions,
            REGISTRATION_GUARD: actions,
        }


def test_the_registration_guard_covers_delete_of_the_named_webhook_only():
    policies = _by_name(guard_policies("ns", "hook", ["gitops"], True), "ValidatingAdmissionPolicy")
    rules = policies[REGISTRATION_GUARD]["spec"]["matchConstraints"]["resourceRules"]
    assert rules == [
        {
            "apiGroups": ["admissionregistration.k8s.io"],
            "apiVersions": ["*"],
            "operations": ["CREATE", "UPDATE", "DELETE"],
            "resources": ["validatingwebhookconfigurations"],
            "resourceNames": ["hook"],
            "scope": "Cluster",
        }
    ]
    assert '"gitops"' in policies[REGISTRATION_GUARD]["spec"]["validations"][0]["expression"]


def test_the_namespace_guard_never_matches_delete_and_covers_streaming_and_status():
    policies = _by_name(guard_policies("ns", "hook", ["gitops"], True), "ValidatingAdmissionPolicy")
    rules = policies[NAMESPACE_GUARD]["spec"]["matchConstraints"]["resourceRules"]
    assert all(rule["operations"] == ["CREATE", "UPDATE", "CONNECT"] for rule in rules)
    resources = {(rule["apiGroups"][0], resource) for rule in rules for resource in rule["resources"]}
    for expected in (
        ("", "pods/exec"),
        ("", "pods/attach"),
        ("", "pods/portforward"),
        ("", "pods/status"),
        ("", "pods/ephemeralcontainers"),
        ("", "pods/binding"),
        ("", "pods/resize"),
        ("", "serviceaccounts"),
        ("", "resourcequotas"),
        ("", "limitranges"),
        ("networking.k8s.io", "networkpolicies"),
        ("", "secrets"),
        ("discovery.k8s.io", "endpointslices"),
        ("apps", "replicasets"),
        ("batch", "jobs"),
    ):
        assert expected in resources


def test_controller_identities_are_exact_names():
    assert "system:kube-controller-manager" in CONTROLLERS
    assert "system:serviceaccount:kube-system:replicaset-controller" in CONTROLLERS
    assert all(not name.endswith("*") and not name.endswith(":") for name in CONTROLLERS)


@pytest.mark.parametrize(
    "deployers",
    [
        [],
        [""],
        ["it's"],
        ["a\\b"],
        ["system:kube-controller-manager"],
        ["system:node:worker"],
        ["system:anonymous"],
        ["system:unauthenticated"],
        ["system:kube-proxy"],
        ["system:serviceaccount:kube-system:argocd"],
        ["system:serviceaccount:ns:default"],
    ],
)
def test_bad_deployers_are_refused(deployers):
    with pytest.raises(ValueError, match="deployer"):
        guard_policies("ns", "hook", deployers, False)


def test_a_gitops_service_account_outside_the_webhook_namespace_may_deploy():
    assert guard_policies("ns", "hook", ["system:serviceaccount:argocd:argocd-application-controller"], True)


def test_only_the_scheduler_may_bind_pods():
    policies = _by_name(guard_policies("ns", "hook", ["gitops"], True), "ValidatingAdmissionPolicy")
    expressions = [check["expression"] for check in policies[NAMESPACE_GUARD]["spec"]["validations"]]
    assert "variables.subresource != 'binding' || variables.user == 'system:kube-scheduler'" in expressions
