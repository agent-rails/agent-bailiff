import pytest

from agent_bailiff.effector.catalog import OperationCatalog, shipped_catalog
from agent_bailiff.effector.platform import (
    DANGEROUS_ACTIONS,
    PLATFORMS,
    Action,
    accepts_incomplete,
    check_catalog,
    check_version,
    parse_platform,
    reviews_denied_actions,
)

GKE_ERROR = "webhook authorizer does not support user rule resolution"


@pytest.mark.parametrize("value", PLATFORMS)
def test_every_known_platform_parses(value):
    assert parse_platform(value) == value


@pytest.mark.parametrize("value", ["GKE", "aks", "", None, 1, ["gke"]])
def test_an_unknown_platform_is_refused(value):
    with pytest.raises(ValueError, match="platform must be one of upstream, gke, eks"):
        parse_platform(value)


@pytest.mark.parametrize(
    ("platform", "git_version"),
    [
        ("upstream", "v1.36.5"),
        ("upstream", "v1.36.5+orb"),
        ("eks", "v1.36.2-eks-0a21954"),
        ("gke", "v1.36.4-gke.2377000"),
    ],
)
def test_a_version_matching_the_platform_passes(platform, git_version):
    assert check_version(platform, {"gitVersion": git_version}) == []


@pytest.mark.parametrize("platform", ["upstream", "eks"])
def test_a_gke_cluster_under_another_platform_is_refused(platform):
    assert check_version(platform, {"gitVersion": "v1.36.4-gke.2377000"}) == [
        f"the cluster runs GKE (v1.36.4-gke.2377000) but the effector platform is {platform}"
    ]


@pytest.mark.parametrize("platform", ["upstream", "gke"])
def test_an_eks_cluster_under_another_platform_is_refused(platform):
    assert check_version(platform, {"gitVersion": "v1.36.2-eks-0a21954"}) == [
        f"the cluster runs EKS (v1.36.2-eks-0a21954) but the effector platform is {platform}"
    ]


@pytest.mark.parametrize("platform", ["gke", "eks"])
def test_a_managed_platform_on_an_upstream_cluster_is_refused(platform):
    assert check_version(platform, {"gitVersion": "v1.36.5"}) == [
        f"the effector platform is {platform} but the cluster runs v1.36.5"
    ]


def test_a_version_naming_two_managed_platforms_is_refused():
    assert check_version("gke", {"gitVersion": "v1.36.4-gke.1-eks-0a21954"}) == [
        "the cluster version v1.36.4-gke.1-eks-0a21954 names more than one managed platform"
    ]


@pytest.mark.parametrize("version", [{}, {"gitVersion": ""}, {"gitVersion": 1}, [], None])
def test_a_version_without_git_version_is_refused(version):
    assert check_version("upstream", version) == ["/version returned no gitVersion"]


def test_the_pinned_gke_error_is_accepted_on_gke():
    assert accepts_incomplete("gke", {"incomplete": True, "evaluationError": GKE_ERROR})


@pytest.mark.parametrize(
    "status",
    [
        {"incomplete": True},
        {"incomplete": True, "evaluationError": ""},
        {"incomplete": True, "evaluationError": None},
        {"incomplete": True, "evaluationError": "another authorizer failed"},
        {"incomplete": True, "evaluationError": f"[{GKE_ERROR}, another authorizer failed]"},
        {"incomplete": True, "evaluationError": f"{GKE_ERROR} "},
        {"incomplete": "true", "evaluationError": GKE_ERROR},
        {"incomplete": False, "evaluationError": GKE_ERROR},
    ],
)
def test_any_other_review_is_not_accepted_on_gke(status):
    assert not accepts_incomplete("gke", status)


@pytest.mark.parametrize("platform", ["upstream", "eks"])
def test_no_incomplete_review_is_accepted_outside_gke(platform):
    assert not accepts_incomplete(platform, {"incomplete": True, "evaluationError": GKE_ERROR})


CLUSTER = {"namespaced": False}


@pytest.mark.parametrize(
    "action",
    [
        Action("*", "*", "*"),
        Action("get", "", "secrets"),
        Action("list", "", "secrets"),
        Action("watch", "", "secrets"),
        Action("create", "", "pods"),
        Action("create", "", "pods", "exec"),
        Action("create", "", "pods", "attach"),
        Action("create", "", "pods", "portforward"),
        Action("patch", "", "pods", "ephemeralcontainers"),
        Action("create", "", "serviceaccounts", "token"),
        Action("patch", "apps", "deployments"),
        Action("patch", "apps", "deployments", "scale"),
        Action("create", "apps", "daemonsets"),
        Action("create", "apps", "statefulsets"),
        Action("create", "batch", "jobs"),
        Action("create", "batch", "cronjobs"),
        Action("create", "rbac.authorization.k8s.io", "rolebindings"),
        Action("bind", "rbac.authorization.k8s.io", "roles"),
        Action("escalate", "rbac.authorization.k8s.io", "roles"),
        Action("impersonate:serviceaccount", "authentication.k8s.io", "serviceaccounts"),
        Action("impersonate-on:user-info:get", "", "secrets"),
        Action("create", "rbac.authorization.k8s.io", "clusterrolebindings", **CLUSTER),
        Action("escalate", "rbac.authorization.k8s.io", "clusterroles", **CLUSTER),
        Action("impersonate", "", "users", **CLUSTER),
        Action("impersonate", "authentication.k8s.io", "userextras", **CLUSTER),
        Action("impersonate:user-info", "authentication.k8s.io", "groups", **CLUSTER),
        Action("impersonate:arbitrary-node", "authentication.k8s.io", "nodes", **CLUSTER),
        Action("create", "", "nodes", "proxy", **CLUSTER),
        Action("patch", "", "nodes", **CLUSTER),
        Action("delete", "", "namespaces", **CLUSTER),
        Action("create", "", "persistentvolumes", **CLUSTER),
        Action("create", "certificates.k8s.io", "certificatesigningrequests", **CLUSTER),
        Action("update", "certificates.k8s.io", "certificatesigningrequests", "approval", **CLUSTER),
        Action("approve", "certificates.k8s.io", "signers", **CLUSTER),
        Action("create", "admissionregistration.k8s.io", "mutatingwebhookconfigurations", **CLUSTER),
        Action("delete", "admissionregistration.k8s.io", "validatingadmissionpolicybindings", **CLUSTER),
        Action("create", "apiextensions.k8s.io", "customresourcedefinitions", **CLUSTER),
    ],
)
def test_the_dangerous_action_list_holds_each_reviewed_action(action):
    assert action in DANGEROUS_ACTIONS


def test_the_dangerous_action_list_has_no_duplicates():
    assert len(set(DANGEROUS_ACTIONS)) == len(DANGEROUS_ACTIONS)


@pytest.mark.parametrize(("platform", "reviewed"), [("gke", True), ("upstream", False), ("eks", False)])
def test_only_platforms_that_accept_an_incomplete_review_send_dangerous_action_reviews(platform, reviewed):
    assert reviews_denied_actions(platform) is reviewed


WRITE_CATALOG = OperationCatalog.load(shipped_catalog("kubernetes"))
READ_CATALOG = OperationCatalog.load(shipped_catalog("kubernetes-read"))


@pytest.mark.parametrize("platform", ["gke", "eks"])
def test_a_managed_platform_refuses_a_write_catalog(platform):
    with pytest.raises(
        ValueError,
        match=f"managed platforms support read-only catalogs only; {platform} refuses restart_deployment, "
        "scale_deployment",
    ):
        check_catalog(platform, WRITE_CATALOG.operations)


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_platform_accepts_the_read_catalog(platform):
    check_catalog(platform, READ_CATALOG.operations)


def test_upstream_accepts_the_write_catalog():
    check_catalog("upstream", WRITE_CATALOG.operations)
