import pytest

from agent_bailiff.effector.platform import PLATFORMS, accepts_incomplete, check_version, parse_platform

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


def test_the_gke_platform_on_a_cluster_that_is_not_gke_is_refused():
    assert check_version("gke", {"gitVersion": "v1.36.5"}) == [
        "the effector platform is gke but the cluster runs v1.36.5"
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
