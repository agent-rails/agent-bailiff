from pathlib import Path

import pytest
from test_agentgateway_calls import message
from test_agentgateway_config import gateway_config, problems_after

from agent_bailiff.adapters.agentgateway.calls import CallRefused, ToolRoute, ToolRoutes, read_call, routes_from_catalog
from agent_bailiff.effector.catalog import OperationCatalog

CATALOG = OperationCatalog.load(
    Path(__file__).resolve().parent.parent / "agent_bailiff" / "effector" / "catalogs" / "kubernetes.json"
)
SCALE = ToolRoute(
    "k8s", "scale_deployment", "k8s.deployments.scale", "k8s/{namespace}/deployments/{name}",
    frozenset({"namespace", "name", "replicas"}),
)  # fmt: skip
ROUTES = ToolRoutes([SCALE])


def call(arguments):
    return read_call(message(params={"name": "scale_deployment", "arguments": arguments}, services=("k8s",)), ROUTES)


def test_a_template_resource_is_filled_from_the_arguments():
    request = call({"namespace": "staging", "name": "api", "replicas": 3})
    assert (request.tool, request.resource) == ("k8s.deployments.scale", "k8s/staging/deployments/api")
    assert request.args == {"namespace": "staging", "name": "api", "replicas": 3}


@pytest.mark.parametrize(
    "arguments",
    [
        {"namespace": "staging", "name": "api", "replicas": 3, "kind": "StatefulSet"},
        {"name": "api", "replicas": 3},
        {"namespace": "", "name": "api"},
        {"namespace": "Staging", "name": "api"},
        {"namespace": "staging/../prod", "name": "api"},
        {"namespace": "staging", "name": "api/*"},
        {"namespace": "staging", "name": "a" * 64},
        {"namespace": "staging", "name": 5},
        {"namespace": ["staging"], "name": "api"},
    ],
)
def test_unknown_missing_or_non_label_arguments_are_refused(arguments):
    with pytest.raises(CallRefused) as refused:
        call(arguments)
    assert refused.value.reason == "malformed_request"


def test_a_template_needs_an_arguments_list_that_covers_its_placeholders():
    with pytest.raises(ValueError, match="arguments list"):
        ToolRoute("k8s", "x", "k8s.x", "k8s/{namespace}/x")
    with pytest.raises(ValueError, match="listed argument"):
        ToolRoute("k8s", "x", "k8s.x", "k8s/{namespace}/x/{name}", frozenset({"namespace"}))
    with pytest.raises(ValueError, match="concrete"):
        ToolRoute("k8s", "x", "k8s.x", "k8s/*/x", frozenset())


def test_routes_from_a_document_accept_templates_and_concrete_resources():
    routes = ToolRoutes.from_document(
        {
            "routes": [
                {
                    "service": "deploy",
                    "name": "deploy_service",
                    "tool": "deploy.service",
                    "resource": "env/staging/api",
                },
                {
                    "service": "k8s",
                    "name": "scale_deployment",
                    "tool": "k8s.deployments.scale",
                    "resource": "k8s/{namespace}/deployments/{name}",
                    "arguments": ["namespace", "name", "replicas"],
                },
            ]
        }
    )
    assert routes.route("k8s", "scale_deployment") == SCALE
    assert routes.route("deploy", "deploy_service").arguments is None
    with pytest.raises(ValueError, match="list of names"):
        ToolRoutes.from_document({"routes": [{**SCALE.__dict__, "arguments": "namespace"}]})


def test_routes_from_the_catalog_cover_every_operation():
    routes = routes_from_catalog("k8s", CATALOG)
    assert routes.route("k8s", "scale_deployment") == SCALE
    assert routes.route("k8s", "list_pods").resource_for({"namespace": "staging", "limit": 5}) == "k8s/staging/pods"
    assert routes.services == frozenset({"k8s"})


def test_a_concrete_route_ignores_arguments_as_before():
    route = ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api")
    assert route.resource_for({"anything": "goes"}) == "env/staging/api"


def test_check_config_requires_the_gateway_to_remove_the_release_header():
    def change(config):
        modifier = config["mcp"]["policies"]["requestHeaderModifier"]
        modifier["remove"] = [name for name in modifier["remove"] if name != "bailiff-release"]

    assert any("missing bailiff-release" in problem for problem in problems_after(change))
    assert "bailiff-release" in gateway_config()["mcp"]["policies"]["requestHeaderModifier"]["remove"]
