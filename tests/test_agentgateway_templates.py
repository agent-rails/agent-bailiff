from pathlib import Path

import pytest
from test_agentgateway_calls import message
from test_agentgateway_config import gateway_config, problems_after

from agent_bailiff.adapters.agentgateway.calls import CallRefused, ToolRoute, ToolRoutes, read_call, routes_from_catalog
from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor
from agent_bailiff.effector.catalog import Argument, OperationCatalog

CATALOG = OperationCatalog.load(
    Path(__file__).resolve().parent.parent / "agent_bailiff" / "effector" / "catalogs" / "kubernetes.json"
)
ROUTES = routes_from_catalog("k8s", CATALOG)


def call(name, arguments):
    return read_call(message(params={"name": name, "arguments": arguments}, services=("k8s",)), ROUTES)


def test_a_template_resource_is_filled_from_valid_arguments():
    request = call("scale_deployment", {"namespace": "staging", "name": "api", "replicas": 3})
    assert (request.tool, request.resource) == ("k8s.deployments.scale", "k8s/staging/deployments/api")
    assert call("list_pods", {"namespace": "staging", "limit": 5}).resource == "k8s/staging/pods"


@pytest.mark.parametrize(
    "arguments",
    [
        {"namespace": "staging", "name": "api", "replicas": 3, "kind": "StatefulSet"},
        {"namespace": "staging", "name": "api"},
        {"name": "api", "replicas": 3},
        {"namespace": "", "name": "api", "replicas": 3},
        {"namespace": "Staging", "name": "api", "replicas": 3},
        {"namespace": "staging/../prod", "name": "api", "replicas": 3},
        {"namespace": "staging", "name": "api/*", "replicas": 3},
        {"namespace": "staging", "name": "a" * 64, "replicas": 3},
        {"namespace": "staging", "name": 5, "replicas": 3},
        {"namespace": "staging", "name": "api", "replicas": 11},
        {"namespace": "staging", "name": "api", "replicas": 0},
        {"namespace": "staging", "name": "api", "replicas": True},
        {"namespace": "staging", "name": "api", "replicas": "3"},
        {"namespace": "staging", "name": "api", "replicas": 10**30},
    ],
)
def test_arguments_outside_the_catalog_schema_are_refused_before_decide(arguments):
    with pytest.raises(CallRefused) as refused:
        call("scale_deployment", arguments)
    assert refused.value.reason == "malformed_request"


def test_a_template_needs_a_schema_with_label_arguments_for_its_placeholders():
    with pytest.raises(ValueError, match="argument schema"):
        ToolRoute("k8s", "x", "k8s.x", "k8s/{namespace}/x")
    with pytest.raises(ValueError, match="label argument"):
        ToolRoute("k8s", "x", "k8s.x", "k8s/{namespace}/x/{name}", (Argument("namespace", "label"),))
    with pytest.raises(ValueError, match="label argument"):
        ToolRoute(
            "k8s", "x", "k8s.x", "k8s/{namespace}/x/{count}",
            (Argument("namespace", "label"), Argument("count", "integer", 0, 5)),
        )  # fmt: skip


def test_route_documents_accept_only_concrete_resources():
    with pytest.raises(ValueError, match="exactly the fields"):
        ToolRoutes.from_document(
            {
                "routes": [
                    {
                        "service": "k8s",
                        "name": "scale_deployment",
                        "tool": "k8s.deployments.scale",
                        "resource": "k8s/{namespace}/deployments/{name}",
                        "arguments": ["namespace", "name", "replicas"],
                    }
                ]
            }
        )
    with pytest.raises(ValueError, match="argument schema"):
        ToolRoutes.from_document(
            {"routes": [{"service": "k8s", "name": "x", "tool": "k8s.x", "resource": "k8s/{namespace}/x"}]}
        )


def test_a_concrete_route_ignores_arguments_as_before():
    route = ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api")
    assert route.resource_for({"anything": "goes"}) == "env/staging/api"


def test_check_config_requires_the_gateway_to_remove_the_release_header():
    def change(config):
        modifier = config["mcp"]["policies"]["requestHeaderModifier"]
        modifier["remove"] = [name for name in modifier["remove"] if name != "bailiff-release"]

    assert any("missing bailiff-release" in problem for problem in problems_after(change))
    assert "bailiff-release" in gateway_config()["mcp"]["policies"]["requestHeaderModifier"]["remove"]


def test_an_effector_only_deployment_can_start_without_credential_headers():
    CustodianProcessor(object(), ROUTES, frozenset())
    GatewayExpectations(
        decide_socket=Path("/run/d/decide.sock"),
        custodian_socket=Path("/run/c/custodian.sock"),
        services=frozenset({"k8s"}),
        credential_headers=frozenset(),
    )
