from pathlib import Path

import pytest
from test_agentgateway_calls import message
from test_agentgateway_config import REDACTOR_SOCKET, gateway_config, problems_after

from agent_bailiff.adapters.agentgateway.calls import CallRefused, read_call
from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor
from agent_bailiff.effector.catalog import Argument, OperationCatalog
from agent_bailiff.routes import ToolRoute, ToolRoutes, routes_from_catalog

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
        redactor_socket=Path("/run/c/redactor.sock"),
        services=frozenset({"k8s"}),
        credential_headers=frozenset(),
    )


def test_a_route_document_cannot_route_a_catalog_tool_to_a_fixed_resource():
    with pytest.raises(ValueError, match="routed only from their catalog"):
        ToolRoutes.from_document(
            {
                "routes": [
                    {
                        "service": "k8s",
                        "name": "scale_deployment",
                        "tool": "k8s.deployments.scale",
                        "resource": "k8s/staging/deployments/api",
                    }
                ]
            }
        )


def test_a_route_document_can_name_a_shipped_catalog():
    routes = ToolRoutes.from_document(
        {
            "routes": [{"service": "ops", "name": "deploy", "tool": "deploy.service", "resource": "env/staging/api"}],
            "catalogs": [{"service": "k8s", "name": "kubernetes"}],
        }
    )
    route = routes.route("k8s", "scale_deployment")
    assert route.tool == "k8s.deployments.scale"
    assert route.resource_for({"namespace": "staging", "name": "api", "replicas": 2}) == "k8s/staging/deployments/api"
    assert routes.route("ops", "deploy").resource == "env/staging/api"


@pytest.mark.parametrize(
    "catalogs",
    [
        [{"service": "k8s", "name": "../../etc/passwd"}],
        [{"service": "k8s", "name": "kubernetes", "path": "/tmp/x.json"}],
        [{"service": "k8s"}],
        {"service": "k8s", "name": "kubernetes"},
    ],
)
def test_a_route_document_refuses_unknown_or_malformed_catalogs(catalogs):
    with pytest.raises(ValueError):
        ToolRoutes.from_document({"routes": [], "catalogs": catalogs})


def test_the_cli_prints_the_shipped_catalog_digest(capsys):
    from agent_bailiff.cli import main
    from agent_bailiff.effector.catalog import OperationCatalog, shipped_catalog

    assert main(["effector", "digest"]) == 0
    assert capsys.readouterr().out.strip() == OperationCatalog.load(shipped_catalog("kubernetes")).digest


CATALOG = (
    "catalog service 'k8s' must target the effector over http on 127.0.0.1 or [::1]; "
    "releases and clearances must not leave the host"
)


@pytest.mark.parametrize(
    ("host", "problem"),
    [
        ("http://127.0.0.1:18080/mcp", None),
        ("http://localhost:18080/mcp", CATALOG),
        ("http://[::1]:18080/mcp", None),
        ("http://10.0.0.5:18080/mcp", CATALOG),
        ("https://127.0.0.1:18080/mcp", CATALOG),
        ("http://127.0.0.1.evil.example:18080/mcp", CATALOG),
        ("127.0.0.1", None),
        ("[::1]", None),
        ("[::1]:18080", None),
        ("localhost:18080", CATALOG),
        ("::1", "url must name a host"),
        ("10.0.0.5", CATALOG),
        ("127.0.0.1:abc", "url port must be a number from 1 to 65535"),
        ("127.0.0.1:99999", "url port must be a number from 1 to 65535"),
        ("127.0.0.1/@evil.com", "a host without a scheme must be host or host:port"),
        ("127.0.0.1?@evil.com", "url must not carry a query or fragment"),
        ("127.0.0.1#@evil.com", "url must not carry a query or fragment"),
        ("127.0.0.\t1", "url must not contain whitespace, control characters or backslashes"),
        ("http://127.0.0.1:abc/mcp", "url port must be a number from 1 to 65535"),
        ("http://127.0.0.1:18080/mcp?x=1", "url must not carry a query or fragment"),
        ("http://127.0.0.1:18080/mcp#x", "url must not carry a query or fragment"),
        ("http://::1/mcp", "url must name a host"),
        ("http://127.0.0.1\t/mcp", "url must not contain whitespace, control characters or backslashes"),
    ],
)
def test_check_config_requires_catalog_services_to_target_a_loopback_effector(host, problem):
    config = gateway_config(upstream=host, credential_headers=["bailiff-release"])
    config["mcp"]["targets"][0]["name"] = "k8s"
    expected = GatewayExpectations(
        Path("/run/bailiff/d/decide.sock"),
        Path("/run/bailiff/c/custodian.sock"),
        REDACTOR_SOCKET,
        frozenset({"k8s"}),
        frozenset(),
        frozenset({"k8s"}),
    )
    targets = ("catalog service", "mcp target")
    problems = [found for found in validate_gateway_config(config, expected) if found.startswith(targets)]
    wanted = [] if problem is None else [problem if problem == CATALOG else f"mcp target 'k8s' is malformed: {problem}"]
    assert problems == wanted


def test_catalog_services_are_the_services_with_catalog_routes():
    routes = ToolRoutes.from_document(
        {
            "routes": [{"service": "ops", "name": "deploy", "tool": "deploy.service", "resource": "env/staging/api"}],
            "catalogs": [{"service": "k8s", "name": "kubernetes"}],
        }
    )
    assert routes.catalog_services == frozenset({"k8s"})
