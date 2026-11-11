import json

import pytest

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.calls import CallRefused, ToolRoute, ToolRoutes, read_call
from agent_bailiff.decide import OperationRequest

ROUTES = ToolRoutes(
    [
        ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api"),
        ToolRoute("deploy", "delete_service", "deploy.delete", "env/staging/api"),
    ]
)
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
HEADERS = {
    "x-bailiff-task-root": "root.token",
    "x-bailiff-links": "link-1.token,link-2.token",
    "x-bailiff-leaf-proof": "proof.token",
    "x-bailiff-nonce": "n-1",
    "traceparent": f"00-{TRACE}-00f067aa0ba902b7-01",
}
PARAMS = {"name": "deploy_service", "arguments": {"service": "api", "replicas": 2}}


def message(*, params=PARAMS, headers=HEADERS, services=("deploy",), raw=None, extra_headers=()):
    pairs = [(key, value.encode() if isinstance(value, str) else value) for key, value in headers.items()]
    pairs.extend(extra_headers)
    fields = {
        "service_names": list(services),
        "method": "tools/call",
        "headers": [ext_mcp_pb2.McpHeader(key=key, value=value) for key, value in pairs],
    }
    if raw is not None:
        fields["mcp_request"] = raw
    elif params is not None:
        fields["mcp_request"] = json.dumps(params).encode()
    return ext_mcp_pb2.McpRequest(**fields)


def refusal(request):
    with pytest.raises(CallRefused) as caught:
        read_call(request, ROUTES)
    return caught.value.reason


def test_reads_a_call_into_an_operation_request():
    assert read_call(message(), ROUTES) == OperationRequest(
        tool="deploy.service",
        resource="env/staging/api",
        args={"service": "api", "replicas": 2},
        nonce="n-1",
        task_root="root.token",
        links=("link-1.token", "link-2.token"),
        leaf_proof="proof.token",
        trace_id=TRACE,
    )


def test_links_header_is_optional():
    headers = {key: value for key, value in HEADERS.items() if key != "x-bailiff-links"}
    assert read_call(message(headers=headers), ROUTES).links == ()


def test_header_names_match_case_insensitively():
    headers = {key.upper(): value for key, value in HEADERS.items()}
    assert read_call(message(headers=headers), ROUTES).nonce == "n-1"


def test_missing_arguments_read_as_an_empty_object():
    assert read_call(message(params={"name": "deploy_service"}), ROUTES).args == {}


def test_other_headers_are_ignored():
    request = message(extra_headers=[("authorization", b"Bearer agent"), ("x-other", b"\xff")])
    assert read_call(request, ROUTES).leaf_proof == "proof.token"


@pytest.mark.parametrize("value", ["", "01-" + TRACE + "-00f067aa0ba902b7-01", "00-" + TRACE.upper() + "-0-01"])
def test_an_invalid_traceparent_leaves_the_trace_id_empty(value):
    assert read_call(message(headers={**HEADERS, "traceparent": value or "x"}), ROUTES).trace_id == ""


@pytest.mark.parametrize("name", ["x-bailiff-task-root", "x-bailiff-leaf-proof", "x-bailiff-nonce"])
def test_a_missing_required_header_is_refused(name):
    headers = {key: value for key, value in HEADERS.items() if key != name}
    assert refusal(message(headers=headers)) == "malformed_request"


@pytest.mark.parametrize("name", sorted(HEADERS))
def test_a_repeated_call_header_is_refused(name):
    assert refusal(message(extra_headers=[(name, HEADERS[name].encode())])) == "malformed_request"


@pytest.mark.parametrize("value", [b"", b"n 1", "né".encode(), b"\xff"])
def test_a_call_header_that_is_not_printable_ascii_is_refused(value):
    assert refusal(message(headers={**HEADERS, "x-bailiff-nonce": value})) == "malformed_request"


@pytest.mark.parametrize("links", [",link-1", "link-1,", "link-1,,link-2"])
def test_an_empty_link_is_refused(links):
    assert refusal(message(headers={**HEADERS, "x-bailiff-links": links})) == "malformed_request"


def test_a_tool_routed_for_another_service_is_refused():
    assert refusal(message(services=("attacker",))) == "unknown_tool"


def test_an_unrouted_tool_is_refused():
    assert refusal(message(params={"name": "drop_tables", "arguments": {}})) == "unknown_tool"


@pytest.mark.parametrize("services", [(), ("deploy", "deploy")])
def test_a_call_must_name_exactly_one_service(services):
    assert refusal(message(services=services)) == "malformed_request"


@pytest.mark.parametrize(
    "raw",
    [
        None,
        b"[]",
        b"not json",
        b'{"name": "deploy_service", "name": "delete_service"}',
        b'{"name": "deploy_service", "arguments": {"replicas": NaN}}',
        b'{"arguments": {}}',
        b'{"name": "", "arguments": {}}',
        b'{"name": 1, "arguments": {}}',
        b'{"name": "deploy_service", "arguments": []}',
        b'{"name": "deploy_service", "arguments": null}',
        b"\xff",
    ],
)
def test_malformed_params_are_refused(raw):
    request = message(params=None) if raw is None else message(raw=raw)
    assert refusal(request) == "malformed_request"


def test_oversized_params_are_refused():
    params = {"name": "deploy_service", "arguments": {"blob": "a" * 200_000}}
    assert refusal(message(params=params)) == "malformed_request"


def test_routes_refuse_a_duplicate_service_and_name():
    route = ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api")
    with pytest.raises(ValueError, match="duplicate"):
        ToolRoutes([route, route])


@pytest.mark.parametrize(
    "fields",
    [
        {"tool": "deploy.*"},
        {"resource": "env/staging/*"},
        {"service": ""},
        {"name": "deploy service"},
        {"tool": 1},
    ],
)
def test_route_fields_must_be_concrete(fields):
    options = {"service": "deploy", "name": "deploy_service", "tool": "deploy.service", "resource": "env/staging/api"}
    with pytest.raises(ValueError):
        ToolRoute(**{**options, **fields})


def test_routes_load_from_a_strict_document():
    routes = ToolRoutes.from_document(
        {"routes": [{"service": "deploy", "name": "deploy_service", "tool": "deploy.service", "resource": "env/a"}]}
    )
    assert routes.services == frozenset({"deploy"})
    assert routes.route("deploy", "deploy_service") == ToolRoute("deploy", "deploy_service", "deploy.service", "env/a")


@pytest.mark.parametrize(
    "document",
    [
        [],
        {},
        {"routes": [], "extra": 1},
        {"routes": {}},
        {"routes": [{"service": "deploy", "name": "n", "tool": "t"}]},
        {"routes": [{"service": "deploy", "name": "n", "tool": "t", "resource": "r", "extra": 1}]},
    ],
)
def test_route_documents_with_wrong_shape_are_refused(document):
    with pytest.raises(ValueError):
        ToolRoutes.from_document(document)
