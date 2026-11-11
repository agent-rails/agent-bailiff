import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config

DECIDE_SOCKET = Path("/run/bailiff-decide/decide.sock")
CUSTODIAN_SOCKET = Path("/run/bailiff-custodian/custodian.sock")
CHAIN_HEADERS = ["x-bailiff-task-root", "x-bailiff-links", "x-bailiff-leaf-proof", "x-bailiff-nonce", "traceparent"]
EXPECTED = GatewayExpectations(
    decide_socket=DECIDE_SOCKET,
    custodian_socket=CUSTODIAN_SOCKET,
    services=frozenset({"deploy"}),
    credential_headers=frozenset({"X-Api-Key"}),
)


def gateway_config(
    decide_socket=DECIDE_SOCKET, custodian_socket=CUSTODIAN_SOCKET, upstream="http://127.0.0.1:8080/mcp"
):
    return {
        "config": {"adminAddr": "127.0.0.1:15000"},
        "mcp": {
            "port": 3000,
            "statefulMode": "stateless",
            "targets": [{"name": "deploy", "mcp": {"host": upstream}}],
            "policies": {
                "mcpGuardrails": {
                    "processors": [
                        {
                            "kind": "expression",
                            "methods": {"tools/call": "response"},
                            "condition": "true",
                            "transform": "mcp.result",
                        },
                        {
                            "kind": "remote",
                            "host": f"unix:{decide_socket}",
                            "methods": {"tools/call": "request"},
                            "failureMode": "failClosed",
                            "requestHeaders": {"allowed": list(CHAIN_HEADERS)},
                        },
                        {
                            "kind": "remote",
                            "host": f"unix:{custodian_socket}",
                            "methods": {"tools/call": "request"},
                            "requestHeaders": {"allowed": list(CHAIN_HEADERS)},
                            "metadata": {"clearance": "mcpGuardrails.clearance"},
                        },
                    ]
                }
            },
        },
    }


def processors(config):
    return config["mcp"]["policies"]["mcpGuardrails"]["processors"]


def problems_after(change):
    config = copy.deepcopy(gateway_config())
    change(config)
    return validate_gateway_config(config, EXPECTED)


def test_the_reference_config_passes():
    assert validate_gateway_config(gateway_config(), EXPECTED) == ()


@pytest.mark.parametrize("index", [1, 2])
def test_fail_open_is_refused(index):
    problems = problems_after(lambda config: processors(config)[index].update(failureMode="failOpen"))
    assert any("failClosed" in problem for problem in problems)


@pytest.mark.parametrize("index", [1, 2])
@pytest.mark.parametrize(
    "headers",
    [None, {}, {"allowed": []}, {"disallowed": ["authorization"]}],
)
def test_a_missing_or_empty_header_allowlist_is_refused(index, headers):
    def change(config):
        if headers is None:
            del processors(config)[index]["requestHeaders"]
        else:
            processors(config)[index]["requestHeaders"] = headers

    assert any("allowlist" in problem for problem in problems_after(change))


@pytest.mark.parametrize("extra", ["authorization", "Authorization", "cookie", ":authority"])
def test_an_allowlist_beyond_the_chain_headers_is_refused(extra):
    problems = problems_after(lambda config: processors(config)[1]["requestHeaders"]["allowed"].append(extra))
    assert any(extra in problem for problem in problems)


@pytest.mark.parametrize("missing", ["x-bailiff-task-root", "x-bailiff-leaf-proof", "x-bailiff-nonce"])
def test_an_allowlist_without_a_required_chain_header_is_refused(missing):
    problems = problems_after(lambda config: processors(config)[2]["requestHeaders"]["allowed"].remove(missing))
    assert any(missing in problem for problem in problems)


def test_custodian_before_decide_is_refused():
    problems = problems_after(lambda config: processors(config).reverse())
    assert any("order" in problem for problem in problems)


def test_a_processor_after_the_custodian_is_refused():
    extra = {"kind": "expression", "methods": {"tools/call": "request"}, "reject": "no"}
    problems = problems_after(lambda config: processors(config).append(extra))
    assert any("order" in problem for problem in problems)


def test_a_processor_between_decide_and_custodian_is_refused():
    extra = {"kind": "expression", "methods": {"tools/call": "request"}, "transform": "mcp.params"}
    problems = problems_after(lambda config: processors(config).insert(2, extra))
    assert any("order" in problem for problem in problems)


@pytest.mark.parametrize(
    "host", ["127.0.0.1:9000", "unix:/tmp/other.sock", "unix:run/bailiff-custodian/custodian.sock"]
)
def test_a_custodian_not_on_its_unix_socket_is_refused(host):
    problems = problems_after(lambda config: processors(config)[2].update(host=host))
    assert any("custodian" in problem for problem in problems)


def test_a_missing_decide_processor_is_refused():
    problems = problems_after(lambda config: processors(config).pop(1))
    assert any("decide" in problem for problem in problems)


def test_a_duplicate_custodian_processor_is_refused():
    problems = problems_after(lambda config: processors(config).insert(0, copy.deepcopy(processors(config)[2])))
    assert any("exactly one" in problem for problem in problems)


@pytest.mark.parametrize(
    "methods",
    [
        {"tools/call": "full"},
        {"tools/*": "request"},
        {"*": "request"},
        {"tools/call": "request", "tools/list": "request"},
    ],
)
def test_processor_methods_must_be_exactly_tools_call_request(methods):
    problems = problems_after(lambda config: processors(config)[1].update(methods=methods))
    assert any("methods" in problem for problem in problems)


@pytest.mark.parametrize(
    "metadata",
    [None, {}, {"clearance": "mcpGuardrails.other"}, {"clearance": "mcpGuardrails.clearance", "extra": "1"}],
)
def test_the_custodian_clearance_expression_is_required(metadata):
    def change(config):
        if metadata is None:
            del processors(config)[2]["metadata"]
        else:
            processors(config)[2]["metadata"] = metadata

    assert any("clearance" in problem for problem in problems_after(change))


def test_decide_takes_no_metadata():
    problems = problems_after(lambda config: processors(config)[1].update(metadata={"x": "request.headers"}))
    assert any("metadata" in problem for problem in problems)


@pytest.mark.parametrize("key", ["policies", "service", "backend"])
def test_unknown_bailiff_processor_fields_are_refused(key):
    problems = problems_after(lambda config: processors(config)[2].update({key: {}}))
    assert any(key in problem for problem in problems)


@pytest.mark.parametrize(
    "where",
    [
        lambda config: processors(config)[0].update(condition='request.headers["x-api-key"] != ""'),
        lambda config: config["mcp"]["policies"].update(
            mcpAuthorization={"rules": ['has(request.headers["X-API-KEY"])']}
        ),
        lambda config: config["config"].update(logging={"fields": {"add": {"key": "request.headers.x-api-key"}}}),
        lambda config: config["config"].update(logging={"fields": {"add": {"x-api-key": "1"}}}),
    ],
)
def test_the_credential_header_name_anywhere_in_the_config_is_refused(where):
    problems = problems_after(where)
    assert any("X-Api-Key" in problem for problem in problems)


def test_a_header_name_inside_a_longer_token_is_not_a_match():
    expected = GatewayExpectations(DECIDE_SOCKET, CUSTODIAN_SOCKET, frozenset({"deploy"}), frozenset({"authorization"}))
    config = gateway_config()
    config["mcp"]["policies"]["mcpAuthorization"] = {"rules": ["true"]}
    assert validate_gateway_config(config, expected) == ()


def test_a_stdio_upstream_for_a_gateway_bound_service_is_refused():
    def change(config):
        config["mcp"]["targets"] = [{"name": "deploy", "stdio": {"cmd": "deploy-mcp"}}]

    assert any("deploy" in problem and "mcp" in problem for problem in problems_after(change))


def test_a_missing_gateway_bound_service_is_refused():
    problems = problems_after(lambda config: config["mcp"].update(targets=[{"name": "other", "mcp": {"host": "x"}}]))
    assert any("deploy" in problem for problem in problems)


def test_a_duplicate_target_name_is_refused():
    def change(config):
        config["mcp"]["targets"].append({"name": "deploy", "mcp": {"host": "http://127.0.0.1:9/mcp"}})

    assert any("deploy" in problem for problem in problems_after(change))


@pytest.mark.parametrize(
    "change",
    [
        lambda config: config.update(binds=[]),
        lambda config: config.update(policies=[]),
        lambda config: config["config"].update(xdsAddress="https://xds"),
        lambda config: config["mcp"].update(gateways="default"),
        lambda config: config["mcp"]["policies"].update(requestMirror={}),
        lambda config: config["mcp"]["policies"].update(transformations={}),
        lambda config: config["mcp"]["policies"].update(backendAuth={}),
        lambda config: config["mcp"]["policies"].update(extProc={}),
        lambda config: config["mcp"]["targets"][0].update(policies={"backendAuth": {}}),
        lambda config: config["mcp"]["targets"][0].update(policies={"requestHeaderModifier": {}}),
        lambda config: config["mcp"]["targets"][0]["mcp"].update(backend="b"),
    ],
)
def test_config_outside_the_validated_surface_is_refused(change):
    assert problems_after(change)


@pytest.mark.parametrize("document", [[], "x", None, {}, {"mcp": []}, {"mcp": {"policies": {}}}])
def test_malformed_documents_are_refused(document):
    assert validate_gateway_config(document, EXPECTED)


@pytest.mark.parametrize(
    "options",
    [
        {"decide_socket": Path("relative.sock")},
        {"custodian_socket": Path("relative.sock")},
        {"custodian_socket": DECIDE_SOCKET},
        {"services": frozenset()},
        {"credential_headers": frozenset()},
        {"credential_headers": frozenset({"bad header"})},
    ],
)
def test_expectations_are_validated(options):
    fields = {
        "decide_socket": DECIDE_SOCKET,
        "custodian_socket": CUSTODIAN_SOCKET,
        "services": frozenset({"deploy"}),
        "credential_headers": frozenset({"X-Api-Key"}),
    }
    with pytest.raises(ValueError):
        GatewayExpectations(**{**fields, **options})


@pytest.fixture
def owned_files():
    directory = Path(tempfile.mkdtemp(prefix="bk-", dir="/tmp"))
    os.chmod(directory, 0o700)

    def write(name, document, mode=0o600):
        path = directory / name
        path.write_text(document if isinstance(document, str) else json.dumps(document))
        os.chmod(path, mode)
        return path

    yield write
    shutil.rmtree(directory)


def run_check(owned_files, config_document):
    routes = owned_files(
        "routes.json",
        {"routes": [{"service": "deploy", "name": "deploy_service", "tool": "deploy.service", "resource": "env/a"}]},
    )
    bindings = owned_files(
        "bindings.json",
        {
            "bindings": [
                {
                    "tenant": "tenant-a",
                    "tool": "deploy.service",
                    "resource": "env/*",
                    "credential_id": "deploy-api",
                    "target": "deploy.example",
                    "header_name": "X-Api-Key",
                    "canary": False,
                }
            ]
        },
    )
    gateway = owned_files("gateway.json", config_document, mode=0o644)
    command = [
        sys.executable,
        "-m",
        "agent_bailiff.adapters.agentgateway",
        "check-config",
        "--gateway-config",
        str(gateway),
        "--routes",
        str(routes),
        "--bindings",
        str(bindings),
        "--decide-socket",
        str(DECIDE_SOCKET),
        "--custodian-socket",
        str(CUSTODIAN_SOCKET),
    ]
    return subprocess.run(command, capture_output=True, text=True, timeout=60)


def test_check_config_accepts_the_reference_config(owned_files):
    result = run_check(owned_files, gateway_config())
    assert (result.returncode, result.stdout.strip()) == (0, "ok"), result.stderr


def test_check_config_refuses_and_lists_problems(owned_files):
    config = gateway_config()
    processors(config)[2]["failureMode"] = "failOpen"
    result = run_check(owned_files, config)
    assert result.returncode == 1
    assert "failClosed" in result.stderr


@pytest.mark.parametrize("text", ["{", '{"mcp": {}, "mcp": {}}', '{"mcp": NaN}'])
def test_check_config_refuses_an_unreadable_gateway_config(owned_files, text):
    result = run_check(owned_files, text)
    assert result.returncode == 1
    assert "gateway config" in result.stderr
