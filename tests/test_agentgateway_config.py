import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agent_bailiff.adapters.agentgateway.config_check import (
    REFUSAL_GUARD,
    GatewayExpectations,
    validate_gateway_config,
)
from agent_bailiff.client.client import REFUSAL_REASONS

DECIDE_SOCKET = Path("/run/bailiff-decide/decide.sock")
CUSTODIAN_SOCKET = Path("/run/bailiff-custodian/custodian.sock")
REDACTOR_SOCKET = Path("/run/bailiff-custodian/redactor.sock")
DECIDE, CUSTODIAN, REDACTOR, GUARD = range(4)
TIMEOUTS = {"requestTimeout": "30s", "backendRequestTimeout": "30s"}
CHAIN_HEADERS = ["x-bailiff-task-root", "x-bailiff-links", "x-bailiff-leaf-proof", "x-bailiff-nonce", "traceparent"]
EXPECTED = GatewayExpectations(
    decide_socket=DECIDE_SOCKET,
    custodian_socket=CUSTODIAN_SOCKET,
    redactor_socket=REDACTOR_SOCKET,
    services=frozenset({"deploy"}),
    credential_headers=frozenset({"X-Api-Key"}),
)


METHOD_RULE = 'mcp.methodName == "tools/call" || mcp.methodName == "tools/list"'
AGENT_CREDENTIALS = ["authorization", "proxy-authorization", "cookie", "bailiff-release"]


def gateway_config(
    decide_socket=DECIDE_SOCKET,
    custodian_socket=CUSTODIAN_SOCKET,
    upstream="http://127.0.0.1:8080/mcp",
    credential_headers=("X-Api-Key",),
    redactor_socket=REDACTOR_SOCKET,
):
    return {
        "config": {"adminAddr": "127.0.0.1:15000"},
        "frontendPolicies": {"accessLog": {"remove": ["mcp.error.message"]}},
        "mcp": {
            "port": 3000,
            "statefulMode": "stateless",
            "targets": [{"name": "deploy", "mcp": {"host": upstream}}],
            "policies": {
                "mcpAuthorization": {"rules": [METHOD_RULE]},
                "requestHeaderModifier": {"remove": [*AGENT_CREDENTIALS, *credential_headers]},
                "timeout": dict(TIMEOUTS),
                "mcpGuardrails": {
                    "processors": [
                        {
                            "kind": "remote",
                            "host": f"unix:{decide_socket}",
                            "methods": {"*": "request"},
                            "failureMode": "failClosed",
                            "requestHeaders": {"allowed": list(CHAIN_HEADERS)},
                        },
                        {
                            "kind": "remote",
                            "host": f"unix:{custodian_socket}",
                            "methods": {"*": "request"},
                            "metadata": {"clearance": "mcpGuardrails.clearance"},
                        },
                        {
                            "kind": "remote",
                            "host": f"unix:{redactor_socket}",
                            "methods": {"tools/call": "response"},
                            "failureMode": "failClosed",
                            "metadata": {"clearance": "mcpGuardrails.clearance"},
                        },
                        dict(REFUSAL_GUARD),
                    ]
                },
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


@pytest.mark.parametrize("mode", [None, "stateful", "Stateless", 1])
def test_a_gateway_not_in_stateless_mode_is_refused(mode):
    def change(config):
        if mode is None:
            del config["mcp"]["statefulMode"]
        else:
            config["mcp"]["statefulMode"] = mode

    assert any("statefulMode" in problem for problem in problems_after(change))


@pytest.mark.parametrize("index", [DECIDE, CUSTODIAN, REDACTOR])
def test_fail_open_is_refused(index):
    problems = problems_after(lambda config: processors(config)[index].update(failureMode="failOpen"))
    assert any("failClosed" in problem for problem in problems)


@pytest.mark.parametrize(
    "headers",
    [None, {}, {"allowed": []}, {"disallowed": ["authorization"]}],
)
def test_a_missing_or_empty_decide_header_allowlist_is_refused(headers):
    def change(config):
        if headers is None:
            del processors(config)[DECIDE]["requestHeaders"]
        else:
            processors(config)[DECIDE]["requestHeaders"] = headers

    assert any("allowlist" in problem for problem in problems_after(change))


@pytest.mark.parametrize(
    "headers", [{}, {"allowed": list(CHAIN_HEADERS)}, {"disallowed": ["sudo"]}, {"allowed": ["x-bailiff-nonce"]}]
)
def test_a_custodian_header_filter_is_refused(headers):
    problems = problems_after(lambda config: processors(config)[CUSTODIAN].update(requestHeaders=headers))
    assert any("custodian processor must not filter requestHeaders" in problem for problem in problems)


@pytest.mark.parametrize("extra", ["authorization", "Authorization", "cookie", ":authority"])
def test_an_allowlist_beyond_the_chain_headers_is_refused(extra):
    problems = problems_after(lambda config: processors(config)[DECIDE]["requestHeaders"]["allowed"].append(extra))
    assert any(extra in problem for problem in problems)


@pytest.mark.parametrize("missing", ["x-bailiff-task-root", "x-bailiff-leaf-proof", "x-bailiff-nonce"])
def test_an_allowlist_without_a_required_chain_header_is_refused(missing):
    problems = problems_after(lambda config: processors(config)[DECIDE]["requestHeaders"]["allowed"].remove(missing))
    assert any(missing in problem for problem in problems)


@pytest.mark.parametrize(
    "change",
    [
        lambda processors: processors.pop(GUARD),
        lambda processors: processors[GUARD].update(condition="false"),
        lambda processors: processors[GUARD].update(methods={"*": "response"}),
        lambda processors: processors[GUARD].pop("reject"),
        lambda processors: processors.insert(
            1,
            {
                "kind": "expression",
                "methods": {"tools/call": "response"},
                "condition": "true",
                "transform": "mcp.result",
            },
        ),
        lambda processors: processors[DECIDE].update(methods={"*": "request", "tools/call": "response"}),
        lambda processors: processors[GUARD].update(methods={"tools/call": "full"}),
        lambda processors: processors.insert(
            1,
            {
                "kind": "expression",
                "methods": {"tools/call": "full"},
                "condition": "true",
                "transform": "mcp.result",
            },
        ),
        lambda processors: processors.insert(
            1,
            {"kind": "remote", "host": "unix:/run/other.sock", "methods": {"*": "full"}, "failureMode": "failClosed"},
        ),
    ],
)
def test_a_missing_or_weakened_refusal_guard_is_refused(change):
    problems = problems_after(lambda config: change(processors(config)))
    assert any("refusal guard" in problem for problem in problems)


def test_every_refusal_reason_is_a_plain_cel_string():
    assert all(re.fullmatch("[a-z_]+", reason) for reason in REFUSAL_REASONS)


def test_the_response_phase_may_come_before_the_request_phase():
    def change(config):
        decide, custodian, redactor, guard = processors(config)
        processors(config)[:] = [redactor, guard, decide, custodian]

    assert problems_after(change) == ()


def test_a_request_phase_processor_before_decide_is_accepted():
    extra = {"kind": "expression", "methods": {"tools/call": "request"}, "reject": "no"}
    assert problems_after(lambda config: processors(config).insert(DECIDE, extra)) == ()


def test_a_request_phase_processor_after_the_custodian_is_refused_even_past_the_response_phase():
    extra = {"kind": "expression", "methods": {"tools/call": "request"}, "reject": "no"}
    problems = problems_after(lambda config: processors(config).insert(GUARD, extra))
    assert any("order" in problem for problem in problems)


@pytest.mark.parametrize(
    "change",
    [
        lambda processors: processors.pop(REDACTOR),
        lambda processors: processors.append(processors.pop(REDACTOR)),
        lambda processors: processors.insert(0, copy.deepcopy(processors[REDACTOR])),
        lambda processors: processors[REDACTOR].update(host="unix:/run/other.sock"),
        lambda processors: processors[REDACTOR].update(methods={"tools/call": "full"}),
        lambda processors: processors[REDACTOR].update(methods={"*": "response"}),
        lambda processors: processors[REDACTOR].update(methods={"tools/call": "response", "tools/list": "response"}),
        lambda processors: processors[REDACTOR].update(failureMode="failOpen"),
        lambda processors: processors[REDACTOR].pop("metadata"),
        lambda processors: processors[REDACTOR].update(metadata={"clearance": "mcpGuardrails.other"}),
        lambda processors: processors[REDACTOR].update(requestHeaders={"allowed": ["x-bailiff-nonce"]}),
        lambda processors: processors[REDACTOR].update(kind="expression"),
    ],
)
def test_a_missing_misplaced_or_weakened_redactor_is_refused(change):
    problems = problems_after(lambda config: change(processors(config)))
    assert any("redactor" in problem for problem in problems), problems


def test_a_redactor_on_the_custodian_socket_is_refused():
    def change(config):
        processors(config)[REDACTOR]["host"] = f"unix:{CUSTODIAN_SOCKET}"

    assert any("redactor" in problem for problem in problems_after(change))


@pytest.mark.parametrize("value", ["30s", "120s", "2m", "500ms", "1s"])
def test_upstream_timeouts_up_to_two_minutes_are_accepted(value):
    def change(config):
        config["mcp"]["policies"]["timeout"] = {"requestTimeout": value, "backendRequestTimeout": value}

    assert problems_after(change) == ()


def test_a_response_idle_timeout_is_accepted():
    def change(config):
        config["mcp"]["policies"]["timeout"]["responseIdleTimeout"] = "2m"

    assert problems_after(change) == ()


@pytest.mark.parametrize(
    "timeout",
    [
        None,
        {},
        "30s",
        {"requestTimeout": "30s"},
        {"backendRequestTimeout": "30s"},
        {"requestTimeout": "30s", "backendRequestTimeout": "121s"},
        {"requestTimeout": "3m", "backendRequestTimeout": "30s"},
        {"requestTimeout": "30", "backendRequestTimeout": "30s"},
        {"requestTimeout": 30, "backendRequestTimeout": "30s"},
        {"requestTimeout": "0s", "backendRequestTimeout": "30s"},
        {"requestTimeout": "30s", "backendRequestTimeout": "1h"},
        {"requestTimeout": "1m30s", "backendRequestTimeout": "30s"},
        {"requestTimeout": " 30s", "backendRequestTimeout": "30s"},
        {"requestTimeout": "30s", "backendRequestTimeout": "30s", "responseIdleTimeout": "soon"},
        {"requestTimeout": "30s", "backendRequestTimeout": "30s", "responseIdleTimeout": "121s"},
        {"requestTimeout": "30s", "backendRequestTimeout": "30s", "idleTimeout": "30s"},
    ],
)
def test_missing_or_unbounded_upstream_timeouts_are_refused(timeout):
    def change(config):
        if timeout is None:
            del config["mcp"]["policies"]["timeout"]
        else:
            config["mcp"]["policies"]["timeout"] = timeout

    assert any("timeout" in problem for problem in problems_after(change))


def test_a_logging_level_and_format_are_accepted():
    def change(config):
        config["config"]["logging"] = {"level": "debug", "format": "json"}

    assert problems_after(change) == ()


@pytest.mark.parametrize(
    "logging",
    [
        None,
        "info",
        {"fields": {"add": {"auth": "request.headers.authorization"}}},
        {"filter": "true"},
        {"database": {"url": "postgres://bailiff@127.0.0.1/logs"}},
        {"level": "info", "fields": {"remove": ["mcp.error.message"]}},
    ],
)
def test_logging_that_adds_filters_or_ships_access_log_fields_is_refused(logging):
    def change(config):
        config["config"]["logging"] = logging

    assert any("config.logging" in problem for problem in problems_after(change))


def test_tracing_and_metrics_without_fields_are_accepted():
    def change(config):
        config["config"]["tracing"] = {"otlpEndpoint": "http://127.0.0.1:4317"}
        config["config"]["metrics"] = {"remove": ["gen_ai.request.model"]}

    assert problems_after(change) == ()


@pytest.mark.parametrize(
    ("key", "telemetry"),
    [
        ("tracing", {"otlpEndpoint": "http://127.0.0.1:4317", "fields": {"add": {"err": "mcp.error.message"}}}),
        ("metrics", {"fields": {"add": {"err": "mcp.error.message"}}}),
        ("tracing", None),
        ("metrics", []),
    ],
)
def test_tracing_or_metrics_that_add_fields_are_refused(key, telemetry):
    def change(config):
        config["config"][key] = telemetry

    assert any(
        problem.startswith(f"config.{key} must be an object without fields") for problem in problems_after(change)
    )


ACCESS_LOG_PROBLEMS = ("frontendPolicies must be exactly", "frontendPolicies.accessLog.remove is missing")


def test_an_access_log_removing_more_fields_is_accepted():
    def change(config):
        config["frontendPolicies"]["accessLog"]["remove"].append("http.path")

    assert problems_after(change) == ()


@pytest.mark.parametrize(
    "frontend",
    [
        None,
        {},
        [],
        {"accessLog": None},
        {"accessLog": {}},
        {"accessLog": {"remove": []}},
        {"accessLog": {"remove": ["http.path"]}},
        {"accessLog": {"remove": "mcp.error.message"}},
        {"accessLog": {"remove": ["mcp.error.message", 1]}},
        {"accessLog": {"remove": ["mcp.error.message", "mcp.error.message"]}},
        {"accessLog": {"remove": ["MCP.ERROR.MESSAGE"]}},
        {"logging": {"remove": ["mcp.error.message"]}},
        {"accessLog": {"remove": ["mcp.error.message"]}, "tracing": {}},
        {"accessLog": {"remove": ["mcp.error.message"], "preset": "otel"}},
        {"accessLog": {"remove": ["mcp.error.message"], "add": {"auth": "request.headers.authorization"}}},
        {"accessLog": {"remove": ["mcp.error.message"], "filter": "true"}},
        {"accessLog": {"remove": ["mcp.error.message"], "otlp": {}}},
    ],
)
def test_an_access_log_that_can_keep_upstream_error_text_is_refused(frontend):
    def change(config):
        if frontend is None:
            del config["frontendPolicies"]
        else:
            config["frontendPolicies"] = frontend

    assert any(problem.startswith(ACCESS_LOG_PROBLEMS) for problem in problems_after(change))


def test_check_config_refuses_a_redactor_on_another_socket(owned_files):
    result = run_check(owned_files, gateway_config(redactor_socket=Path("/run/other/redactor.sock")))
    assert result.returncode == 1
    assert "redactor" in result.stderr


def test_custodian_before_decide_is_refused():
    problems = problems_after(lambda config: processors(config).reverse())
    assert any("order" in problem for problem in problems)


def test_a_processor_after_the_custodian_is_refused():
    extra = {"kind": "expression", "methods": {"tools/call": "request"}, "reject": "no"}
    problems = problems_after(lambda config: processors(config).insert(REDACTOR, extra))
    assert any("order" in problem for problem in problems)


def test_a_processor_between_decide_and_custodian_is_refused():
    extra = {"kind": "expression", "methods": {"tools/call": "request"}, "transform": "mcp.params"}
    problems = problems_after(lambda config: processors(config).insert(CUSTODIAN, extra))
    assert any("order" in problem for problem in problems)


@pytest.mark.parametrize(
    "host", ["127.0.0.1:9000", "unix:/tmp/other.sock", "unix:run/bailiff-custodian/custodian.sock"]
)
def test_a_custodian_not_on_its_unix_socket_is_refused(host):
    problems = problems_after(lambda config: processors(config)[CUSTODIAN].update(host=host))
    assert any("custodian" in problem for problem in problems)


def test_a_missing_decide_processor_is_refused():
    problems = problems_after(lambda config: processors(config).pop(DECIDE))
    assert any("decide" in problem for problem in problems)


def test_a_duplicate_custodian_processor_is_refused():
    problems = problems_after(lambda config: processors(config).insert(0, copy.deepcopy(processors(config)[CUSTODIAN])))
    assert any("exactly one" in problem for problem in problems)


@pytest.mark.parametrize(
    "methods",
    [
        {"tools/call": "request"},
        {"*": "full"},
        {"*": "response"},
        {"tools/*": "request"},
        {"*": "request", "tools/call": "request"},
        {"*": "request", "notifications/*": "off"},
    ],
)
def test_processor_methods_must_be_exactly_every_method_request(methods):
    problems = problems_after(lambda config: processors(config)[DECIDE].update(methods=methods))
    assert any("methods" in problem for problem in problems)


@pytest.mark.parametrize(
    "metadata",
    [None, {}, {"clearance": "mcpGuardrails.other"}, {"clearance": "mcpGuardrails.clearance", "extra": "1"}],
)
def test_the_custodian_clearance_expression_is_required(metadata):
    def change(config):
        if metadata is None:
            del processors(config)[CUSTODIAN]["metadata"]
        else:
            processors(config)[CUSTODIAN]["metadata"] = metadata

    assert any("clearance" in problem for problem in problems_after(change))


def test_decide_takes_no_metadata():
    problems = problems_after(lambda config: processors(config)[DECIDE].update(metadata={"x": "request.headers"}))
    assert any("metadata" in problem for problem in problems)


@pytest.mark.parametrize("key", ["policies", "service", "backend"])
def test_unknown_bailiff_processor_fields_are_refused(key):
    problems = problems_after(lambda config: processors(config)[CUSTODIAN].update({key: {}}))
    assert any(key in problem for problem in problems)


@pytest.mark.parametrize(
    "where",
    [
        lambda config: processors(config)[GUARD].update(condition='request.headers["x-api-key"] != ""'),
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


def test_a_header_name_inside_a_longer_token_or_the_remove_list_is_not_a_match():
    expected = GatewayExpectations(
        DECIDE_SOCKET, CUSTODIAN_SOCKET, REDACTOR_SOCKET, frozenset({"deploy"}), frozenset({"authorization"})
    )
    assert validate_gateway_config(gateway_config(credential_headers=()), expected) == ()


def test_the_credential_header_in_the_remove_list_is_not_flagged():
    assert validate_gateway_config(gateway_config(), EXPECTED) == ()


def modifier(config):
    return config["mcp"]["policies"]["requestHeaderModifier"]


@pytest.mark.parametrize(
    "change",
    [
        lambda config: config["mcp"]["policies"].pop("mcpAuthorization"),
        lambda config: config["mcp"]["policies"].update(mcpAuthorization={"rules": ["true"]}),
        lambda config: config["mcp"]["policies"].update(mcpAuthorization={"rules": [METHOD_RULE, "true"]}),
        lambda config: config["mcp"]["policies"].update(mcpAuthorization={"rules": [{"allow": METHOD_RULE}]}),
        lambda config: config["mcp"]["policies"]["mcpAuthorization"].update(extra=1),
    ],
)
def test_the_method_rule_is_required_exactly(change):
    assert any("mcpAuthorization" in problem for problem in problems_after(change))


@pytest.mark.parametrize(
    "change",
    [
        lambda config: config["mcp"]["policies"].pop("requestHeaderModifier"),
        lambda config: modifier(config).update(add={"x-a": "1"}),
        lambda config: modifier(config).update(set={"x-a": "1"}),
        lambda config: modifier(config).update(remove="authorization"),
        lambda config: modifier(config).update(remove=[1]),
        lambda config: modifier(config).update(remove=dict.fromkeys(modifier(config)["remove"], 1)),
        lambda config: modifier(config)["remove"].remove("authorization"),
        lambda config: modifier(config)["remove"].remove("proxy-authorization"),
        lambda config: modifier(config)["remove"].remove("cookie"),
        lambda config: modifier(config)["remove"].remove("X-Api-Key"),
        lambda config: modifier(config)["remove"].append("x-bailiff-nonce"),
        lambda config: modifier(config)["remove"].append("X-Bailiff-Links"),
        lambda config: modifier(config)["remove"].append("x-bailiff-anything"),
        lambda config: modifier(config)["remove"].append("traceparent"),
    ],
)
def test_the_header_modifier_must_only_strip_agent_credentials(change):
    assert any(problem.startswith("mcp.policies.requestHeaderModifier") for problem in problems_after(change))


def test_the_header_modifier_matches_names_case_insensitively():
    def change(config):
        modifier(config)["remove"] = [
            "Authorization",
            "PROXY-AUTHORIZATION",
            "Cookie",
            "Bailiff-Release",
            "x-api-key",
            "x-extra",
        ]

    assert problems_after(change) == ()


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
    "target",
    [
        {"host": "https://mcp.example.com/mcp"},
        {"host": "https://10.0.0.5:8443/mcp"},
        {"host": "http://127.0.0.1:8080/mcp"},
        {"host": "http://localhost:8080/mcp"},
        {"host": "http://[::1]:8080/mcp"},
        {"host": "127.0.0.1"},
        {"host": "[::1]", "port": 8080, "path": "/mcp"},
        {"host": "[::1]:8080"},
    ],
)
def test_a_gateway_bound_target_over_https_or_loopback_is_accepted(target):
    assert problems_after(lambda config: config["mcp"]["targets"][0].update(mcp=target)) == ()


@pytest.mark.parametrize(
    "target",
    [
        {"host": "http://gitea-mcp:8080/mcp"},
        {"host": "gitea-mcp:8080"},
        {"host": "gitea-mcp", "port": 8080, "path": "/mcp"},
        {"host": "http://gitea-mcp.local:8080/mcp"},
        {"host": "http://mcp.example.com/mcp"},
        {"host": "http://mcp.example.com:8080/mcp"},
        {"host": "http://10.0.0.5:8080/mcp"},
        {"host": "http://[2001:db8::1]:8080/mcp"},
        {"host": "http://127.0.0.1.evil.example/mcp"},
        {"host": "http://167772165:8080/mcp"},
        {"host": "http://0xa000005:8080/mcp"},
        {"host": "http://gitea-mcp@10.0.0.5:8080/mcp"},
        {"host": "http://user@gitea-mcp:8080/mcp"},
        {"host": "ftp://gitea-mcp:21/mcp"},
        {"host": "https:///mcp"},
        {"host": "mcp.example.com:443"},
        {"host": "10.0.0.5"},
        {"host": "mcp.example.com", "port": 443, "path": "/mcp"},
        {"host": "10.0.0.5", "port": 8080, "path": "/mcp"},
        {"host": 7},
        {"host": "gateway#@evil.com"},
        {"host": "gateway?@evil.com"},
        {"host": "gateway/@evil.com"},
        {"host": "gateway:abc"},
        {"host": "gateway:99999"},
        {"host": "gate\tway"},
        {"host": "gate way"},
        {"host": "gateway\n"},
        {"host": "gateway\x00"},
        {"host": "http://gateway:abc/mcp"},
        {"host": "http://gateway:99999/mcp"},
        {"host": "http://gate\tway/mcp"},
        {"host": "http://gateway/mcp?@evil.com"},
        {"host": "http://gateway/mcp#@evil.com"},
        {"host": "http://gateway/mcp?"},
        {"host": "http://gateway/mcp\r\n"},
        {"host": "https://x", "port": 443, "path": "/"},
        {"host": "http://gateway", "port": 8080, "path": "/mcp"},
        {"host": "https://mcp.example.com", "path": "/mcp"},
        {"host": "gateway", "port": 8080, "path": "@evil.com"},
        {"host": "gateway", "port": 8080, "path": "mcp"},
        {"host": "gateway", "port": 8080, "path": "//evil.com/mcp"},
        {"host": "gateway", "port": 8080, "path": "/mcp?x=1"},
        {"host": "gateway", "port": 8080, "path": "/mcp#x"},
        {"host": "gateway", "port": 8080, "path": "/m\\cp"},
        {"host": "gateway", "port": 8080, "path": "/m cp"},
        {"host": "gateway", "port": 8080, "path": "/m\u00e9"},
        {"host": "gateway", "port": 8080, "path": 7},
        {"host": "gateway", "port": "8080", "path": "/mcp"},
        {"host": "gateway", "port": True, "path": "/mcp"},
        {"host": "gateway", "port": 0, "path": "/mcp"},
        {"host": "gateway", "port": 65536, "path": "/mcp"},
    ],
)
def test_a_gateway_bound_target_over_cleartext_to_a_remote_host_is_refused(target):
    problems = problems_after(lambda config: config["mcp"]["targets"][0].update(mcp=target))
    assert any("deploy" in problem and "cleartext" in problem for problem in problems), problems


def test_backend_tls_with_only_a_root_is_accepted():
    def change(config):
        config["mcp"]["targets"][0].update(
            mcp={"host": "https://mcp.example.com/mcp"}, policies={"backendTLS": {"root": "/etc/gateway/ca.pem"}}
        )

    assert problems_after(change) == ()


@pytest.mark.parametrize(
    "backend_tls",
    [
        {"root": "/etc/gateway/ca.pem", "insecure": True},
        {"root": "/etc/gateway/ca.pem", "insecureHost": True},
        {"root": "/etc/gateway/ca.pem", "hostname": "other.example"},
        {"insecure": True},
        {"root": ""},
        {"root": 1},
        {},
        "/etc/gateway/ca.pem",
        None,
    ],
)
def test_backend_tls_beyond_a_non_empty_root_is_refused(backend_tls):
    def change(config):
        config["mcp"]["targets"][0].update(
            mcp={"host": "https://mcp.example.com/mcp"}, policies={"backendTLS": backend_tls}
        )

    assert any("backendTLS" in problem for problem in problems_after(change))


GATEWAY_TLS = {"cert": "/var/lib/bailiff/certs/gateway.pem", "key": "/var/lib/bailiff/gateway-key/gateway.key"}


def tls_listener(config):
    config["gateways"] = {"default": {"port": config["mcp"].pop("port"), "tls": dict(GATEWAY_TLS)}}
    return config


def test_a_tls_gateways_listener_is_accepted():
    assert validate_gateway_config(tls_listener(gateway_config()), EXPECTED) == ()


@pytest.mark.parametrize(
    "change",
    [
        lambda gateways: gateways.update(other=gateways["default"]),
        lambda gateways: gateways.update(public=gateways.pop("default")),
        lambda gateways: gateways["default"].update(bind="0.0.0.0"),
        lambda gateways: gateways["default"].pop("tls"),
        lambda gateways: gateways["default"].pop("port"),
        lambda gateways: gateways["default"]["tls"].update(root="/ca.pem"),
        lambda gateways: gateways["default"]["tls"].update(cert=""),
        lambda gateways: gateways["default"]["tls"].update(key=7),
        lambda gateways: gateways["default"]["tls"].pop("key"),
        lambda gateways: gateways["default"].update(tls="/cert.pem"),
        lambda gateways: gateways["default"].update(port=0),
        lambda gateways: gateways["default"].update(port=65536),
        lambda gateways: gateways["default"].update(port="8443"),
        lambda gateways: gateways["default"].update(port=True),
        lambda gateways: gateways.clear(),
    ],
)
def test_a_gateways_listener_beyond_one_tls_default_is_refused(change):
    config = tls_listener(gateway_config())
    change(config["gateways"])
    assert any(problem.startswith("gateways") for problem in validate_gateway_config(config, EXPECTED))


@pytest.mark.parametrize("gateways", [None, [], "default", {"default": None}])
def test_a_malformed_gateways_value_is_refused(gateways):
    config = gateway_config()
    del config["mcp"]["port"]
    config["gateways"] = gateways
    assert any(problem.startswith("gateways") for problem in validate_gateway_config(config, EXPECTED))


def test_an_mcp_port_beside_a_gateways_listener_is_refused():
    config = tls_listener(gateway_config())
    config["mcp"]["port"] = 8080
    problems = validate_gateway_config(config, EXPECTED)
    assert any("mcp.port" in problem and "plaintext" in problem for problem in problems), problems


def test_check_config_accepts_a_tls_gateways_listener(owned_files):
    result = run_check(owned_files, tls_listener(gateway_config()))
    assert (result.returncode, result.stdout.strip()) == (0, "ok"), result.stderr


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
        {"redactor_socket": Path("relative.sock")},
        {"redactor_socket": DECIDE_SOCKET},
        {"redactor_socket": CUSTODIAN_SOCKET},
        {"services": frozenset()},
        {"credential_headers": frozenset({"bad header"})},
    ],
)
def test_expectations_are_validated(options):
    fields = {
        "decide_socket": DECIDE_SOCKET,
        "custodian_socket": CUSTODIAN_SOCKET,
        "redactor_socket": REDACTOR_SOCKET,
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


ROUTE = {"service": "deploy", "name": "deploy_service", "tool": "deploy.service", "resource": "env/a"}


def run_check(owned_files, config_document, routes=(ROUTE,)):
    routes = owned_files("routes.json", {"routes": list(routes)})
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
        "--redactor-socket",
        str(REDACTOR_SOCKET),
    ]
    return subprocess.run(command, capture_output=True, text=True, timeout=60)


def test_check_config_accepts_the_reference_config(owned_files):
    result = run_check(owned_files, gateway_config())
    assert (result.returncode, result.stdout.strip()) == (0, "ok"), result.stderr


def test_check_config_refuses_and_lists_problems(owned_files):
    config = gateway_config()
    processors(config)[CUSTODIAN]["failureMode"] = "failOpen"
    result = run_check(owned_files, config)
    assert result.returncode == 1
    assert "failClosed" in result.stderr


@pytest.mark.parametrize("text", ["{", '{"mcp": {}, "mcp": {}}', '{"mcp": NaN}'])
def test_check_config_refuses_an_unreadable_gateway_config(owned_files, text):
    result = run_check(owned_files, text)
    assert result.returncode == 1
    assert "gateway config" in result.stderr


def test_check_config_refuses_one_tool_and_resource_routed_from_two_services(owned_files):
    other = {**ROUTE, "service": "attacker"}
    config = gateway_config()
    config["mcp"]["targets"].append({"name": "attacker", "mcp": {"host": "http://127.0.0.1:9/mcp"}})
    result = run_check(owned_files, config, routes=(ROUTE, other))
    assert result.returncode == 1
    assert "deploy.service" in result.stderr


@pytest.mark.parametrize("name", CHAIN_HEADERS + ["X-Bailiff-Nonce"])
def test_a_chain_header_in_disallowed_is_refused(name):
    problems = problems_after(lambda config: processors(config)[DECIDE]["requestHeaders"].update(disallowed=[name]))
    assert any("disallowed" in problem and name in problem for problem in problems)


def test_an_unrelated_disallowed_header_is_accepted():
    problems = problems_after(lambda config: processors(config)[DECIDE]["requestHeaders"].update(disallowed=["cookie"]))
    assert problems == ()


@pytest.mark.parametrize("disallowed", ["cookie", [1], {}])
def test_a_malformed_disallowed_list_is_refused(disallowed):
    problems = problems_after(lambda config: processors(config)[DECIDE]["requestHeaders"].update(disallowed=disallowed))
    assert any("disallowed" in problem for problem in problems)


@pytest.mark.parametrize("name", [" authorization", "authorization ", "x a", "", "x-api-key\n", "caf\u00e9", "x:y"])
def test_every_remove_entry_must_be_a_header_name(name):
    problems = problems_after(lambda config: modifier(config)["remove"].append(name))
    assert any(
        problem.startswith("mcp.policies.requestHeaderModifier") and "field name" in problem for problem in problems
    )
