from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bailiff.adapters.agentgateway.processors import CLEARANCE_KEY
from agent_bailiff.chain_headers import CALL_HEADERS, REQUIRED_HEADERS, TRACEPARENT_HEADER
from agent_bailiff.client.client import REFUSAL_REASONS
from agent_bailiff.custodian.bindings import HEADER_NAME
from agent_bailiff.custodian.config import MAX_UPSTREAM_TIMEOUT
from agent_bailiff.custodian.release import RELEASE_HEADER
from agent_bailiff.plain_http import LOOPBACK_HOSTS, PLAIN_HTTP_HOSTS, allows_plain_http, parse_transport_url

TOP_LEVEL_KEYS = frozenset({"config", "mcp", "frontendPolicies"})
CONFIG_KEYS = frozenset({"adminAddr", "statsAddr", "readinessAddr", "logging", "tracing", "metrics", "workerThreads"})
LOGGING_KEYS = frozenset({"level", "format"})
MCP_KEYS = frozenset(
    {"port", "targets", "policies", "statefulMode", "prefixMode", "failureMode", "server", "sseKeepAlive"}
    | {"dnsRebindingProtection"}
)
MCP_POLICY_KEYS = frozenset(
    {"mcpGuardrails", "mcpAuthorization", "mcpAuthentication", "authorization", "cors", "csrf", "jwtAuth"}
    | {"apiKey", "basicAuth", "localRateLimit", "timeout", "requestHeaderModifier"}
)
TARGET_KEYS = frozenset({"name", "mcp", "sse", "stdio", "openapi", "policies"})
TARGET_POLICY_KEYS = frozenset({"backendTLS"})
TARGET_TLS_KEYS = frozenset({"root"})
HTTP_TARGET_KEYS = frozenset({"host", "port", "path"})
TARGET_PATH = re.compile(r"/(?!/)[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
BAILIFF_PROCESSOR_KEYS = frozenset({"kind", "host", "methods", "failureMode", "requestHeaders", "metadata"})
HEADER_FILTER_KEYS = frozenset({"allowed", "disallowed"})
BAILIFF_METHODS = {"*": "request"}
REDACTOR_METHODS = {"tools/call": "response"}
TIMEOUT_KEYS = frozenset({"requestTimeout", "backendRequestTimeout", "responseIdleTimeout"})
BOUNDED_TIMEOUTS = ("requestTimeout", "backendRequestTimeout")
MAX_UPSTREAM_TIMEOUT_MS = MAX_UPSTREAM_TIMEOUT * 1000
DURATION = re.compile(r"([1-9][0-9]{0,8})(ms|s|m)")
DURATION_UNIT_MS = {"ms": 1, "s": 1000, "m": 60_000}
METHOD_RULE = 'mcp.methodName == "tools/call" || mcp.methodName == "tools/list"'
AGENT_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", RELEASE_HEADER})
CHAIN_HEADER_PREFIX = "x-bailiff-"
REMOVE_PATH = "$.mcp.policies.requestHeaderModifier.remove"
CLEARANCE_EXPRESSION = f"mcpGuardrails.{CLEARANCE_KEY}"
ACCESS_LOG_REMOVED_FIELDS = frozenset({"mcp.error.message"})

REFUSAL_SHAPE = (
    "has(mcp.result.isError) && mcp.result.isError == true"
    " && has(mcp.result.content) && size(mcp.result.content) == 1"
    " && has(mcp.result.content[0].text) && mcp.result.content[0].text in "
    + "["
    + ", ".join(f"'{reason}'" for reason in sorted(REFUSAL_REASONS))
    + "]"
)
REQUEST_ONLY_PHASES = frozenset({"request", "off"})
RESPONSE_ONLY_PHASES = frozenset({"response", "off"})
REFUSAL_GUARD = {
    "kind": "expression",
    "methods": {"tools/call": "response"},
    "condition": REFUSAL_SHAPE,
    "reject": "the upstream answer has the shape of a bailiff refusal",
}


@dataclass(frozen=True)
class GatewayExpectations:
    decide_socket: Path
    custodian_socket: Path
    redactor_socket: Path
    services: frozenset[str]
    credential_headers: frozenset[str]
    effector_services: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        sockets = (self.decide_socket, self.custodian_socket, self.redactor_socket)
        for name, value in zip(("decide_socket", "custodian_socket", "redactor_socket"), sockets, strict=True):
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute path")
        if len(set(sockets)) != len(sockets):
            raise ValueError("decide, custodian and redactor must listen on different sockets")
        if not self.services or not all(isinstance(item, str) and item for item in self.services):
            raise ValueError("services must be a non-empty set of non-empty str")
        if not all(isinstance(item, str) and HEADER_NAME.fullmatch(item) for item in self.credential_headers):
            raise ValueError("credential_headers must be HTTP field names")


def validate_gateway_config(document: object, expected: GatewayExpectations) -> tuple[str, ...]:
    if not isinstance(document, dict):
        return ("the gateway config must be a JSON object",)
    problems: list[str] = []
    _only_keys(problems, "the top level", document, TOP_LEVEL_KEYS)
    config = document.get("config", {})
    if isinstance(config, dict):
        _only_keys(problems, "config", config, CONFIG_KEYS)
        _check_logging(problems, config.get("logging", {}))
        _check_telemetry_fields(problems, config)
    else:
        problems.append("config must be an object")
    mcp = document.get("mcp")
    if not isinstance(mcp, dict):
        problems.append("the gateway config must have an mcp object")
        return tuple(problems)
    _only_keys(problems, "mcp", mcp, MCP_KEYS)
    if mcp.get("statefulMode") != "stateless":
        problems.append('mcp.statefulMode must be "stateless"; the stateful event stream reaches upstreams unchecked')
    _check_targets(problems, mcp.get("targets"), expected.services, expected.effector_services)
    _check_policies(problems, mcp.get("policies"), expected)
    _check_access_log(problems, document.get("frontendPolicies"))
    _check_credential_headers(problems, document, expected.credential_headers)
    return tuple(problems)


def _check_logging(problems: list[str], logging: object) -> None:
    if not isinstance(logging, dict) or not set(logging) <= LOGGING_KEYS:
        problems.append(
            "config.logging may set only level and format; its other keys add, filter or ship access-log fields "
            "outside frontendPolicies.accessLog"
        )


def _check_telemetry_fields(problems: list[str], config: Mapping[str, Any]) -> None:
    for key in ("tracing", "metrics"):
        telemetry = config.get(key, {})
        if not isinstance(telemetry, dict) or "fields" in telemetry:
            problems.append(
                f"config.{key} must be an object without fields; added fields can carry upstream error text "
                "that frontendPolicies.accessLog does not remove"
            )


def _check_access_log(problems: list[str], frontend: object) -> None:
    access_log = frontend.get("accessLog") if isinstance(frontend, dict) else None
    remove = access_log.get("remove") if isinstance(access_log, dict) else None
    if (
        not isinstance(frontend, dict)
        or set(frontend) != {"accessLog"}
        or not isinstance(access_log, dict)
        or set(access_log) != {"remove"}
        or not isinstance(remove, list)
        or not all(isinstance(name, str) for name in remove)
        or len(set(remove)) != len(remove)
    ):
        problems.append(
            'frontendPolicies must be exactly {"accessLog": {"remove": [unique field names]}}; '
            "the access log keeps upstream error text, which can echo a released credential"
        )
        return
    missing = sorted(ACCESS_LOG_REMOVED_FIELDS - set(remove))
    if missing:
        problems.append(
            f"frontendPolicies.accessLog.remove is missing {', '.join(missing)}; "
            "upstream error text can echo a released credential"
        )


def _check_targets(
    problems: list[str], targets: object, services: frozenset[str], effector_services: frozenset[str]
) -> None:
    if not isinstance(targets, list):
        problems.append("mcp.targets must be a list")
        return
    seen: dict[str, Mapping[str, Any]] = {}
    for index, target in enumerate(targets):
        if not isinstance(target, dict) or not isinstance(target.get("name"), str):
            problems.append(f"mcp.targets[{index}] must be an object with a name")
            continue
        name = target["name"]
        if name in seen:
            problems.append(f"mcp target {name!r} is defined more than once")
        seen[name] = target
        _only_keys(problems, f"mcp target {name!r}", target, TARGET_KEYS)
        policies = target.get("policies", {})
        if not isinstance(policies, dict):
            problems.append(f"mcp target {name!r} policies must be an object")
        else:
            _only_keys(problems, f"mcp target {name!r} policies", policies, TARGET_POLICY_KEYS)
            if "backendTLS" in policies:
                _check_backend_tls(problems, name, policies["backendTLS"])
    for service in sorted(services):
        target = seen.get(service)
        if target is None:
            problems.append(f"gateway-bound service {service!r} has no mcp target")
            continue
        transport = [key for key in ("mcp", "sse", "stdio", "openapi") if key in target]
        if transport != ["mcp"] or not isinstance(target["mcp"], dict):
            problems.append(
                f"gateway-bound service {service!r} must be an HTTP mcp target; "
                "stdio, sse and openapi upstreams cannot carry the released header"
            )
            continue
        _only_keys(problems, f"mcp target {service!r} mcp", target["mcp"], HTTP_TARGET_KEYS)
        if service in effector_services:
            if not _is_loopback_http(target["mcp"]):
                problems.append(
                    f"catalog service {service!r} must target the effector over http on 127.0.0.1, localhost or "
                    "[::1]; releases and clearances must not leave the host"
                )
        elif not _is_protected_transport(target["mcp"]):
            problems.append(
                f"gateway-bound service {service!r} must target https, or http only on {PLAIN_HTTP_HOSTS}; "
                "a host without a scheme is http, and the released credential must not cross the network in cleartext"
            )


def _check_backend_tls(problems: list[str], name: str, backend_tls: object) -> None:
    if not isinstance(backend_tls, dict):
        problems.append(f"mcp target {name!r} policies.backendTLS must be an object with a root")
        return
    _only_keys(problems, f"mcp target {name!r} policies.backendTLS", backend_tls, TARGET_TLS_KEYS)
    root = backend_tls.get("root")
    if not isinstance(root, str) or not root:
        problems.append(f"mcp target {name!r} policies.backendTLS root must be a non-empty string")


def _parse_target_host(target: Mapping[str, Any]) -> urllib.parse.SplitResult | None:
    host = target.get("host")
    if not isinstance(host, str):
        return None
    has_scheme = "://" in host
    if has_scheme and ("port" in target or "path" in target):
        return None
    if "port" in target and not _is_valid_target_port(target["port"]):
        return None
    if "path" in target and not _is_valid_target_path(target["path"]):
        return None
    try:
        return parse_transport_url(host, bare_host=not has_scheme)
    except ValueError:
        return None


def _is_valid_target_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _is_valid_target_path(path: object) -> bool:
    return isinstance(path, str) and TARGET_PATH.fullmatch(path) is not None


def _is_protected_transport(target: Mapping[str, Any]) -> bool:
    url = _parse_target_host(target)
    if url is None or url.hostname is None:
        return False
    return url.scheme == "https" or allows_plain_http(url.hostname)


def _is_loopback_http(target: Mapping[str, Any]) -> bool:
    url = _parse_target_host(target)
    return url is not None and url.scheme == "http" and url.hostname in LOOPBACK_HOSTS


def _check_policies(problems: list[str], policies: object, expected: GatewayExpectations) -> None:
    if not isinstance(policies, dict):
        problems.append("mcp.policies must be an object")
        return
    _only_keys(problems, "mcp.policies", policies, MCP_POLICY_KEYS)
    if policies.get("mcpAuthorization") != {"rules": [METHOD_RULE]}:
        problems.append(f"mcp.policies.mcpAuthorization must be exactly {{'rules': [{METHOD_RULE!r}]}}")
    _check_header_modifier(problems, policies.get("requestHeaderModifier"), expected.credential_headers)
    _check_timeouts(problems, policies.get("timeout"))
    guardrails = policies.get("mcpGuardrails")
    if (
        not isinstance(guardrails, dict)
        or set(guardrails) != {"processors"}
        or not isinstance(guardrails["processors"], list)
    ):
        problems.append("mcp.policies.mcpGuardrails must be an object with only a processors list")
        return
    processors = guardrails["processors"]
    _check_response_phase(problems, processors, expected.redactor_socket)
    decide = _bailiff_processors(processors, expected.decide_socket)
    custodian = _bailiff_processors(processors, expected.custodian_socket)
    for label, found in (("decide", decide), ("custodian", custodian)):
        if len(found) != 1:
            problems.append(f"exactly one remote {label} processor must target its unix socket; found {len(found)}")
    if len(decide) != 1 or len(custodian) != 1:
        return
    requesting = [index for index, processor in enumerate(processors) if not _in_phase(processor, RESPONSE_ONLY_PHASES)]
    if requesting[-2:] != [decide[0], custodian[0]]:
        problems.append(
            "processor order: decide must run immediately before custodian, "
            "and custodian must be the last request-phase processor"
        )
    _check_bailiff_processor(problems, "decide", processors[decide[0]], BAILIFF_METHODS, {})
    _check_header_filter(problems, "decide", processors[decide[0]].get("requestHeaders"))
    _check_bailiff_processor(
        problems, "custodian", processors[custodian[0]], BAILIFF_METHODS, {CLEARANCE_KEY: CLEARANCE_EXPRESSION}
    )
    if "requestHeaders" in processors[custodian[0]]:
        problems.append(
            "the custodian processor must not filter requestHeaders; "
            "it removes every header outside the upstream allowlist, so it must see them all"
        )


def _check_timeouts(problems: list[str], timeout: object) -> None:
    if not isinstance(timeout, dict):
        problems.append(
            "mcp.policies.timeout must set requestTimeout and backendRequestTimeout; "
            "an unbounded upstream call outlives the in-flight release the redactor needs"
        )
        return
    _only_keys(problems, "mcp.policies.timeout", timeout, TIMEOUT_KEYS)
    optional = ("responseIdleTimeout",) if "responseIdleTimeout" in timeout else ()
    for key in (*BOUNDED_TIMEOUTS, *optional):
        milliseconds = _duration_ms(timeout.get(key))
        if milliseconds is None or milliseconds > MAX_UPSTREAM_TIMEOUT_MS:
            problems.append(
                f"mcp.policies.timeout.{key} must be a duration with a unit, at most {MAX_UPSTREAM_TIMEOUT}s"
            )


def _duration_ms(value: object) -> int | None:
    match = DURATION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    return int(match.group(1)) * DURATION_UNIT_MS[match.group(2)]


def _in_phase(processor: object, phases: frozenset[str]) -> bool:
    return (
        isinstance(processor, dict)
        and isinstance(processor.get("methods"), dict)
        and all(phase in phases for phase in processor["methods"].values())
    )


def _check_response_phase(problems: list[str], processors: list[Any], redactor_socket: Path) -> None:
    redactor = _bailiff_processors(processors, redactor_socket)
    if len(redactor) != 1:
        problems.append(f"exactly one remote redactor processor must target its unix socket; found {len(redactor)}")
    else:
        _check_bailiff_processor(
            problems, "redactor", processors[redactor[0]], REDACTOR_METHODS, {CLEARANCE_KEY: CLEARANCE_EXPRESSION}
        )
        if "requestHeaders" in processors[redactor[0]]:
            problems.append("the redactor processor must not set requestHeaders; it runs only on call results")
    responding = [index for index, processor in enumerate(processors) if not _in_phase(processor, REQUEST_ONLY_PHASES)]
    if (
        len(redactor) != 1
        or len(responding) != 2
        or responding[0] != redactor[0]
        or processors[responding[1]] != REFUSAL_GUARD
    ):
        problems.append(
            "the response-phase processors must be exactly the redactor then the refusal guard "
            "(config_check.REFUSAL_GUARD); without the guard an upstream can answer with a bailiff refusal "
            "after acting, and without the redactor an echoed credential reaches the agent"
        )


def _bailiff_processors(processors: list[Any], socket_path: Path) -> list[int]:
    host = f"unix:{socket_path}"
    return [
        index
        for index, processor in enumerate(processors)
        if isinstance(processor, dict) and processor.get("kind") == "remote" and processor.get("host") == host
    ]


def _check_bailiff_processor(
    problems: list[str],
    label: str,
    processor: Mapping[str, Any],
    methods: Mapping[str, str],
    metadata: Mapping[str, str],
) -> None:
    _only_keys(problems, f"the {label} processor", processor, BAILIFF_PROCESSOR_KEYS)
    if processor.get("methods") != methods:
        problems.append(f"the {label} processor methods must be exactly {json.dumps(methods)}")
    if processor.get("failureMode", "failClosed") != "failClosed":
        problems.append(f"the {label} processor must be failClosed")
    if processor.get("metadata", {}) != metadata:
        expected = f"exactly {dict(metadata)}" if metadata else "no metadata"
        problems.append(f"the {label} processor must send {expected} (clearance channel)")


def _check_header_filter(problems: list[str], label: str, header_filter: object) -> None:
    allowed = header_filter.get("allowed") if isinstance(header_filter, dict) else None
    if (
        not isinstance(header_filter, dict)
        or not isinstance(allowed, list)
        or not all(isinstance(name, str) for name in allowed)
    ):
        problems.append(f"the {label} processor needs a requestHeaders allowlist")
        return
    _only_keys(problems, f"the {label} processor requestHeaders", header_filter, HEADER_FILTER_KEYS)
    names = {name.lower() for name in allowed}
    extra = sorted(name for name in allowed if name.lower() not in CALL_HEADERS)
    if extra:
        problems.append(f"the {label} processor allowlist forwards headers it must not see: {', '.join(extra)}")
    missing = sorted(REQUIRED_HEADERS - names)
    if missing:
        problems.append(f"the {label} processor allowlist is missing {', '.join(missing)}")
    disallowed = header_filter.get("disallowed", [])
    if not isinstance(disallowed, list) or not all(isinstance(name, str) for name in disallowed):
        problems.append(f"the {label} processor requestHeaders disallowed must be a list of names")
        return
    dropped = sorted(name for name in disallowed if name.lower() in CALL_HEADERS)
    if dropped:
        problems.append(f"the {label} processor disallowed list drops chain headers: {', '.join(dropped)}")


def _check_header_modifier(problems: list[str], modifier: object, credential_headers: frozenset[str]) -> None:
    remove = modifier.get("remove") if isinstance(modifier, dict) else None
    if (
        not isinstance(modifier, dict)
        or set(modifier) != {"remove"}
        or not isinstance(remove, list)
        or not all(isinstance(name, str) for name in remove)
    ):
        problems.append('mcp.policies.requestHeaderModifier must be exactly {"remove": [header names]}')
        return
    invalid = sorted(repr(name) for name in remove if not HEADER_NAME.fullmatch(name))
    if invalid:
        problems.append(
            f"mcp.policies.requestHeaderModifier remove has entries that are not field names: {', '.join(invalid)}"
        )
    names = {name.lower() for name in remove}
    required = AGENT_CREDENTIAL_HEADERS | {name.lower() for name in credential_headers}
    missing = sorted(required - names)
    if missing:
        problems.append(f"mcp.policies.requestHeaderModifier remove is missing {', '.join(missing)}")
    chain = sorted(name for name in names if name.startswith(CHAIN_HEADER_PREFIX) or name == TRACEPARENT_HEADER)
    if chain:
        problems.append(f"mcp.policies.requestHeaderModifier must not remove chain headers: {', '.join(chain)}")


def _check_credential_headers(problems: list[str], document: object, headers: frozenset[str]) -> None:
    patterns = {
        header: re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(header)}(?![A-Za-z0-9_-])", re.IGNORECASE)
        for header in sorted(headers)
    }
    for path, text in _strings(document, "$"):
        if path.startswith(f"{REMOVE_PATH}["):
            continue
        for header, pattern in patterns.items():
            if pattern.search(text):
                problems.append(f"credential header {header} appears in the gateway config at {path}")


def _strings(value: object, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, inner in value.items():
            yield path, str(key)
            yield from _strings(inner, f"{path}.{key}")
    elif isinstance(value, list):
        for index, inner in enumerate(value):
            yield from _strings(inner, f"{path}[{index}]")


def _only_keys(problems: list[str], label: str, mapping: Mapping[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(str(key) for key in mapping if key not in allowed)
    if unknown:
        problems.append(f"{label} has keys check-config does not validate: {', '.join(unknown)}")
