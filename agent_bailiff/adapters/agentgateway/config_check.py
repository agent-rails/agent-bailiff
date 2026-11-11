from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_bailiff.adapters.agentgateway.calls import CALL_HEADERS, REQUIRED_HEADERS, TRACEPARENT_HEADER
from agent_bailiff.adapters.agentgateway.processors import CLEARANCE_KEY
from agent_bailiff.custodian.bindings import HEADER_NAME

TOP_LEVEL_KEYS = frozenset({"config", "mcp"})
CONFIG_KEYS = frozenset({"adminAddr", "statsAddr", "readinessAddr", "logging", "tracing", "metrics", "workerThreads"})
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
HTTP_TARGET_KEYS = frozenset({"host", "port", "path"})
BAILIFF_PROCESSOR_KEYS = frozenset({"kind", "host", "methods", "failureMode", "requestHeaders", "metadata"})
HEADER_FILTER_KEYS = frozenset({"allowed", "disallowed"})
BAILIFF_METHODS = {"*": "request"}
METHOD_RULE = 'mcp.methodName == "tools/call" || mcp.methodName == "tools/list"'
AGENT_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
CHAIN_HEADER_PREFIX = "x-bailiff-"
REMOVE_PATH = "$.mcp.policies.requestHeaderModifier.remove"
CLEARANCE_EXPRESSION = f"mcpGuardrails.{CLEARANCE_KEY}"


@dataclass(frozen=True)
class GatewayExpectations:
    decide_socket: Path
    custodian_socket: Path
    services: frozenset[str]
    credential_headers: frozenset[str]

    def __post_init__(self) -> None:
        for name in ("decide_socket", "custodian_socket"):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute path")
        if self.decide_socket == self.custodian_socket:
            raise ValueError("decide and custodian must listen on different sockets")
        if not self.services or not all(isinstance(item, str) and item for item in self.services):
            raise ValueError("services must be a non-empty set of non-empty str")
        if not self.credential_headers or not all(
            isinstance(item, str) and HEADER_NAME.fullmatch(item) for item in self.credential_headers
        ):
            raise ValueError("credential_headers must be a non-empty set of HTTP field names")


def validate_gateway_config(document: object, expected: GatewayExpectations) -> tuple[str, ...]:
    if not isinstance(document, dict):
        return ("the gateway config must be a JSON object",)
    problems: list[str] = []
    _only_keys(problems, "the top level", document, TOP_LEVEL_KEYS)
    config = document.get("config", {})
    if isinstance(config, dict):
        _only_keys(problems, "config", config, CONFIG_KEYS)
    else:
        problems.append("config must be an object")
    mcp = document.get("mcp")
    if not isinstance(mcp, dict):
        problems.append("the gateway config must have an mcp object")
        return tuple(problems)
    _only_keys(problems, "mcp", mcp, MCP_KEYS)
    _check_targets(problems, mcp.get("targets"), expected.services)
    _check_policies(problems, mcp.get("policies"), expected)
    _check_credential_headers(problems, document, expected.credential_headers)
    return tuple(problems)


def _check_targets(problems: list[str], targets: object, services: frozenset[str]) -> None:
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


def _check_policies(problems: list[str], policies: object, expected: GatewayExpectations) -> None:
    if not isinstance(policies, dict):
        problems.append("mcp.policies must be an object")
        return
    _only_keys(problems, "mcp.policies", policies, MCP_POLICY_KEYS)
    if policies.get("mcpAuthorization") != {"rules": [METHOD_RULE]}:
        problems.append(f"mcp.policies.mcpAuthorization must be exactly {{'rules': [{METHOD_RULE!r}]}}")
    _check_header_modifier(problems, policies.get("requestHeaderModifier"), expected.credential_headers)
    guardrails = policies.get("mcpGuardrails")
    if (
        not isinstance(guardrails, dict)
        or set(guardrails) != {"processors"}
        or not isinstance(guardrails["processors"], list)
    ):
        problems.append("mcp.policies.mcpGuardrails must be an object with only a processors list")
        return
    processors = guardrails["processors"]
    decide = _bailiff_processors(processors, expected.decide_socket)
    custodian = _bailiff_processors(processors, expected.custodian_socket)
    for label, found in (("decide", decide), ("custodian", custodian)):
        if len(found) != 1:
            problems.append(f"exactly one remote {label} processor must target its unix socket; found {len(found)}")
    if len(decide) != 1 or len(custodian) != 1:
        return
    if decide != [len(processors) - 2] or custodian != [len(processors) - 1]:
        problems.append("processor order: decide must run immediately before custodian, and custodian must be last")
    _check_bailiff_processor(problems, "decide", processors[decide[0]], {})
    _check_bailiff_processor(problems, "custodian", processors[custodian[0]], {CLEARANCE_KEY: CLEARANCE_EXPRESSION})


def _bailiff_processors(processors: list[Any], socket_path: Path) -> list[int]:
    host = f"unix:{socket_path}"
    return [
        index
        for index, processor in enumerate(processors)
        if isinstance(processor, dict) and processor.get("kind") == "remote" and processor.get("host") == host
    ]


def _check_bailiff_processor(
    problems: list[str], label: str, processor: Mapping[str, Any], metadata: Mapping[str, str]
) -> None:
    _only_keys(problems, f"the {label} processor", processor, BAILIFF_PROCESSOR_KEYS)
    if processor.get("methods") != BAILIFF_METHODS:
        problems.append(f'the {label} processor methods must be exactly {{"*": "request"}}')
    if processor.get("failureMode", "failClosed") != "failClosed":
        problems.append(f"the {label} processor must be failClosed")
    if processor.get("metadata", {}) != metadata:
        expected = f"exactly {dict(metadata)}" if metadata else "no metadata"
        problems.append(f"the {label} processor must send {expected} (clearance channel)")
    _check_header_filter(problems, label, processor.get("requestHeaders"))


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
