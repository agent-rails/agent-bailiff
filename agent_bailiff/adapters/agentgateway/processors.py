from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from typing import Protocol

from google.protobuf import struct_pb2

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.calls import (
    LEAF_PROOF_HEADER,
    LINKS_HEADER,
    NONCE_HEADER,
    TASK_ROOT_HEADER,
    TOOLS_CALL,
    CallRefused,
    ToolRoutes,
    read_call,
)
from agent_bailiff.custodian.bindings import HEADER_NAME
from agent_bailiff.custodian.custodian import Released, ReleaseResult
from agent_bailiff.decide.decider import Decision
from agent_bailiff.decide.request import OperationRequest

CLEARANCE_KEY = "clearance"
RELEASE_REFUSED = "release_refused"
AGENT_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
CHAIN_HEADERS = frozenset({LEAF_PROOF_HEADER, LINKS_HEADER, NONCE_HEADER, TASK_ROOT_HEADER})

logger = logging.getLogger(__name__)

Clock = Callable[[], int]


class CallDecider(Protocol):
    def check(self, request: OperationRequest, now: int) -> Decision: ...


class CredentialReleaser(Protocol):
    def release(self, clearance_token: object, request: object, now: int) -> ReleaseResult: ...


def system_clock() -> int:
    return int(time.time())


class DecideProcessor:
    def __init__(self, decider: CallDecider, routes: ToolRoutes, clock: Clock = system_clock) -> None:
        self._decider = decider
        self._routes = routes
        self._clock = clock

    def check_request(self, message: ext_mcp_pb2.McpRequest) -> ext_mcp_pb2.McpRequestResult:
        try:
            return self._check(message)
        except Exception:
            logger.exception("decide processor failed with an internal error")
            return refuse("internal_error")

    def _check(self, message: ext_mcp_pb2.McpRequest) -> ext_mcp_pb2.McpRequestResult:
        if message.method != TOOLS_CALL:
            return passed()
        try:
            request = read_call(message, self._routes)
        except CallRefused as refusal:
            logger.warning("decide processor refused an unreadable call: %s", refusal.reason)
            return refuse(refusal.reason)
        decision = self._decider.check(request, self._clock())
        if not decision.allowed or not decision.clearance:
            return refuse(decision.reason)
        metadata = struct_pb2.Struct()
        metadata.update({CLEARANCE_KEY: decision.clearance})
        return ext_mcp_pb2.McpRequestResult(**{"pass": ext_mcp_pb2.Pass()}, metadata=metadata)


class CustodianProcessor:
    def __init__(
        self,
        custodian: CredentialReleaser,
        routes: ToolRoutes,
        credential_headers: Iterable[str],
        clock: Clock = system_clock,
    ) -> None:
        names = frozenset(credential_headers)
        if not names or not all(isinstance(name, str) and HEADER_NAME.fullmatch(name) for name in names):
            raise ValueError("credential_headers must be a non-empty set of HTTP field names")
        self._custodian = custodian
        self._routes = routes
        self._clock = clock
        self._stripped = AGENT_CREDENTIAL_HEADERS | CHAIN_HEADERS | {name.lower() for name in names}

    def check_request(self, message: ext_mcp_pb2.McpRequest) -> ext_mcp_pb2.McpRequestResult:
        try:
            return self._check(message)
        except Exception:
            logger.exception("custodian processor failed with an internal error")
            return refuse("internal_error")

    def _check(self, message: ext_mcp_pb2.McpRequest) -> ext_mcp_pb2.McpRequestResult:
        if message.method != TOOLS_CALL:
            return self._passed_without(frozenset())
        clearance = _clearance(message)
        if clearance is None:
            logger.warning("custodian processor refused a call without a clearance in the metadata context")
            return refuse("clearance_missing")
        try:
            request = read_call(message, self._routes)
        except CallRefused as refusal:
            logger.warning("custodian processor refused an unreadable call: %s", refusal.reason)
            return refuse(refusal.reason)
        result = self._custodian.release(clearance, request, self._clock())
        if not isinstance(result, Released):
            logger.warning("custodian processor refused a release: %s", result.reason)
            return refuse(RELEASE_REFUSED)
        released = ext_mcp_pb2.McpHeader(key=result.header_name, value=result.header_value.encode("ascii"))
        return self._passed_without(frozenset({result.header_name.lower()}), released)

    def _passed_without(
        self, kept: frozenset[str], released: ext_mcp_pb2.McpHeader | None = None
    ) -> ext_mcp_pb2.McpRequestResult:
        mutation = ext_mcp_pb2.HeaderMutation(
            set=[released] if released is not None else [],
            remove=sorted(self._stripped - kept),
        )
        return ext_mcp_pb2.McpRequestResult(**{"pass": ext_mcp_pb2.Pass()}, header_mutation=mutation)


def passed() -> ext_mcp_pb2.McpRequestResult:
    return ext_mcp_pb2.McpRequestResult(**{"pass": ext_mcp_pb2.Pass()})


def refuse(reason: str) -> ext_mcp_pb2.McpRequestResult:
    error = ext_mcp_pb2.AuthorizationError(code=ext_mcp_pb2.AuthorizationError.PERMISSION_DENIED, reason=reason)
    return ext_mcp_pb2.McpRequestResult(error=error)


def _clearance(message: ext_mcp_pb2.McpRequest) -> str | None:
    if not message.HasField("metadata_context"):
        return None
    value = message.metadata_context.fields.get(CLEARANCE_KEY)
    if value is None or not value.string_value:
        return None
    clearance: str = value.string_value
    return clearance
