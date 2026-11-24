import json

import pytest
import test_custodian
from google.protobuf import struct_pb2
from test_agentgateway_calls import HEADERS, ROUTES, message
from test_custodian import DEPLOY_SECRET, NOW, custodian_entries, docket_entries
from test_decide import make_request

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.calls import read_call
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor, RedactorProcessor
from agent_bailiff.custodian import Refused, Released, ResponseChecked, ResponseRefused
from agent_bailiff.custodian.custodian import RESPONSE_REASONS
from agent_bailiff.custodian.echo import MARKER
from agent_bailiff.decide import Decision
from agent_bailiff.decide.request import OperationRequest
from agent_bailiff.routes import ToolRoute, ToolRoutes

ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
open_docket = test_custodian.open_docket
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer
DENIED = ext_mcp_pb2.AuthorizationError.PERMISSION_DENIED
CREDENTIAL_HEADERS = frozenset({"X-Api-Key", "X-Other-Key"})
AGENT_HEADERS = [
    "authorization",
    "bailiff-release",
    "cookie",
    "proxy-authorization",
    "x-bailiff-leaf-proof",
    "x-bailiff-links",
    "x-bailiff-nonce",
    "x-bailiff-task-root",
]


class FakeDecider:
    def __init__(self, decision=None, error=None):
        self.decision = decision or Decision(allowed=True, reason="ok", clearance="clearance.token")
        self.error = error
        self.calls = []

    def check(self, request, now):
        self.calls.append((request, now))
        if self.error:
            raise self.error
        return self.decision


class FakeCustodian:
    def __init__(self, result=None):
        self.result = result or Released("X-Api-Key", "secret-value", op_id="op", entry_id="entry")
        self.calls = []

    def release(self, clearance_token, request, now):
        self.calls.append((clearance_token, request, now))
        return self.result


def with_clearance(request, value="clearance.token"):
    context = struct_pb2.Struct()
    if value is not None:
        context.update({"clearance": value})
    request.metadata_context.CopyFrom(context)
    return request


def result_kind(result):
    return result.WhichOneof("result")


@pytest.mark.parametrize("method", ["initialize", "ping", "tools/list"])
def test_decide_passes_the_allowed_session_methods_untouched(method):
    decider = FakeDecider()
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(
        ext_mcp_pb2.McpRequest(method=method, service_names=["deploy"])
    )
    assert result_kind(result) == "pass"
    assert not result.HasField("metadata") and not result.HasField("header_mutation")
    assert decider.calls == []


@pytest.mark.parametrize(
    "method",
    [
        "prompts/get",
        "prompts/list",
        "resources/read",
        "resources/list",
        "resources/templates/list",
        "logging/setLevel",
        "server/discover",
        "subscriptions/listen",
        "tools/call/extra",
        "TOOLS/CALL",
        "",
    ],
)
def test_decide_refuses_every_other_method_with_a_generic_reason(method):
    decider = FakeDecider()
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(
        ext_mcp_pb2.McpRequest(method=method, service_names=["deploy"])
    )
    assert (result_kind(result), result.error.code, result.error.reason) == ("error", DENIED, "method_refused")
    assert not result.HasField("metadata")
    assert decider.calls == []


def test_decide_allow_passes_with_only_the_clearance_in_metadata():
    decider = FakeDecider()
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(message())
    assert result_kind(result) == "pass"
    assert dict(result.metadata.items()) == {"clearance": "clearance.token"}
    assert not result.HasField("header_mutation")
    [(request, now)] = decider.calls
    assert request == read_call(message(), ROUTES)
    assert now == NOW


def test_decide_refusal_returns_the_reason_without_metadata():
    decider = FakeDecider(Decision(allowed=False, reason="out_of_scope"))
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(message())
    assert result_kind(result) == "error"
    assert (result.error.code, result.error.reason) == (DENIED, "out_of_scope")
    assert not result.HasField("metadata") and not result.HasField("header_mutation")


def test_decide_refusal_never_passes_even_with_a_clearance():
    decider = FakeDecider(Decision(allowed=False, reason="suspended", clearance="clearance.token"))
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(message())
    assert (result_kind(result), result.error.reason) == ("error", "suspended")
    assert not result.HasField("metadata")


def test_decide_allow_without_a_clearance_is_refused():
    decider = FakeDecider(Decision(allowed=True, reason="ok", clearance=None))
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(message())
    assert result_kind(result) == "error"
    assert not result.HasField("metadata")


def test_decide_refuses_an_unreadable_call_without_asking_the_decider():
    decider = FakeDecider()
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(message(services=("attacker",)))
    assert (result_kind(result), result.error.reason) == ("error", "unknown_tool")
    assert decider.calls == []


def test_decide_internal_error_refuses():
    decider = FakeDecider(error=RuntimeError("boom"))
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(message())
    assert (result_kind(result), result.error.reason) == ("error", "internal_error")


def test_custodian_strips_agent_credentials_on_methods_other_than_tools_call():
    custodian = FakeCustodian()
    result = CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW).check_request(
        with_clearance(ext_mcp_pb2.McpRequest(method="tools/list", service_names=["deploy"]))
    )
    assert result_kind(result) == "pass"
    assert list(result.header_mutation.set) == []
    assert sorted(result.header_mutation.remove) == sorted([*AGENT_HEADERS, "x-api-key", "x-other-key"])
    assert not result.HasField("metadata")
    assert custodian.calls == []


def test_custodian_release_sets_the_credential_header_and_strips_chain_headers():
    custodian = FakeCustodian()
    result = CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW).check_request(
        with_clearance(message())
    )
    assert result_kind(result) == "pass"
    assert [(item.key, item.value) for item in result.header_mutation.set] == [("X-Api-Key", b"secret-value")]
    assert sorted(result.header_mutation.remove) == sorted([*AGENT_HEADERS, "x-other-key"])
    assert not result.HasField("metadata")
    [(token, request, now)] = custodian.calls
    assert (token, request, now) == ("clearance.token", read_call(message(), ROUTES), NOW)


AGENT_EXTRA_HEADERS = (
    ("Sudo", b"root"),
    ("x-forwarded-user", b"admin"),
    ("x-bailiff-extra", b"1"),
    ("user-agent", b"agent/1"),
    ("X-Api-Key", b"forged"),
    (":authority", b"gateway"),
    ("accept", b"application/json"),
    ("content-type", b"application/json"),
    ("mcp-protocol-version", b"2025-06-18"),
    ("tracestate", b"vendor=1"),
)
FORWARDED = {"accept", "content-type", "mcp-protocol-version", "traceparent", "tracestate"}


@pytest.mark.parametrize("method", ["tools/call", "tools/list", "initialize"])
def test_custodian_removes_every_agent_header_outside_the_upstream_allowlist(method):
    request = with_clearance(message(extra_headers=AGENT_EXTRA_HEADERS))
    request.method = method
    result = CustodianProcessor(FakeCustodian(), ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW).check_request(request)
    assert result_kind(result) == "pass"
    removed = set(result.header_mutation.remove)
    sent = {header.key.lower() for header in request.headers if not header.key.startswith(":")}
    released = {item.key.lower() for item in result.header_mutation.set}
    assert sent - removed == FORWARDED | released
    assert {"sudo", "x-forwarded-user", "x-bailiff-extra", "user-agent"} <= removed
    assert not [name for name in removed if name.startswith(":")]


@pytest.mark.parametrize("context", ["absent", "empty", None, 7])
def test_custodian_refuses_without_a_string_clearance(context):
    custodian = FakeCustodian()
    request = message()
    if context == "empty":
        with_clearance(request, None)
    elif context != "absent":
        request.metadata_context.CopyFrom(struct_pb2.Struct())
        request.metadata_context.update({"clearance": context})
    result = CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW).check_request(request)
    assert (result_kind(result), result.error.reason) == ("error", "clearance_missing")
    assert not result.HasField("header_mutation")
    assert custodian.calls == []


@pytest.mark.parametrize("reason", ["canary", "already_issued", "clearance_mismatch", "rate_limited", "task_denied"])
def test_custodian_refusals_share_one_generic_reason_without_a_header(reason):
    custodian = FakeCustodian(Refused(reason))
    result = CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW).check_request(
        with_clearance(message())
    )
    assert (result_kind(result), result.error.code, result.error.reason) == ("error", DENIED, "release_refused")
    assert not result.HasField("header_mutation")


def test_custodian_refuses_an_unreadable_call_without_releasing():
    custodian = FakeCustodian()
    headers = {key: value for key, value in HEADERS.items() if key != "x-bailiff-nonce"}
    result = CustodianProcessor(custodian, ROUTES, CREDENTIAL_HEADERS, clock=lambda: NOW).check_request(
        with_clearance(message(headers=headers))
    )
    assert (result_kind(result), result.error.reason) == ("error", "malformed_request")
    assert custodian.calls == []


GATEWAY_ROUTES = ToolRoutes([ToolRoute("deploy", "deploy_service", "deploy.service", "env/staging/api")])


def gateway_call(request: OperationRequest, *, metadata=None):
    headers = {
        "x-bailiff-task-root": request.task_root,
        "x-bailiff-leaf-proof": request.leaf_proof,
        "x-bailiff-nonce": request.nonce,
    }
    call = message(params={"name": "deploy_service", "arguments": request.args}, headers=headers)
    if metadata is not None:
        call.metadata_context.CopyFrom(metadata)
    return call


def test_a_decide_clearance_releases_the_credential_once_through_both_processors(make_decider, make_custodian, workdir):
    request = make_request(trace_id="")
    decide = DecideProcessor(make_decider(), GATEWAY_ROUTES, clock=lambda: NOW)
    custodian = CustodianProcessor(
        make_custodian(), GATEWAY_ROUTES, frozenset({"Authorization"}), clock=lambda: NOW + 1
    )
    decided = decide.check_request(gateway_call(request))
    assert result_kind(decided) == "pass", decided
    released = custodian.check_request(gateway_call(request, metadata=decided.metadata))
    assert result_kind(released) == "pass", released
    [header] = released.header_mutation.set
    assert (header.key, header.value) == ("Authorization", DEPLOY_SECRET)
    replayed = custodian.check_request(gateway_call(request, metadata=decided.metadata))
    assert (result_kind(replayed), replayed.error.reason) == ("error", "release_refused")
    assert not replayed.HasField("header_mutation")
    redecided = decide.check_request(gateway_call(request))
    assert (result_kind(redecided), redecided.error.reason) == ("error", "already_issued")
    decide_allow = [entry for entry in docket_entries(workdir) if entry.hop == "decide" and entry.decision == "allow"]
    release = [entry for entry in custodian_entries(workdir) if entry.decision == "release"]
    assert len(decide_allow) == len(release) == 1
    assert release[0].parent_entry == decide_allow[0].entry_id
    assert (release[0].trace_id, release[0].op_id) == (decide_allow[0].trace_id, decide_allow[0].op_id)


def test_a_clearance_for_other_arguments_is_refused_by_the_custodian(make_decider, make_custodian):
    request = make_request(trace_id="")
    other = make_request(trace_id="", args={"service": "api", "replicas": 3}, nonce="n-2")
    decide = DecideProcessor(make_decider(), GATEWAY_ROUTES, clock=lambda: NOW)
    custodian = CustodianProcessor(
        make_custodian(), GATEWAY_ROUTES, frozenset({"Authorization"}), clock=lambda: NOW + 1
    )
    decided = decide.check_request(gateway_call(request))
    result = custodian.check_request(gateway_call(other, metadata=decided.metadata))
    assert (result_kind(result), result.error.reason) == ("error", "release_refused")
    assert not result.HasField("header_mutation")


def test_custodian_never_removes_the_header_it_releases():
    custodian = FakeCustodian(Released("Authorization", "Bearer released", op_id="op", entry_id="entry"))
    processor = CustodianProcessor(custodian, ROUTES, frozenset({"Authorization"}), clock=lambda: NOW)
    result = processor.check_request(with_clearance(message()))
    assert [(item.key, item.value) for item in result.header_mutation.set] == [("Authorization", b"Bearer released")]
    assert "authorization" not in [name.lower() for name in result.header_mutation.remove]
    assert "cookie" in result.header_mutation.remove


@pytest.mark.parametrize("headers", [frozenset({"bad header"}), frozenset({""})])
def test_custodian_processor_needs_valid_credential_header_names(headers):
    with pytest.raises(ValueError):
        CustodianProcessor(FakeCustodian(), ROUTES, headers)


class FakeChecker:
    def __init__(self, result=None, error=None):
        self.result = result or ResponseChecked(None)
        self.error = error
        self.calls = []

    def check_response(self, clearance_token, result, now):
        self.calls.append((clearance_token, result, now))
        if self.error:
            raise self.error
        return self.result


CALL_RESULT = b'{"content":[{"type":"text","text":"done"}]}'


def call_response(method="tools/call", clearance="clearance.token", body=CALL_RESULT):
    response = ext_mcp_pb2.McpResponse(service_names=["deploy"], method=method, mcp_response=body)
    if clearance is not None:
        response.metadata_context.update({"clearance": clearance})
    return response


@pytest.mark.parametrize("method", ["initialize", "ping", "tools/list", "resources/read"])
def test_redactor_passes_results_of_other_methods_without_a_check(method):
    checker = FakeChecker()
    result = RedactorProcessor(checker, clock=lambda: NOW).check_response(call_response(method, clearance=None))
    assert result_kind(result) == "pass"
    assert checker.calls == []


def test_redactor_passes_an_unchanged_result():
    checker = FakeChecker()
    result = RedactorProcessor(checker, clock=lambda: NOW).check_response(call_response())
    assert result_kind(result) == "pass"
    assert checker.calls == [("clearance.token", CALL_RESULT, NOW)]


def test_redactor_replaces_a_redacted_result():
    checker = FakeChecker(ResponseChecked(b'{"content":[]}'))
    result = RedactorProcessor(checker, clock=lambda: NOW).check_response(call_response())
    assert (result_kind(result), result.mutated) == ("mutated", b'{"content":[]}')


@pytest.mark.parametrize("context", ["absent", "empty", 7])
def test_redactor_refuses_a_call_result_without_a_clearance(context):
    checker = FakeChecker()
    response = call_response(clearance=None)
    if context == "empty":
        response.metadata_context.update({"clearance": ""})
    elif context == 7:
        response.metadata_context.update({"clearance": 7})
    result = RedactorProcessor(checker, clock=lambda: NOW).check_response(response)
    assert (result_kind(result), result.error.code) == ("error", DENIED)
    assert result.error.reason == "response_clearance_missing"
    assert checker.calls == []


@pytest.mark.parametrize("reason", sorted(RESPONSE_REASONS))
def test_redactor_refusals_carry_the_custodian_reason(reason):
    result = RedactorProcessor(FakeChecker(ResponseRefused(reason)), clock=lambda: NOW).check_response(call_response())
    assert (result_kind(result), result.error.code, result.error.reason) == ("error", DENIED, reason)


def test_redactor_internal_error_refuses():
    checker = FakeChecker(error=RuntimeError("boom"))
    result = RedactorProcessor(checker, clock=lambda: NOW).check_response(call_response())
    assert (result_kind(result), result.error.reason) == ("error", "response_internal_error")


def test_a_released_credential_echoed_in_the_call_result_is_redacted(make_decider, make_custodian, workdir):
    request = make_request(trace_id="")
    custodian = make_custodian()
    decide = DecideProcessor(make_decider(), GATEWAY_ROUTES, clock=lambda: NOW)
    releaser = CustodianProcessor(custodian, GATEWAY_ROUTES, frozenset({"Authorization"}), clock=lambda: NOW + 1)
    redactor = RedactorProcessor(custodian, clock=lambda: NOW + 2)
    decided = decide.check_request(gateway_call(request))
    assert result_kind(releaser.check_request(gateway_call(request, metadata=decided.metadata))) == "pass"
    echo = json.dumps({"content": [{"type": "text", "text": f"sent {DEPLOY_SECRET.decode()}"}]}).encode()
    response = ext_mcp_pb2.McpResponse(method="tools/call", mcp_response=echo)
    response.metadata_context.CopyFrom(decided.metadata)
    result = redactor.check_response(response)
    assert result_kind(result) == "mutated"
    assert json.loads(result.mutated)["content"][0]["text"] == f"sent {MARKER}"
    release, alert = custodian_entries(workdir)
    assert (alert.decision, alert.reason, alert.parent_entry) == ("alert", "credential_echo", release.entry_id)
