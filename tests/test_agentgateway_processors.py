import pytest
import test_custodian
from agent_warrant.ledger import TaskLedger
from google.protobuf import struct_pb2
from test_agentgateway_calls import HEADERS, ROUTES, message
from test_custodian import DEPLOY_SECRET, NOW, custodian_entries, docket_entries
from test_decide import make_request

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.calls import ToolRoute, ToolRoutes, read_call
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor
from agent_bailiff.custodian import Refused, Released
from agent_bailiff.decide import Decision
from agent_bailiff.decide.request import OperationRequest

ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
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


def test_decide_passes_methods_other_than_tools_call_untouched():
    decider = FakeDecider()
    result = DecideProcessor(decider, ROUTES, clock=lambda: NOW).check_request(
        ext_mcp_pb2.McpRequest(method="tools/list", service_names=["deploy"])
    )
    assert result_kind(result) == "pass"
    assert not result.HasField("metadata") and not result.HasField("header_mutation")
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


needs_read_only_ledger = pytest.mark.skipif(
    not hasattr(TaskLedger, "open_read_only"),
    reason="needs agent-warrant with TaskLedger.open_read_only (unreleased PR #15); move the pin after its release",
)
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


@needs_read_only_ledger
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


@needs_read_only_ledger
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


@pytest.mark.parametrize("headers", [frozenset(), frozenset({"bad header"}), frozenset({""})])
def test_custodian_processor_needs_valid_credential_header_names(headers):
    with pytest.raises(ValueError):
        CustodianProcessor(FakeCustodian(), ROUTES, headers)
