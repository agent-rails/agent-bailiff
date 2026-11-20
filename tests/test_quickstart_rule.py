import importlib.util
import os
import threading
from pathlib import Path

import pytest
import test_custodian
from test_control import MemoryDocket
from test_control_suspension import shared_suspension
from test_custodian import WRITERS
from test_decide import NOW, FakeClock, make_request, make_root

from agent_bailiff.control import Control, Suspension
from agent_bailiff.control.control import ControlRefused, Outcome
from agent_bailiff.decide.refusals import RefusalBudget
from agent_bailiff.docket.follower import DocketFollower, load_checkpoint
from agent_bailiff.docket.sink import build_kid_index

ledger_path = test_custodian.ledger_path
make_decider = test_custodian.make_decider
private = test_custodian.private
sink = test_custodian.sink
workdir = test_custodian.workdir
writer = test_custodian.writer

_spec = importlib.util.spec_from_file_location(
    "quickstart_rule", Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "rule.py"
)
assert _spec is not None and _spec.loader is not None
rule_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rule_module)

INDEX = build_kid_index(WRITERS)
TOOLS = frozenset({"deploy.service"})
OUT_OF_SCOPE = {"resource": "env/prod/api"}


class Session:
    def __init__(self, control):
        self.control = control
        self.closed = False

    def close(self):
        self.closed = True


class RecordingControl:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def revoke(self, token, level, actor, now):
        self.calls.append((level, actor, now))
        if self.error is not None:
            raise self.error
        return Outcome("revoke", level, "trace", "entry", {"task": "task-1", "tenant": "tenant"})


@pytest.fixture
def control(writer, private):
    suspension = Suspension(shared_suspension(private("shared")), os.getegid())
    return Control("control.example", WRITERS, writer, suspension, MemoryDocket(), "control")


@pytest.fixture
def checkpoint(private):
    return private("rule") / "checkpoint.json"


def make_rule(control, tools=TOOLS, writer_name="decide"):
    sessions = []

    def open_session():
        sessions.append(Session(control))
        return sessions[-1]

    return rule_module.RevokeRule(open_session, writer_name, tools, clock=lambda: NOW), sessions


def follow(workdir, checkpoint, rule):
    return DocketFollower(workdir / "docket.log", INDEX, checkpoint, rule).run(threading.Event(), follow=False)


@pytest.mark.parametrize(
    ("request_fields", "tools", "writer_name", "revokes"),
    [
        (OUT_OF_SCOPE, TOOLS, "decide", 1),
        (OUT_OF_SCOPE, frozenset({"deploy.scale"}), "decide", 0),
        (OUT_OF_SCOPE, TOOLS, "custodian", 0),
        ({"tool": "deploy.delete"}, frozenset({"deploy.delete"}), "decide", 0),
        ({}, TOOLS, "decide", 0),
    ],
    ids=["out_of_scope", "other_tool", "other_writer", "other_reason", "allow"],
)
def test_only_a_decide_out_of_scope_refusal_of_a_configured_tool_revokes(
    make_decider, workdir, checkpoint, request_fields, tools, writer_name, revokes
):
    make_decider().check(make_request(**request_fields), NOW)
    recording = RecordingControl()
    rule, sessions = make_rule(recording, tools, writer_name)
    assert follow(workdir, checkpoint, rule) == 1
    assert recording.calls == [("task", "rule", NOW)] * revokes
    assert all(session.closed for session in sessions)


def test_a_revoke_stops_the_task_and_a_restart_does_not_revoke_again(make_decider, workdir, checkpoint, control):
    root = make_root()
    decider = make_decider()
    assert decider.check(make_request(root, **OUT_OF_SCOPE), NOW).reason == "out_of_scope"
    rule, sessions = make_rule(control)
    assert follow(workdir, checkpoint, rule) == 1
    assert decider.check(make_request(root, nonce="n-2"), NOW + 1).reason == "chain_invalid"
    assert follow(workdir, checkpoint, rule) == 0
    assert len(sessions) == 1 and sessions[0].closed


def test_a_second_revoke_of_the_same_record_succeeds_and_keeps_the_task_revoked(
    make_decider, workdir, private, checkpoint, control
):
    root = make_root()
    decider = make_decider()
    decider.check(make_request(root, **OUT_OF_SCOPE), NOW)
    rule, sessions = make_rule(control)
    follow(workdir, checkpoint, rule)
    follow(workdir, private("lost") / "checkpoint.json", rule)
    assert len(sessions) == 2
    assert decider.check(make_request(root, nonce="n-2"), NOW + 1).reason == "chain_invalid"


def test_two_refusals_of_one_task_in_a_batch_revoke_once(make_decider, workdir, checkpoint):
    root = make_root()
    decider = make_decider()
    for nonce in ("n-1", "n-2"):
        decider.check(make_request(root, nonce=nonce, **OUT_OF_SCOPE), NOW)
    recording = RecordingControl()
    rule, _ = make_rule(recording)
    assert follow(workdir, checkpoint, rule) == 2
    assert len(recording.calls) == 1


def test_padding_past_the_record_budget_revokes_the_task(make_decider, workdir, checkpoint, control):
    root = make_root()
    decider = make_decider(refusal_budget=RefusalBudget(limit=2, clock=FakeClock()))
    for n in range(4):
        decider.check(make_request(root, tool="deploy.delete", nonce=f"pad-{n}"), NOW)
    assert decider.check(make_request(root, nonce="probe", **OUT_OF_SCOPE), NOW).entry_id is None
    rule, _ = make_rule(control)
    assert follow(workdir, checkpoint, rule) == 3
    assert decider.check(make_request(root, nonce="after"), NOW + 1).reason == "chain_invalid"


def test_replays_of_an_allowed_call_past_the_record_budget_do_not_revoke(make_decider, workdir, checkpoint):
    request = make_request(make_root(), nonce="victim")
    decider = make_decider(refusal_budget=RefusalBudget(limit=2, clock=FakeClock()))
    assert decider.check(request, NOW).allowed
    replays = {decider.check(request, NOW).reason for _ in range(4)}
    assert replays == {"already_issued"}
    recording = RecordingControl()
    rule, _ = make_rule(recording)
    assert follow(workdir, checkpoint, rule) == 4
    assert recording.calls == []


def test_a_tenant_capped_marker_does_not_revoke(make_decider, workdir, checkpoint):
    decider = make_decider(refusal_budget=RefusalBudget(max_windows_per_tenant=1, clock=FakeClock()))
    for n in range(2):
        decider.check(make_request(make_root(task_id=f"task-{n}"), tool="deploy.delete", nonce=f"n-{n}"), NOW)
    recording = RecordingControl()
    rule, _ = make_rule(recording, frozenset({"deploy.delete"}))
    assert follow(workdir, checkpoint, rule) == 2
    assert recording.calls == []


def test_a_refused_revoke_stops_the_rule_before_the_checkpoint(make_decider, workdir, checkpoint):
    make_decider().check(make_request(**OUT_OF_SCOPE), NOW)
    rule, _ = make_rule(RecordingControl(ControlRefused("ledger_unavailable")))
    with pytest.raises(ControlRefused):
        follow(workdir, checkpoint, rule)
    assert load_checkpoint(checkpoint) is None
    recording = RecordingControl()
    rule, _ = make_rule(recording)
    follow(workdir, checkpoint, rule)
    assert len(recording.calls) == 1


def test_the_rule_needs_a_tool():
    with pytest.raises(ValueError, match="at least one tool"):
        rule_module.RevokeRule(lambda: None, "decide", frozenset())
