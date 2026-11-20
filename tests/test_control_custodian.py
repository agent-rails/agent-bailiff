import os

import pytest
import test_custodian
from test_control import MemoryDocket
from test_control_suspension import shared_suspension
from test_custodian import WRITERS, Refused, Released, custodian_entries
from test_decide import NOW, make_request, make_root

from agent_bailiff.control import Control, Suspension
from agent_bailiff.control.suspension import SuspensionView
from agent_bailiff.docket import decode_record
from agent_bailiff.docket.sink import build_kid_index

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


@pytest.fixture
def suspension_dir(private):
    return shared_suspension(private("shared"))


@pytest.fixture
def control(writer, suspension_dir):
    return Control(
        "control.example",
        WRITERS,
        writer,
        Suspension(suspension_dir, os.getegid()),
        MemoryDocket(),
        "control",
    )


def line_for(workdir, hop, decision):
    index = build_kid_index(WRITERS)
    for line in (workdir / "docket.log").read_text().splitlines():
        entry = decode_record(line, index).entry
        if (entry.hop, entry.decision) == (hop, decision):
            return line
    raise AssertionError(f"no {hop} {decision} record")


@pytest.mark.parametrize("level", ["task", "tenant", "root"])
def test_a_revoke_after_decide_allowed_stops_the_release_at_the_custodian(
    make_decider, make_custodian, control, workdir, level
):
    request = make_request()
    decision = make_decider().check(request, NOW)
    assert decision.allowed
    control.revoke(line_for(workdir, "decide", "allow"), level, "ops", NOW)
    assert make_custodian().release(decision.clearance, request, NOW + 1) == Refused("chain_invalid")
    assert [entry for entry in custodian_entries(workdir) if entry.decision == "release"] == []


def test_a_canary_alert_record_revokes_its_task(make_decider, make_custodian, control, workdir):
    root = make_root()
    decider = make_decider()
    canary = make_request(root, tool="deploy.canary")
    assert make_custodian().release(decider.check(canary, NOW).clearance, canary, NOW + 1) == Refused("canary")
    control.revoke(line_for(workdir, "custodian", "alert"), "task", "ops", NOW + 2)
    later = make_request(root, nonce="n-2")
    assert decider.check(later, NOW + 2).reason == "chain_invalid"


def test_a_call_without_a_revoke_is_still_released(make_decider, make_custodian, workdir):
    request = make_request()
    decision = make_decider().check(request, NOW)
    assert isinstance(make_custodian().release(decision.clearance, request, NOW + 1), Released)


def test_a_suspend_after_decide_allowed_stops_the_release_until_resume(
    make_decider, make_custodian, control, workdir, suspension_dir
):
    request = make_request()
    decision = make_decider().check(request, NOW)
    assert decision.allowed
    control.suspend(line_for(workdir, "decide", "allow"), "ops", NOW)
    custodian = make_custodian(suspension=SuspensionView(suspension_dir, os.geteuid(), os.getegid()))
    assert custodian.release(decision.clearance, request, NOW + 1) == Refused("suspended")
    assert [entry.reason for entry in custodian_entries(workdir) if entry.decision == "refuse"] == ["suspended"]
    control.resume("ops", NOW + 1)
    assert isinstance(custodian.release(decision.clearance, request, NOW + 2), Released)
