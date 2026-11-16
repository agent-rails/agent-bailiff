import pytest
import test_custodian
from test_control import MemoryDocket
from test_custodian import WRITERS, Refused, Released, custodian_entries
from test_decide import NOW, make_request, make_root

from agent_bailiff.control import Control, Suspension
from agent_bailiff.docket import decode_record
from agent_bailiff.docket.sink import build_kid_index

ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer


@pytest.fixture
def control(writer, private):
    return Control("control.example", WRITERS, writer, Suspension(private("suspension")), MemoryDocket(), "control")


def line_for(workdir, hop, decision):
    index = build_kid_index(WRITERS)
    for line in (workdir / "docket.log").read_text().splitlines():
        entry = decode_record(line, index).entry
        if (entry.hop, entry.decision) == (hop, decision):
            return line
    raise AssertionError(f"no {hop} {decision} record")


@pytest.mark.parametrize("level", ["agent_key", "task", "tenant", "root"])
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
