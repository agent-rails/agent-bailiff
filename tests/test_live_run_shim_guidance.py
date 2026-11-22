import sys
from pathlib import Path

import pytest

from agent_bailiff.client import NeedsApproval, Refused

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "live-run"))
import shim  # noqa: E402


def guidance_text(outcome):
    result = shim.mcp_result(outcome)
    assert result["isError"] is True
    [item] = result["content"]
    return item["text"]


@pytest.mark.parametrize(
    ("outcome", "phrases"),
    [
        (Refused("out_of_scope"), ("did not forward", "do not retry", "tell the user")),
        (Refused("already_issued"), ("did not forward", "do not retry")),
        (Refused("release_refused"), ("did not forward", "do not retry")),
        (NeedsApproval(), ("approve", "did not forward", "tell the user")),
        (Refused("suspended"), ("operator suspended", "do not retry until it is resumed")),
        (Refused("docket_unavailable"), ("did not forward", "may already be spent", "at most twice")),
        (Refused("ledger_unavailable"), ("may already be spent", "at most twice")),
        (Refused("internal_error"), ("may already be spent", "at most twice")),
    ],
)
def test_a_refusal_tells_the_model_what_to_do(outcome, phrases):
    message = guidance_text(outcome)
    assert message.startswith(f"{outcome.reason}: ")
    for phrase in phrases:
        assert phrase in message


@pytest.mark.parametrize("reason", ["out_of_scope", "release_refused", "already_issued"])
def test_a_stop_refusal_does_not_claim_the_task_lacks_authority(reason):
    assert "authority" not in guidance_text(Refused(reason))


def test_a_retry_refusal_does_not_claim_the_call_was_not_made():
    assert "not made" not in guidance_text(Refused("docket_unavailable"))
