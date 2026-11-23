"""Turns a call's outcome into the MCP result the model reads, with what it should do next on a refusal."""

from __future__ import annotations

from typing import Any

from agent_bailiff.client import NeedsApproval, Outcome, OutcomeUnknown, Refused, Result

GUIDANCE = {
    "stop": "agent-bailiff refused this call and the gateway did not forward it; "
    "do not retry it or get its effect another way; tell the user",
    "ask_user": "agent-bailiff needs a human to approve this call; the gateway did not forward it; "
    "stop and tell the user",
    "retry_later": "an agent-bailiff component was unavailable and the gateway did not forward the call; "
    "budget for this attempt may already be spent; retry at most twice with backoff, then stop and tell the user",
}
SUSPENDED_GUIDANCE = (
    "an operator suspended agent-bailiff and the gateway did not forward the call; "
    "stop, tell the user, and do not retry until it is resumed"
)

TASK_EXPIRED = (
    "task_expired: this task's authority has expired and nothing was sent; stop and ask the user to issue a new task"
)
NO_TASK = "no_task: no task has been issued to this agent and nothing was sent; stop and ask the user to issue one"
OUTCOME_UNKNOWN = (
    "the call was sent but its outcome is unknown, so it may have taken effect; "
    "do not retry it; check the target's state or tell the user"
)
GATEWAY_UNAVAILABLE = (
    "gateway_unavailable: the gateway did not answer and the call was not sent; "
    "retry at most twice with backoff, then stop and tell the user"
)


def guidance(outcome: Refused | NeedsApproval) -> str:
    if outcome.reason == "suspended":
        return SUSPENDED_GUIDANCE
    return GUIDANCE[outcome.action]


def mcp_result(outcome: Outcome) -> dict[str, Any]:
    if isinstance(outcome, Result):
        return dict(outcome.result)
    if isinstance(outcome, Refused | NeedsApproval):
        return text(f"{outcome.reason}: {guidance(outcome)}", error=True)
    if isinstance(outcome, OutcomeUnknown):
        return text(f"outcome_unknown: {outcome.detail}; {OUTCOME_UNKNOWN}", error=True)
    raise AssertionError(f"unexpected outcome {outcome!r}")


def text(value: str, *, error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": value}], "isError": error}
