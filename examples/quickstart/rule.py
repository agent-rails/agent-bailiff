"""Quickstart revoke rule. It follows the verified docket and revokes a task through control when decide refuses one
of the task's calls as out_of_scope for a configured tool, or records that the task passed its refusal record budget
(refusals_capped). It is a rule, not detection: it matches signed fields and sees only what decide recorded."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from agent_warrant.ledger import LedgerError

from agent_bailiff.control.control import Control, ControlRefused, ControlUnrecorded
from agent_bailiff.decide.refusals import CAPPED_REASON
from agent_bailiff.docket.client import DocketError
from agent_bailiff.docket.follower import CheckpointMismatch, DocketFollower, FollowerLocked
from agent_bailiff.docket.report import pinned_writers
from agent_bailiff.docket.sink import DocketCorrupt, VerifiedLine, build_kid_index
from agent_bailiff.service.init import read_pin
from agent_bailiff.service.run import open_control
from agent_bailiff.service.settings import load_control, load_decide

DOCKET = Path("/var/lib/bailiff/docket/docket.log")
PINS = tuple(Path(f"/pins/{component}/{component}.json") for component in ("decide", "custodian", "control", "rule"))
CHECKPOINT = Path("/var/lib/bailiff/rule/checkpoint.json")
CONTROL_CONFIG = Path("/var/lib/bailiff/rule/config.json")
DECIDE_WRITER = "decide.quickstart"
TOOLS = ("gitea.contents.read",)
ACTOR = "rule"
POLL_INTERVAL = 0.5
FAILURES = (
    ControlRefused,
    ControlUnrecorded,
    CheckpointMismatch,
    FollowerLocked,
    DocketCorrupt,
    DocketError,
    LedgerError,
    OSError,
    ValueError,
)


class Session(Protocol):
    control: Control

    def close(self) -> None: ...


class RevokeRule:
    def __init__(
        self,
        open_session: Callable[[], Session],
        writer: str,
        tools: frozenset[str],
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not tools:
            raise ValueError("the rule needs at least one tool")
        self._open_session = open_session
        self._writer = writer
        self._tools = tools
        self._clock = clock

    def matches(self, verified: VerifiedLine) -> bool:
        entry = verified.record.entry
        if verified.record.writer != self._writer or entry.decision != "refuse":
            return False
        return entry.reason == CAPPED_REASON or (entry.reason == "out_of_scope" and entry.tool in self._tools)

    def __call__(self, batch: Sequence[VerifiedLine], stop: threading.Event) -> None:
        revoked: set[tuple[str | None, str | None]] = set()
        for verified in batch:
            if not self.matches(verified):
                continue
            entry = verified.record.entry
            task = (entry.tenant, entry.handles.get("task"))
            if task in revoked:
                continue
            self._revoke(verified)
            revoked.add(task)

    def _revoke(self, verified: VerifiedLine) -> None:
        session = self._open_session()
        try:
            outcome = session.control.revoke(verified.record.token, "task", ACTOR, int(self._clock()))
        finally:
            session.close()
        reason = verified.record.entry.reason
        line = {"rule": reason, "line": verified.line, "entry_id": outcome.entry_id, **outcome.handles}
        print(json.dumps(line, sort_keys=True), flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", action="append", dest="tools", help=f"tool to match (default: {', '.join(TOOLS)})")
    parser.add_argument("--once", action="store_true", help="check the records present now, then exit")
    args = parser.parse_args(argv)
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    try:
        settings = load_control(CONTROL_CONFIG)
        decide = load_decide(settings.decide_config)
        index = build_kid_index(pinned_writers(read_pin(path) for path in PINS))
        rule = RevokeRule(lambda: open_control(settings, decide), DECIDE_WRITER, frozenset(args.tools or TOOLS))
        checked = DocketFollower(DOCKET, index, CHECKPOINT, rule, poll_interval=POLL_INTERVAL).run(
            stop, follow=not args.once
        )
    except FAILURES as error:
        print(f"rule failed: {error}", file=sys.stderr)
        return 1
    print(f"rule: {checked} records checked", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
