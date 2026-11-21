from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from agent_bailiff.docket.manifest import Manifest, SegmentEntry
from agent_bailiff.docket.receipt import Receipt

MAX_CLOCK_AHEAD = 60
MIN_RECEIPT_AGE = 3600
MAX_RECEIPT_AGE = 7 * 86400

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Retention:
    receipt_dir: Path
    archiver_uid: int
    retained_bytes: int
    max_receipt_age: int

    def __post_init__(self) -> None:
        if not self.receipt_dir.is_absolute():
            raise ValueError("receipt_dir must be an absolute path")
        if type(self.archiver_uid) is not int or self.archiver_uid < 0:
            raise ValueError("archiver_uid must be a non-negative integer")
        if type(self.retained_bytes) is not int or self.retained_bytes < 1:
            raise ValueError("retained_bytes must be a positive integer")
        age = self.max_receipt_age
        if type(age) is not int or not MIN_RECEIPT_AGE <= age <= MAX_RECEIPT_AGE:
            raise ValueError(f"max_receipt_age must be an integer between {MIN_RECEIPT_AGE} and {MAX_RECEIPT_AGE}")


def removable(
    manifest: Manifest,
    receipt: Receipt | None,
    *,
    retained_bytes: int,
    cap: int,
    now: int,
    max_age: int,
) -> SegmentEntry | None:
    if not manifest.segments or retained_bytes <= cap:
        return None
    oldest = manifest.segments[0]
    if receipt is None:
        return None
    mismatched = _mismatched_fields(manifest.docket_id, oldest, receipt)
    if mismatched:
        logger.error(
            "receipt for docket segment %d does not match its manifest entry (%s); it is kept",
            oldest.segment,
            ", ".join(mismatched),
        )
        return None
    if receipt.verified_at > now + MAX_CLOCK_AHEAD:
        logger.error(
            "receipt for docket segment %d was verified %d s in the future; it is kept",
            oldest.segment,
            receipt.verified_at - now,
        )
        return None
    if now - receipt.verified_at > max_age:
        logger.warning(
            "receipt for docket segment %d is %d s old, over the %d s limit; it is kept",
            oldest.segment,
            now - receipt.verified_at,
            max_age,
        )
        return None
    return oldest


def _mismatched_fields(docket_id: str, entry: SegmentEntry, receipt: Receipt) -> list[str]:
    expected = {
        "docket_id": docket_id,
        "segment": entry.segment,
        "sha256": entry.sha256,
        "size": entry.size,
        "end_heads": dict(entry.end_heads),
    }
    actual = {
        "docket_id": receipt.docket_id,
        "segment": receipt.segment,
        "sha256": receipt.sha256,
        "size": receipt.size,
        "end_heads": dict(receipt.end_heads),
    }
    return [name for name in expected if expected[name] != actual[name]]
