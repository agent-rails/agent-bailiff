from __future__ import annotations

import re

TASK_ROOT_HEADER = "x-bailiff-task-root"
LINKS_HEADER = "x-bailiff-links"
LEAF_PROOF_HEADER = "x-bailiff-leaf-proof"
NONCE_HEADER = "x-bailiff-nonce"
TRACEPARENT_HEADER = "traceparent"
REQUIRED_HEADERS = frozenset({TASK_ROOT_HEADER, LEAF_PROOF_HEADER, NONCE_HEADER})
CALL_HEADERS = REQUIRED_HEADERS | {LINKS_HEADER, TRACEPARENT_HEADER}
TRACEPARENT = re.compile(r"00-(?!0{32})([0-9a-f]{32})-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}")
