from __future__ import annotations

import re

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SERVICE_NAME = re.compile(r"[a-z][a-z0-9_-]*")
PLAIN_HTTP_HOSTS = "127.0.0.1, localhost, [::1] or a single-label service name"


def allows_plain_http(host: str) -> bool:
    return host in LOOPBACK_HOSTS or SERVICE_NAME.fullmatch(host) is not None
