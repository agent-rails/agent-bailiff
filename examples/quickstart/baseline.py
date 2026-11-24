"""Quickstart latency baseline. It calls the upstream MCP server directly, with the credential the custodian would
inject, so the same tool and call counts as `agent.py load` run without the gateway, decide and custodian. The
difference between the two is the time bailiff adds. It runs as the bootstrap service because only that service can
read both the stored credential and the upstream network."""

from __future__ import annotations

import argparse
import http.client
import json
import statistics
import sys
import threading
import time
from collections import Counter
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

PROTOCOL_VERSION = "2025-06-18"
SESSION_HEADER = "mcp-session-id"
TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TOOL = "list_issues"
ARGUMENTS = {"owner": "quickstart", "repo": "demo"}


class BaselineFailed(Exception):
    pass


class DirectClient:
    def __init__(self, url: str, authorization: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "http" or not parts.hostname:
            raise ValueError("the baseline url must be an http URL")
        self._path = parts.path or "/"
        self._authorization = authorization
        self._connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=TIMEOUT_SECONDS)
        self._session: str | None = None
        self._next_id = 1

    def open(self) -> None:
        params = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "baseline", "version": "1"},
        }
        self._post("initialize", params)
        self._post("notifications/initialized", None)

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        message = self._post("tools/call", {"name": name, "arguments": arguments})
        result = message.get("result") if message else None
        if not isinstance(result, dict):
            return "no result"
        return "error result" if result.get("isError") is True else "result"

    def close(self) -> None:
        self._connection.close()

    def _post(self, method: str, params: dict[str, Any] | None) -> dict[str, Any] | None:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not method.startswith("notifications/"):
            body["id"] = self._next_id
            self._next_id += 1
        headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "authorization": self._authorization,
            "mcp-protocol-version": PROTOCOL_VERSION,
        }
        if self._session is not None:
            headers[SESSION_HEADER] = self._session
        self._connection.request("POST", self._path, json.dumps(body).encode(), headers)
        response = self._connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status not in {200, 202} or len(raw) > MAX_RESPONSE_BYTES:
            raise BaselineFailed(f"{method} returned HTTP {response.status}")
        if method == "initialize":
            self._session = response.getheader(SESSION_HEADER)
        if "id" not in body:
            return None
        return decode(raw, response.getheader("content-type") or "")


def decode(raw: bytes, content_type: str) -> dict[str, Any] | None:
    text = raw.decode("utf-8")
    if content_type.startswith("text/event-stream"):
        text = "\n".join(line.removeprefix("data:").strip() for line in text.splitlines() if line.startswith("data:"))
    if not text.strip():
        return None
    message = json.loads(text)
    return message if isinstance(message, dict) else None


def percentile(latencies: list[float], fraction: float) -> float:
    return statistics.quantiles(latencies, n=100, method="inclusive")[round(fraction * 100) - 1]


def run_baseline(
    url: str, authorization: str, clients: int, calls: int, tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    start = threading.Barrier(clients + 1)
    samples: list[list[tuple[float, str]]] = [[] for _ in range(clients)]
    errors: list[BaseException] = []

    def drive(index: int) -> None:
        client = DirectClient(url, authorization)
        try:
            client.open()
            start.wait()
            for _ in range(calls):
                began = time.perf_counter()
                outcome = client.call(tool, arguments)
                samples[index].append((time.perf_counter() - began, outcome))
        except BaseException as error:
            errors.append(error)
            start.abort()
        finally:
            client.close()

    threads = [threading.Thread(target=drive, args=(index,)) for index in range(clients)]
    for thread in threads:
        thread.start()
    try:
        start.wait()
    except threading.BrokenBarrierError:
        pass
    began = time.perf_counter()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - began
    if errors:
        raise BaselineFailed(f"a baseline client failed: {errors[0]!r}")
    latencies = [latency for client in samples for latency, _ in client]
    outcomes = Counter(outcome for client in samples for _, outcome in client)
    return {
        "clients": clients,
        "calls": len(latencies),
        "seconds": round(elapsed, 3),
        "calls_per_second": round(len(latencies) / elapsed, 1),
        "p50_ms": round(percentile(latencies, 0.50) * 1000, 1),
        "p99_ms": round(percentile(latencies, 0.99) * 1000, 1),
        "outcomes": dict(sorted(outcomes.items())),
    }


def stored_authorization() -> tuple[str, str]:
    import bootstrap

    upstream = bootstrap.load_upstream(bootstrap.UPSTREAM_FILE)
    credential = bootstrap.stored_credential(upstream)
    if credential is None:
        raise BaselineFailed("the custodian holds no credential for the upstream")
    return upstream.url, credential


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clients", type=int, default=1)
    parser.add_argument("--calls", type=int, default=20)
    args = parser.parse_args(argv)
    if args.clients < 1 or args.calls < 2:
        parser.error("--clients must be at least 1 and --calls at least 2")
    try:
        url, authorization = stored_authorization()
        print(json.dumps(run_baseline(url, authorization, args.clients, args.calls, TOOL, ARGUMENTS)))
        return 0
    except (BaselineFailed, OSError, ValueError, http.client.HTTPException) as error:
        print(f"baseline failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
