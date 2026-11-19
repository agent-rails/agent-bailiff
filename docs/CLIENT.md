# Agent-side client (contract v1)

`agent_bailiff.client.BailiffClient` signs and sends an agent's `tools/call` through agentgateway. It holds the agent's key and chain, never a service credential. It imports neither the gateway adapter, gRPC nor protobuf.

```python
from agent_bailiff.client import BailiffClient, Holder

client = BailiffClient(url, Holder(task_root, links, agent_key, decider_id), routes)
outcome = client.call("gitea", "get_me", {})
```

## Request contract

- Routes are the same `agent_bailiff.routes.ToolRoutes` the gateway adapter reads. `prepare(service, name, arguments)` maps the call to its scope `tool` and `resource`, and rejects an unrouted tool or arguments outside the route's schema before signing.
- Nonce: 16 random bytes, hex. Each `prepare` makes a new nonce, so each prepared call is a new operation.
- Leaf proof: signed by the holder key over the last record in the chain, with `audience` set to the decider id, `iat` from the client clock, and `request_digest` = `request_digest(tool, resource, arguments, nonce)` (`agent_bailiff/decide/identity.py`).
- Headers: `x-bailiff-task-root`, `x-bailiff-leaf-proof`, `x-bailiff-nonce`, `traceparent`, and `x-bailiff-links` (comma-joined) when the holder is a delegate.
- `traceparent`: W3C version `00`, generated with random non-zero trace and parent ids, or supplied by the caller and validated. The gateway adapter treats an all-zero id as absent.
- Body: one JSON-RPC `tools/call` request, compact JSON with sorted keys.
- `Holder` rejects a key that is not the subject of the last record in the chain.
- Golden vectors: `tests/vectors/client-v1.json` (root holder and delegated holder). `tests/test_client.py` checks that the client produces them and that the gateway adapter reads them back to the same tool, resource, arguments, links, trace id and request digest.

## Session

- MCP Streamable HTTP. `initialize` offers `2025-11-25` and accepts `2025-11-25` or `2025-06-18`; any other version fails with `GatewayError`. agentgateway v1.7.0 negotiates `2025-11-25`.
- After `initialize` the client sends `notifications/initialized`, then sends `MCP-Protocol-Version` on every request, and `Mcp-Session-Id` when the gateway returned one.
- HTTP 404 on a request that carried a session id ends the session. The next use initializes again after a jittered delay. A `tools/call` that got the 404 returns `OutcomeUnknown("session_expired")` and is not resent; `tools/list` initializes again and retries once.
- `initialize`, `notifications/initialized` and `tools/list` retry up to 3 attempts with full-jitter backoff (0.2 s base, 2 s cap) on a transport error or HTTP 429, 502, 503 or 504. `tools/call` is never retried.
- One keep-alive connection. A client is used only by the thread that created it.

## Outcomes of `send` and `call`

| Outcome | Meaning |
| --- | --- |
| `Result(result)` | The upstream answered. `is_error` is the MCP tool-error flag. |
| `Refused(reason)` | The gateway refused the call with a bailiff reason (`REFUSAL_REASONS`). The call was not forwarded upstream. |
| `NeedsApproval()` | The policy requires a human (`needs_approval`). The call was not forwarded upstream. |
| `OutcomeUnknown(detail)` | Timeout, dropped connection, oversized response, non-200 status, JSON-RPC error or expired session. The credential may have been released and the target may have acted. |

- A gateway refusal is an HTTP 200 tool error whose only content is one text item equal to the reason. The client trusts that shape: an upstream that returns exactly a bailiff reason as its error text is classified as `Refused`.
- A non-200 status after the gateway forwarded the call, such as an upstream rejecting the released credential, is `OutcomeUnknown`.
- After `OutcomeUnknown`, do not assume the call failed. Preparing the call again is a new operation with a new nonce and spends budget again.
- `GatewayError` is raised only by session setup and `tools/list`.

## Limits

- Responses are capped at 4 MiB. `timeout` (default 30 s) applies to each socket operation; an event-stream response also stops at `timeout` after the response headers.
- A `PreparedCall` is sent at most once. Its `headers` and `body` stay readable, which is how the quickstart's replay scenario captures and resends a call.
- Not in v1: tool-name prefixes from a multi-target gateway, approval resubmission, outcome reconciliation by op_id.
