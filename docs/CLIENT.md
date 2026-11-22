# Agent-side client (contract v1)

`agent_bailiff.client.BailiffClient` signs and sends an agent's `tools/call` through agentgateway. It holds the agent's key and chain, never a service credential. It imports neither the gateway adapter, gRPC nor protobuf.

```python
from agent_bailiff.client import BailiffClient, Holder

client = BailiffClient(url, Holder(task_root, links, agent_key, decider_id), routes)
outcome = client.call("gitea", "get_me", {})
```

## Request contract

- Routes are the same `agent_bailiff.routes.ToolRoutes` the gateway adapter reads. `prepare(service, name, arguments)` maps the call to its scope `tool` and `resource`, and raises `ValueError` before signing for an unrouted tool, or for arguments the route refuses: outside the schema of a catalog route, or schema arguments of a route document that are missing or not identifiers.
- A route document (`ToolRoutes.from_document`) lists routes with exactly `service`, `name`, `tool` and `resource`, and optionally `schema`: a list of `{"name": ..., "kind": "identifier"}` items naming each `{placeholder}` in `resource` once; each placeholder must be a whole `/`-separated segment. An identifier is `[A-Za-z0-9_][A-Za-z0-9._-]{0,99}`, so it cannot be `.`, `..` or contain `/`, and the filled resource must be a valid scope entry (at most 128 characters). The client raises `ValueError` for a call that fails these checks; the gateway refuses it with `malformed_request`. Only schema arguments are checked; any other argument passes to the upstream unchecked. A document route cannot route a `k8s.*` tool; those come from the effector catalog, whose routes refuse any argument outside their schema.

  ```json
  {"service": "gitea", "name": "list_issues", "tool": "gitea.issues.list",
   "resource": "gitea/repos/{owner}/{repo}/issues",
   "schema": [{"name": "owner", "kind": "identifier"}, {"name": "repo", "kind": "identifier"}]}
  ```

- Scope resource grants must be exact or end at `/*`. Decide refuses a call whose leaf scope holds any other pattern, such as `gitea/repos/acme-*`, with `unbounded_scope`, the custodian refuses such a leaf on release, and refuses to load a binding with one. `/*` covers every resource below that segment; resources compare byte for byte, so `Demo` is not `demo`.
- Nonce: 16 random bytes, hex. Each `prepare` makes a new nonce, so each prepared call is a new operation.
- Leaf proof: signed by the holder key over the last record in the chain, with `audience` set to the decider id, `iat` from the client clock, and `request_digest` = `request_digest(tool, resource, arguments, nonce)` (`agent_bailiff/decide/identity.py`).
- Headers: `x-bailiff-task-root`, `x-bailiff-leaf-proof`, `x-bailiff-nonce`, `traceparent`, and `x-bailiff-links` (comma-joined) when the holder is a delegate.
- `traceparent`: W3C version `00`, generated with random non-zero trace and parent ids, or supplied by the caller and validated. The gateway adapter treats an all-zero id as absent.
- Body: one JSON-RPC `tools/call` request, compact JSON with sorted keys.
- `Holder` rejects a key that is not the subject of the last record in the chain.
- Golden vectors: `tests/vectors/client-v1.json` (root holder and delegated holder). `tests/test_client.py` checks that the client produces them and that the gateway adapter reads them back to the same tool, resource, arguments, links, trace id and request digest.

## Delegating to a sub-agent

```python
links = client.delegate(sub_agent_key.public_key(), scope=scope, budget=10, ttl=600)
sub_agent = BailiffClient(url, Holder(task_root, links, sub_agent_key, decider_id), routes)
```

- `delegate` signs the next chain link with the holder key, at the client clock, naming the sub-agent's public key as subject. It returns the holder's links plus the new one. `Holder.delegate(..., now=)` does the same without a client.
- The sub-agent's private key never reaches the parent: only its public key goes in. Pass the returned links to the sub-agent; they are public, signed records.
- `delegate` refuses, with `ValueError`, a scope that does not narrow the holder's, a budget above the holder's, a depth past the root's `max_depth`, a non-positive `ttl`, or a holder record not valid now. Expiry is clamped to the holder's. These are local link-construction checks (`agent_warrant.chain.delegate`), the same rules decide applies to scope, budget, depth and expiry. Decide independently verifies the whole chain on every call: root trust, every link's signature, the possession proof and revocation.
- Calls from the sub-agent are checked against the narrowed link. A call outside it is refused (`out_of_scope`), and its docket entries carry the sub-agent key and the `link` handle. Pass a signed docket record of a verified sub-agent call to `control revoke --level link` to revoke that link; the holder's own calls go on. A call refused as `chain_invalid` has no verified sub-agent, so its record carries no link handle.
- `issued_at` comes from the client clock. Decide refuses a link issued more than 5 s (`CLOCK_SKEW_SECONDS`) ahead of its own clock, so keep the client clock within that of decide's.
- Every link travels in one request header, about 660 characters per link with a small scope; a larger scope makes each link larger. Depth up to the root's `max_depth` was not tested through the gateway, and proxy header limits on the path were not checked.

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
| `Refused(reason)` | The gateway refused the call (`REFUSAL_REASONS`) and did not forward it upstream. |
| `NeedsApproval()` | The gateway refused the call with `needs_approval`: the policy requires a human. The call was not forwarded upstream. |
| `OutcomeUnknown(detail)` | Timeout, dropped connection, oversized or non-UTF-8 response, response id not matching the request, non-200 status, JSON-RPC error (including an upstream answer the refusal guard rejected) or expired session. The credential may have been released and the target may have acted. |

- `Refused` and `NeedsApproval` carry `action` and `retryable`, fixed per reason by `refusal_action`, so an agent knows what to do next without parsing the reason:
  - `retry_later` (`retryable` true): `docket_unavailable`, `ledger_unavailable`, `internal_error`. A component was unavailable and the gateway did not forward the call; a later call may pass. Budget for the refused attempt may already be spent: decide refuses with `docket_unavailable` after it reserved and issued the operation, and its `ledger_unavailable` does not say how far the reservation got. A retry is a new operation with a new nonce and spends budget again, so bound retries and back off.
  - `ask_user`: `needs_approval`, `suspended`. A human has to act before the task can go on. `suspended` means an operator suspended the gateway; the user may not be able to resume it, so the agent stops and does not retry until it is resumed.
  - `stop`: every other reason, `unbounded_scope` included: the task's scope must be reissued. The gateway did not forward the call. The reason does not say whether a later call could pass: `already_*` means this nonce was already used, and `release_refused` covers every custodian refusal, a custodian ledger outage included, after decide issued the operation. The agent does not retry it or reach the same effect another way, and reports to the user.
  The action comes from the reason alone. It does not say which scope, binding or policy rule refused the call.
- An effector behind the gateway answers with a `Result` whose `is_error` is true. If its only content is one text item starting with `effector_`, `Result.effector_error` gives that reason and `effector_error_action(reason)` the action. These reasons are disjoint from `REFUSAL_REASONS` and pass the refusal guard. The effector may have claimed the release, so a retry is a new call that spends budget again:
  - `retry_later`: `effector_busy`, `effector_docket_unavailable`, `effector_rbac_unverified`, `effector_restart_unverified`, `effector_webhook_unverified`, `effector_kubernetes_429`. Kubernetes did not act on the call.
  - `ask_user`: `effector_suspended`.
  - `stop`: every other reason, including one the client does not know. `effector_outcome_unknown` means Kubernetes may have acted; treat it like `OutcomeUnknown`.
- A gateway refusal is an HTTP 200 tool error whose only content is one text item equal to the reason. An upstream cannot deliver that shape to the client through a gateway running a checked config: check-config requires a response-phase refusal guard on `tools/call` that turns any upstream tool error whose only content is a bailiff reason into a JSON-RPC error, which the client classifies as `OutcomeUnknown`. Gateway refusals never reach a response-phase processor.
- The classification relies on the gateway running a config that passed check-config. A client pointed at a gateway without the guard cannot tell an upstream's text from a refusal.
- A non-200 status after the gateway forwarded the call, such as an upstream rejecting the released credential, is `OutcomeUnknown`.
- After `OutcomeUnknown`, do not assume the call failed. Preparing the call again is a new operation with a new nonce and spends budget again.
- `GatewayError` is raised only by session setup and `tools/list`.

## Limits

- Responses are capped at 4 MiB. `timeout` (default 30 s) bounds each socket operation while connecting, sending, and reading headers or a JSON body. An event-stream response must deliver its result within `timeout` after its headers arrive.
- Event streams: empty-data events (such as a priming event) and messages for other ids are skipped. A stream that ends before the result is `OutcomeUnknown`; the client does not resume with `GET` and `Last-Event-ID`.
- A `PreparedCall` is sent at most once. Its `headers` and `body` stay readable, which is how the quickstart's replay scenario captures and resends a call.
- Not in v1: event-stream resumption, tool-name prefixes from a multi-target gateway, approval resubmission, outcome reconciliation by op_id.
