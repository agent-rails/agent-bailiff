# agentgateway adapter

Two ExtMcp processors for agentgateway v1.7.0 (`mcpGuardrails`): decide, then custodian, both on every method's request phase (`{"*": "request"}`), both `failClosed`.

## Method surface

- Decide passes `initialize`, `ping` and `tools/list`, decides `tools/call`, and refuses every other hooked method with `method_refused`.
- On every hooked method the custodian removes every agent header except `accept`, `content-type`, `mcp-protocol-version`, `traceparent` and `tracestate`, plus every binding-table credential header, from the upstream request; on a release it then sets the released credential header. Decide sees only the chain headers (`requestHeaders.allowed`); the custodian has no `requestHeaders` filter, so it sees every header the agent sent, and check-config refuses a custodian `requestHeaders` entry. The gateway still adds its own `host`, `content-length`, `accept-encoding`, `mcp-method` and `mcp-name`. Pseudo-headers such as `:authority` are not forwarded as headers.
- agentgateway v1.7.0 runs no request-phase hook for `resources/subscribe`, `resources/unsubscribe`, `completion/complete` or `tasks/*`. check-config requires `mcpAuthorization.rules` to be exactly `mcp.methodName == "tools/call" || mcp.methodName == "tools/list"`; with a rule present, agentgateway denies those methods before they reach an upstream. Under that rule alone, `prompts/list` and `resources/list` return empty lists; decide refuses both before that.
- check-config requires `requestHeaderModifier` to be exactly `{"remove": [...]}` naming `authorization`, `proxy-authorization`, `cookie`, `bailiff-release` and every binding-table credential header, and naming no `x-bailiff-*` header or `traceparent`. agentgateway applies it before the processors run, on every message, and it does not remove the header the custodian sets.
- Client notifications (`notifications/initialized`, `notifications/cancelled`, `notifications/progress`, `notifications/roots/list_changed` and custom notifications) run no processor and no `mcpAuthorization` check in v1.7.0. They reach every upstream carrying every agent header except those `requestHeaderModifier` removes: the `x-bailiff-*` headers and any other header the agent adds (for example `sudo` or `x-forwarded-user`), but no agent credential header. An upstream must not trust any request header on a notification.
- check-config requires `statefulMode` to be `stateless`. In stateful mode the GET event stream reaches the upstream with the agent's headers and no processor. In stateless mode agentgateway answers GET and DELETE with 405.
- Not probed: client responses to server-initiated requests.

## Refusal guard

- check-config requires exactly one processor that runs on responses: the refusal guard (`config_check.REFUSAL_GUARD`), an expression processor on `tools/call` responses. A processor with any method phase other than `request` or `off`, including `full`, counts as running on responses, so no later processor can rewrite an upstream answer into the refusal shape after the guard. When an upstream answer is a tool error whose only content item has `text` equal to a bailiff refusal reason, it rejects the answer, and agentgateway returns a JSON-RPC error (`-32001`) to the agent instead.
- Without it, an upstream that acted and then answered `needs_approval` or `out_of_scope` would be classified by the client as not executed, and preparing the call again would run it twice.
- agentgateway fails an expression evaluation error closed. A malformed upstream error answer therefore also becomes a JSON-RPC error.
- Gateway refusals are written by the request path and never pass through a response-phase processor, so they still reach the agent as tool errors.

## Clearance visibility

- Decide returns the signed clearance in the `metadata` bag of its `CheckRequest` result. agentgateway records that bag in its access log and exposes it to backend CEL as `mcpGuardrails.clearance`.
- The clearance carries no secret. A copied clearance does not release a credential on its own: the custodian re-verifies the chain, leaf proof and request digest from the call itself, checks the ledger reservation, and claims the op_id once.

## Processor sockets

- Each processor listens on a unix socket in a 0750 directory with the gateway's group, socket mode 0660.
- The processor accepts each connection itself, refuses any peer whose uid is not the configured gateway uid, and relays accepted connections to its gRPC server on a socket in a 0700 directory.
- The relay holds at most 64 connections and has no idle timeout. A connection over the cap is closed.
- A refused, closed or unreachable processor fails the call closed, because check-config requires `failClosed`.
- Each gRPC server runs 8 workers and admits at most 256 concurrent calls; a call past that is refused with `RESOURCE_EXHAUSTED`, which fails it closed. The limit is fixed. At the quickstart's measured rate (about 115 calls a second at 32 clients), 256 queued calls drain well inside the gateway's 10-second processor timeout.
- agentgateway abandons a processor call after 10 seconds. grpcio drops a call the gateway abandoned while it was still queued, so the processor never sees it and it never reserves a ledger slot or claims an op_id. A call already inside the processor runs to completion; its result is discarded and its op_id stays claimed.

## check-config

- `python -m agent_bailiff.adapters.agentgateway check-config` validates a JSON gateway config at startup only.
- agentgateway watches its config file and reloads it on change, so a later edit is not checked. The config file must be writable only by its owner, and that owner must be neither the gateway's user nor an agent's user.
- The mcp target `host` of a gateway-bound service must be `https`, or `http` only to `127.0.0.1`, `localhost`, `[::1]` or a single-label service name. A host without a scheme, alone or with `port` and `path`, is `http`, as agentgateway v1.7.0 treats it. A host with user info, a query, a fragment, whitespace, a control character, a backslash or an invalid port is refused. A host without a scheme must be `host` or `host:port`, with `[::1]` bracketed. In the split form, with `port` or `path`, `host` must not carry a scheme: agentgateway v1.7.0 treats a split-form host as an authority with TLS off and rejects a scheme, so only the `https://` URI form gives TLS to a remote upstream. The supported deployment is single host: gateway, bailiff and upstreams on one Docker host or machine. A plain-http single-label name is trusted to resolve inside that host's container network, so DNS on that network is in the trusted computing base. The check validates name syntax, not where a name resolves. Any hop that leaves the host must use `https://`; the check refuses dotted names and IP literals over `http`. Channel authentication (TLS on every non-loopback hop) is required before multi-host support and is tracked in #86.
- A target's `backendTLS` may hold only a non-empty string `root`. `insecure`, `insecureHost`, `hostname` and every other key are refused.

## tools/call params

- Params may hold only `name`, `arguments` and `_meta`. Any other key is refused as `malformed_request`.
- `_meta` may hold only `progressToken` (string or integer), `io.modelcontextprotocol/protocolVersion` (string), `io.modelcontextprotocol/clientInfo` (object) and `io.modelcontextprotocol/clientCapabilities` (object). Any other key or type is refused as `malformed_request`.
- These `_meta` values are not part of the request digest, the leaf proof or the clearance; they reach the upstream unbound. Binding them needs a change to the agent-side proof.

## Proof headers on notifications

- Client notifications fan out to every upstream and carry the agent's `x-bailiff-*` headers, including the leaf proof for whatever request the agent is about to make.
- A leaf proof binds one request: tool id, resource, arguments and nonce. Its op_id is claimed once, and the route table maps each tool id and resource to one upstream. The worst case is therefore an upstream that submits the operation first: it runs once, at the upstream routed for it, with the agent's arguments, and the agent's own call is refused (`already_issued` from decide). The credential is not released to the upstream that replayed the proof. This reasoning has not been executed as a test.
- Agent clients should send the `x-bailiff-*` headers only on `tools/call`.

## Batches

- agentgateway v1.7.0 rejects a JSON-RPC batch with HTTP 400 ("fail to deserialize request body: unrecognized JSON-RPC message") before any processor or upstream call.
