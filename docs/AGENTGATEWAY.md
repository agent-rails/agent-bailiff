# agentgateway adapter

Two ExtMcp processors for agentgateway v1.7.0 (`mcpGuardrails`): decide, then custodian, both on every method's request phase (`{"*": "request"}`), both `failClosed`.

## Method surface

- Decide passes `initialize`, `ping` and `tools/list`, decides `tools/call`, and refuses every other hooked method with `method_refused`.
- On every hooked method the custodian removes `authorization`, `proxy-authorization`, `cookie`, the `x-bailiff-*` headers and every binding-table credential header from the upstream request; on a release it then sets the released credential header.
- agentgateway v1.7.0 runs no request-phase hook for `resources/subscribe`, `resources/unsubscribe`, `completion/complete` or `tasks/*`. check-config requires `mcpAuthorization.rules` to be exactly `mcp.methodName == "tools/call" || mcp.methodName == "tools/list"`; with a rule present, agentgateway denies those methods before they reach an upstream. Under that rule alone, `prompts/list` and `resources/list` return empty lists; decide refuses both before that.
- check-config requires `requestHeaderModifier` to be exactly `{"remove": [...]}` naming `authorization`, `proxy-authorization`, `cookie` and every binding-table credential header, and naming no `x-bailiff-*` header or `traceparent`. agentgateway applies it before the processors run, on every message, and it does not remove the header the custodian sets.
- Client notifications (`notifications/initialized`, `notifications/cancelled`, `notifications/progress`, `notifications/roots/list_changed` and custom notifications) run no processor and no `mcpAuthorization` check in v1.7.0. They reach every upstream carrying the `x-bailiff-*` headers and no agent credential header.
- Not probed: client responses to server-initiated requests, the SSE GET stream, session DELETE, and stateful mode.

## Clearance visibility

- Decide returns the signed clearance in the `metadata` bag of its `CheckRequest` result. agentgateway records that bag in its access log and exposes it to backend CEL as `mcpGuardrails.clearance`.
- The clearance carries no secret. A copied clearance does not release a credential on its own: the custodian re-verifies the chain, leaf proof and request digest from the call itself, checks the ledger reservation, and claims the op_id once.

## Processor sockets

- Each processor listens on a unix socket in a 0750 directory with the gateway's group, socket mode 0660.
- The processor accepts each connection itself, refuses any peer whose uid is not the configured gateway uid, and relays accepted connections to its gRPC server on a socket in a 0700 directory.
- The relay holds at most 64 connections and has no idle timeout. A connection over the cap is closed.
- A refused, closed or unreachable processor fails the call closed, because check-config requires `failClosed`.

## check-config

- `python -m agent_bailiff.adapters.agentgateway check-config` validates a JSON gateway config at startup only.
- agentgateway watches its config file and reloads it on change, so a later edit is not checked. The config file must be writable only by its owner, and that owner must be neither the gateway's user nor an agent's user.

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
