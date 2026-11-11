# agentgateway adapter

Two ExtMcp processors for agentgateway v1.7.0 (`mcpGuardrails`): decide, then custodian, both on `tools/call` request phase, both `failClosed`.

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
