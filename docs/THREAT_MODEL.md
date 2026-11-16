# Threat model

Scope: agent-bailiff with the agentgateway v1.7.0 adapter, each component under its own OS user on one host, as described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Assets

- Credentials in the custodian's store, and the key encryption key.
- Each component's signing key.
- The ledger: reservations, revocations and issued state.
- The suspension switch.
- The docket: the record of decisions, releases and control actions.

## Attackers

1. **A hijacked agent**, for example through prompt injection. It holds a valid task root, links and agent key, and can send any MCP traffic the gateway accepts.
2. **A compromised decide.** It holds decide's key and the ledger writer, but no credentials.
3. **A compromised upstream MCP server.** It receives every request routed to it, including the credential header.
4. **A local user** who is not root and is not one of the component users, including a member of the ledger group who is not decide.
5. **An operator error**, such as a misconfigured gateway, a permissive directory mode or a wrong config path.

Root on the host is trusted. It can read every key and every file.

## Trust boundaries

- Agent to gateway: the MCP connection. The agent is untrusted.
- Gateway to processors: Unix sockets in a 0750 directory with the gateway's group. Each processor checks the peer uid on accept.
- Decide to custodian: the clearance, signed by decide and verified with the custodian's pinned decide keys. It is necessary but not sufficient.
- Components to docket: a Unix socket; the sink checks the peer uid and each writer's pinned key, sequence and previous hash.
- Decide to custodian through the ledger and suspension directory: decide and control, both as decide's uid, write; the custodian reads through the ledger group.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| A hijacked agent calls a tool or resource outside its task | Decide verifies the chain and leaf proof, and refuses out-of-scope calls and unknown costs. The custodian re-verifies the same proof itself. |
| A hijacked agent replays a call | The leaf proof binds tool, resource, arguments and nonce. The op_id is reserved in decide's ledger, and claimed once in the custodian's claims database. |
| A hijacked agent sends its own credential headers, or tampers with `x-bailiff-*` headers | The custodian removes `authorization`, `proxy-authorization`, `cookie`, the four chain headers (`x-bailiff-task-root`, `x-bailiff-links`, `x-bailiff-leaf-proof`, `x-bailiff-nonce`) and every bound credential header from the upstream request. check-config requires a gateway header modifier that removes `authorization`, `proxy-authorization`, `cookie` and every bound credential header, and refuses one that removes any `x-bailiff-` header or `traceparent`. |
| A compromised decide asks the custodian for any credential | The custodian takes the binding from its own table, re-verifies the chain, leaf proof and request digest from the call, checks the reservation, claims each op_id once, and rate-limits per task. It releases only credentials covered by authority the caller can present. |
| A copied clearance is reused | It is bound to one op_id, audience, request digest and expiry, and the op_id can be claimed once. A clearance in the gateway access log releases nothing on its own. |
| Bulk decryption of the credential store | Data keys are wrapped per credential, with tenant, credential id and target as associated data. Decryption happens only in the custodian, after verification. |
| An operator stops a task, tenant or agent, and a call still goes through | Control revokes through the ledger, which decide and the custodian both read. Suspension is checked by decide before it issues a clearance, and by the custodian just before it claims a release. |
| Suspension state is swapped or faked | The suspension directory's parent must be owned by root or decide, be in the ledger group, and not be group or other writable. The directory is opened relative to that parent without following symlinks. Anything unverifiable counts as suspended. |
| A forged or altered docket record | Records are signed with pinned keys and chained per writer. The sink refuses a bad signature, unknown key id, wrong sequence or broken chain. |
| A forged or tampered record is used for control | Control verifies the signature and pinned key id, and refuses its own writer's records. It also refuses a record whose tenant handle does not match its tenant. |
| A gateway config that fails open | check-config refuses `failOpen`, a missing header allowlist, the wrong processor order, a non-Unix processor target and an unsafe method surface. |
| A local user connects to a processor or the sink | Peer uid checks on every socket; processor sockets sit in a 0750 directory with the gateway's group. |
| Key or database file substitution | Key files and databases are opened with owner, mode, link and parent checks. The custodian re-checks its databases before each use. |
| Canary credential use | A canary release is refused, denies the task in the claims database and writes an alert entry. Control can then revoke the task. |

## Residual risks

These are known and accepted for the current release:

- **The upstream MCP server is trusted.** It receives the credential in the request. For `gateway-bound` credentials, the operation binding holds only at this layer.
- **Root is trusted.** Root can read keys, the credential store and the docket.
- **The docket is tamper-evident, not tamper-proof.** The sink uid or root can truncate or delete it. Signatures do not detect removed records; see [DOCKET.md](DOCKET.md) for writer-side rollback detection and its limits.
- **A credential that has already been released lives until the upstream stops using it, and a completed effect is not undone.** A release that has passed the custodian's suspension check completes.
- **A compromised decide controls the ledger.** As the ledger owner it can drop revocations or alter reservations. The custodian's reservation check catches bugs, not a hostile decide. Its independent checks are the chain, leaf proof, binding table, claims and rate limit.
- **Control trusts pinned signers for bindings.** It revokes the root and link bindings named in a record signed by a pinned decide or custodian key, so a compromised signer can name any binding.
- **There is no agent-key revocation across chains.**
- **An old record can be replayed to suspend again after a resume.** Control runs as decide's uid, and a replay only makes things more restrictive.
- **`--actor` is recorded as given.** It is not tied to the caller's OS identity.
- **The per-task rate limit is in memory.** A custodian restart resets it. It tracks at most 65536 live tasks; while that many are live, a release for a new task is refused as `rate_limited`, and checking it scans the tracked tasks.
- **The revocation tables only grow.** There is no retention.
- **Directory checks read mode bits, owner and group.** They do not inspect ACLs, and they check only the immediate parent directory. The ledger's parent check, in agent-warrant, does not check the parent's owner.
- **check-config runs at startup only.** agentgateway reloads its config on change, so the config file must be writable only by a user that is neither the gateway's nor an agent's.
- **agentgateway v1.7.0 runs no processor for client notifications.** They reach upstreams with the `x-bailiff-*` headers. See [AGENTGATEWAY.md](AGENTGATEWAY.md).
- **`_meta` values in `tools/call` are not bound to the proof.**
- **Other `x-bailiff-` headers reach the upstream.** The processors see only the allowlisted headers, so the custodian removes only the four chain headers. An agent can send other `x-bailiff-` headers; they carry no authority.
- **Reconciliation is in memory.** While decide runs, an issued operation that expires without an outcome is recorded as `outcome_unknown`. After a decide restart, operations issued before it stay `issued` in the ledger with no docket entry. The custodian still refuses their expired clearances.
- **Decide and custodian lifetimes are not checked against each other.** If decide's `max_proof_age` is above the custodian's `max_clearance_lifetime`, decide records an allow that the custodian then refuses as `clearance_invalid`. `init` writes equal values.
- **Unrecorded refusals.** Custodian refusals before verification are logged, not docketed. Control applies its action before recording it and reports an unacknowledged entry as unrecorded.
- **The docket sink writes and fsyncs on its event loop.** A slow disk delays every writer, and writers then refuse calls when their append times out.
- **Processor relays have no idle timeout.** Idle connections can hold the 64-connection cap; see [AGENTGATEWAY.md](AGENTGATEWAY.md).
- **Python cannot reliably zero secrets in memory.**
- **On macOS, `fsync` does not flush the drive cache.**
