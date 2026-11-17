# Decisions

Each entry records what was decided and why. Later entries supersede earlier ones where they differ.

## Credits

- The split between deciding a call and delivering the credential, and the credential proxy models, come from the IETF Internet-Draft [Credential Broker for Agents (CB4A)](https://datatracker.ietf.org/doc/draft-hartman-credential-broker-4-agents/), draft-hartman-credential-broker-4-agents-00 by Kenneth G. Hartman (2026-03-29; an individual draft, now expired).
- The use of agentgateway's processors for credential injection, and the focus on protecting the credential store, follow the agentgateway blog series:
  - [Credential Injection Patterns for AI Agents](https://agentgateway.dev/blog/2026-07-27-credential-injection-ai-agent-egress-cb4a/)
  - [Credential Injection Patterns for AI Agents: Part 2, Securing the Vault](https://agentgateway.dev/blog/2026-08-03-protecting-token-vault-kms-credential-injection/)
- agent-bailiff takes no code from either. It plugs into agentgateway only through its public `ExtMcp` processor interface.

## D1. A decision core and a separate credential custodian

**Decision:** decide holds no credentials and no credential encryption key; it holds only its own signing key, and issues a signed clearance. The custodian holds the credentials and re-verifies the authority itself before every decrypt.

**Why:** if the component that decides also holds the keys, one compromise exposes every credential. With the split, a compromised decide obtains only credentials covered by authority the caller can present, at a bounded rate.

## D2. The clearance is necessary, not sufficient

**Decision:** the custodian verifies the clearance and then re-verifies the chain, leaf proof and request digest from the call itself. It takes the credential binding and header name from its own table and refuses if the clearance disagrees.

**Why:** a clearance signed by a compromised decide must not be enough to release a credential.

## D3. Two chained agentgateway processors

**Decision:** decide and the custodian are separate `ExtMcp` processors, decide first and the custodian last. Decide returns only metadata (the clearance); the custodian returns the credential as a header mutation.

**Why:** a processor's header mutation is the only way to inject a header in agentgateway v1.7.0. Gateway metadata is access-logged and visible to CEL, so it must never carry a secret.

## D4. Unix sockets with peer uid checks

**Decision:** each processor listens on a Unix socket in a 0750 directory with the gateway's group, checks the peer uid on accept, and relays to its gRPC server on a private socket. check-config requires `unix:` targets.

**Why:** grpcio 1.85.1 does not expose the peer uid, and the custodian must accept only the gateway.

## D5. Per-component Ed25519 keys, pinned by key id

**Decision:** `agent-bailiff init` generates the decide, custodian and control keys, each under that component's uid; the docket's init writes a sink config with the pinned writer public keys. Verifiers pin peer public keys by key id in config they own. Records are Ed25519 over agent-warrant's canonical JSON, with `typ`, `v` and `kid` in the payload. Decoding is strict.

**Why:** no component can sign as another, and a verifier never takes keys from the party it verifies.

## D6. A separate docket sink

**Decision:** a sink process under its own uid verifies each record's signature, sequence and previous hash, appends with `O_APPEND`, fsyncs, then acknowledges. No acknowledgement means the caller refuses.

**Why:** the record of a decision must sit out of reach of the component that made it. It is tamper-evident, not tamper-proof; see [DOCKET.md](DOCKET.md).

## D7. Ledger shared read-only through a group

**Decision:** decide owns the agent-warrant ledger and writes it in shared-group mode (0640). The custodian opens it read-only (`TaskLedger.open_read_only`). The read-only open was added to agent-warrant, which owns the ledger file checks (released in agent-warrant 0.2.0).

**Why:** the custodian must see reservations and revocations without being able to write them. The fix belonged in the library that owns the file checks.

## D8. Exactly-once is not a core property

**Decision:** decide reserves and marks an op_id issued, and the custodian claims it once. An issued operation that expires without an outcome is moved to `outcome_unknown` by reconciliation. Reconciliation also reads expired issued operations from the ledger (`issued_expired`, at most 100 per pass), so operations left by a restart or another decide process are recorded with reason `untracked_issued_expired` in a new trace. For those, the docket entry is written before the ledger changes, so a failed append is retried on the next pass. Operations still being issued are skipped.

**Why:** the ledger stops an op_id from being issued twice, which gives at-most-once issuance. `ExtMcp` gives no exactly-once execution at the target; that needs a target that honours an idempotency key, so it is a per-target capability.

## D9. Credential tiers

**Decision:** each release records a tier:
- `target-bound`: narrowed or minted at the target;
- `gateway-bound`: long-lived, never given to the agent;
- `exposed`: would reach the agent.

`gateway-bound` is implemented, and for catalog tools so is `effector` (D13): no credential is released. check-config refuses stdio, SSE and OpenAPI upstreams for services with a credential binding, because they cannot carry the released header.

**Why:** most targets accept only long-lived keys, so a per-operation credential cannot be assumed. For `gateway-bound`, the upstream MCP server is trusted.

## D10. Control from the docket

**Decision:** control revokes or suspends from one signed docket line, runs as decide's uid against decide's config, and records its own entry in the source record's trace. Levels: `link`, `task`, `tenant`, `root`.

**Why:** an operator acts on what the trace shows, and the action joins the same trace. An `agent_key` level was removed because agent-warrant has no revocation of a key across chains, and the level revoked only one binding.

## D11. Suspension checked at decide and at the custodian

**Decision:** the suspension directory is `<ledger>.suspension`, shared like the ledger. Its path is derived from the ledger path. Decide checks it before issuing a clearance; the custodian checks it just before claiming a release. Its parent must be owned by root or decide, be in the ledger group, and not be group or other writable.

**Why:** with suspension checked only at decide, a clearance issued just before a suspension still released its credential until it expired.

## D12. Pinned dependencies

**Decision:** runtime dependencies are pinned exactly. CI installs only from a hash lock. The agentgateway proto and release binary are fetched at a pinned commit and version and checked by sha256, not vendored.

**Why:** supply-chain integrity, and no copied gateway code.

## D13. A Bailiff-owned effector for infrastructure operations

**Decision:** for Kubernetes, agent-bailiff runs its own MCP server, the effector, as the gateway's upstream for catalog tools. The custodian signs a single-use release instead of releasing a credential; the effector verifies it, rebuilds the request from an operation catalog and makes the call itself. One catalog produces the routes, tool schemas, RBAC and admission policies. Third-party MCP servers are used only for tools that need no credential.

**Why:** passing a reusable token to a separate MCP server lets that server, or anything that captures the token, act beyond the approved call. An `ExtMcp` hook cannot return a result, so the effector has to be the upstream.

## D14. Constrained impersonation, with generated admission and a drift check

**Decision:** the effector's service account uses Kubernetes constrained impersonation (beta in v1.36) of synthetic users `bailiff:<tenant>:<identity>`, with the op-id as a user extra. Admission policies are load-bearing: writes only through the catalog, only in the tenant's namespaces, replicas in range, one op-id. The effector refuses calls unless a check at most 120 s old found exactly the generated set, including no legacy `impersonate` grant anywhere.

**Why:** minted service-account tokens outlive a single call, and Kubernetes falls back to a legacy `impersonate` grant even when constrained grants exist, so the grants must be checked across all namespaces. Impersonated users carry `system:authenticated`, so writes are tied to the tenant at admission as well as by RBAC.

## D15. Restart through a full-comparison admission policy

**Decision:** the catalog offers `restart_deployment`: a forced server-side apply of only the pod template's `restartedAt` annotation, sent as a restart identity that admission confines to that change. The drift check withdraws restart when the cluster's Deployment schema has fields the policy does not compare.

**Why:** Kubernetes has no narrow restart API. A rolling restart is a patch to the whole Deployment, which RBAC cannot narrow, and pod eviction cannot be scoped to one Deployment's pods. A policy that checks only part of the object let other pod template annotations through. Comparing every field, including other field managers' entries, does not, and pinning the schema withdraws restart from the effector on a version with new fields. Deleting pods, scoped by their owner, was also tested: it can be confined to one Deployment's pods, but takes them all down at once and ignores PodDisruptionBudgets, so a stolen token could cause outages where a restart only rolls. Restart was deferred until this was tested on a cluster.

## Deferred

- Target-bound minting and an OpenBao or KMS key backend.
- Effector targets other than Kubernetes, and more than one effector instance.
- OpenTelemetry export of docket entries.
- A `CheckResponse` hook for outcomes (reconciliation covers them).
- A standards check of the chain format against RFC 8693 and the OAuth Transaction Tokens draft before 1.0.
