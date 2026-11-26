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

**Decision:** decide and the custodian are separate `ExtMcp` processors, decide first and the custodian last on the request phase. Decide returns only metadata (the clearance); the custodian returns the credential as a header mutation. D20 adds a response-phase processor.

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

**Decision:** the catalog offers `restart_deployment`: a forced server-side apply of the pod template's `restartedAt` and `bailiff.dev/restart-op` annotations. The second annotation carries the release op-id, distinguishes separate restarts issued in one second, and makes a retry of the same release a no-op. Admission confines the restart identity to those annotations and requires the marker to equal the request's single op-id extra. The drift check withdraws restart when the cluster's Deployment schema has fields the policy does not compare.

**Why:** Kubernetes has no narrow restart API. A rolling restart is a patch to the whole Deployment, which RBAC cannot narrow, and pod eviction cannot be scoped to one Deployment's pods. A policy that checks only part of the object let other pod template annotations through. Comparing every field, including other field managers' entries, does not, and pinning the schema withdraws restart from the effector on a version with new fields. The op-id marker also prevents two separately released operations in the same second from collapsing into one identical template update. Deleting pods, scoped by their owner, was also tested: it can be confined to one Deployment's pods, but takes them all down at once and ignores PodDisruptionBudgets, so a stolen token could cause outages where a restart only rolls. Restart was deferred until this was tested on a cluster.

## D16. One custodian key for docket entries and releases

**Decision:** the custodian signs docket entries and effector releases with one key.

**Why:** the record type is inside the signed payload and checked on verify, so a docket entry cannot pass as a release. Both keys would sit in the same process and directory, so a second key adds no isolation. A release-only key pays off once keys can live apart, with a KMS or OpenBao backend.

## D17. Release-verifying admission for catalog writes

**Decision:** Kubernetes admission requires a signed, 10-second custodian release for each catalog write. The webhook uses the same pure release-and-clearance verifier as the effector, pins both signing key sets, and compares the full admitted operation and old-to-new object change. The webhook is stateless: a captured, still-live release may be replayed and may undo a later write; suspension does not invalidate a release already issued. The verifier's skew limit applies only to the issue time: a release is accepted from that many seconds before its issue time until its expiry, on the verifier's clock. A stolen effector token alone cannot create a valid release. Rollback changes the webhook to Audit mode; deleting its registration is not a safe rollback.

**Why:** admission can verify signatures and the exact object change without requiring API-server flags or a state store in the write path. The remaining replay and suspension window is explicitly accepted to keep admission stateless; on the verifier's clock it lasts no longer than the release lifetime plus the skew limit, and a verifier clock behind the custodian's moves it later in real time by the lag without lengthening it.

## D18. Traces from the verified docket, off the call path

**Decision:** spans are built by a separate exporter that follows the docket, verifies each record against pinned writer keys and sends it over OTLP/HTTP. Decide, the custodian and the gateway emit no spans. Automated responses, such as a revoke rule, follow the same verified docket with their own checkpoint and act through `Control` as their own docket writer.

**Why:** emitting spans on the call path would add a dependency that can slow or fail calls, and would produce a second, unsigned record that could disagree with the docket. Building spans from verified records keeps one source of truth, and a stopped exporter changes no decision. A separate writer for automation avoids two processes sharing one writer sequence, which the docket client does not lock across processes.

## D19. Each call carries its own authority

**Decision:** a component that holds a credential uses it for an agent call only when the call carries authority for it. The agent presents a task root signed by the issuer and bound to the agent's key, and a leaf proof over the tool, resource, arguments and a nonce. The decide and custodian processors each map the call to a tool and resource through their own route table, fixed or built from the arguments, and each verifies the chain and proof (D2). Decide checks scope, budget and revocation before it issues a clearance; the custodian releases the credential for that one operation. A delegated link can narrow scope, budget and expiry, within the root's `max_depth` (agent-warrant `chain.py`). Components still hold standing authority: the custodian holds the upstream credential, and the effector calls Kubernetes with its own service account token, which it can use only to impersonate `bailiff:<tenant>:<identity>` (D14).

**Why:** this is the confused deputy problem described by Norm Hardy ([The Confused Deputy](https://doi.org/10.1145/54289.871709), ACM SIGOPS Operating Systems Review 22(4), 1988): a component that holds authority is tricked into using it for a requester who lacks it. A gateway that injects a credential into any call it forwards is such a deputy. Requiring authority bound to the request, as a capability, removes that ambient authority from the call path. Splitting decision from release (D1) means a compromised decide cannot release a credential on its own. Each allow, release and verified refusal is a signed docket entry (D6), and control can revoke a link, task, tenant or root named in one (D10).

The defence stops at what the call designates and what the docket sees. Arguments that do not build the route's resource reach the upstream unchecked, so a route with a coarse resource leaves the upstream able to act on objects the task did not name. The proof does not cover `_meta` or `traceparent`. The upstream MCP server holds the credential on every allowed call and is a deputy agent-bailiff does not constrain; what it does with the credential is not docketed. A task that never made an allowed call has no docket record to revoke from. An agent steered by injected instructions is itself a confused deputy for its user; the task scope bounds it but does not stop a call in scope. See [THREAT_MODEL.md](THREAT_MODEL.md).

## D20. Credential echo redaction at the custodian

**Decision:** the custodian serves a third processor, the redactor, on its own socket, gRPC server and workers, on `tools/call` responses only, `failClosed`, before the refusal guard. At each release the custodian keeps the released header value in memory, keyed by the hash of the verified clearance and bounded by `inflight_ttl` (180 s, at least the 120 s upstream timeout cap plus 30 s), `inflight_max` (4096 entries), `inflight_max_bytes` (8 MiB) and `inflight_per_tenant` (512). A full map refuses the release as `inflight_full`, before the upstream acts. The redactor takes the entry for the clearance in the gateway metadata, replaces each echo of the value in the result's JSON strings and keys with `[redacted by agent-bailiff]`, and records an `alert` entry with reason `credential_echo` and the release entry as `parent_entry`. It matches the raw header value, the token after an auth scheme, a Basic credential's decoded `user:pass` and password, their percent encodings and their base64 and base64url encodings at every byte offset, each only when it is at least 12 characters long. A shorter form is not matched; a credential with one is refused when stored and at release unless it carries an accepted exception (D22). Matching is literal and case-sensitive. A result with no matching entry, unreadable JSON or a redacted size over 4 MiB fails the call with a `response_*` reason; the client reports `OutcomeUnknown`. check-config requires the processor order decide, custodian, redactor, refusal guard, and `requestTimeout`, `backendRequestTimeout` and any `responseIdleTimeout` of at most 120 s.

**Why:** an upstream can return the credential it received, and the result goes to the agent. Only the custodian holds the plaintext, and the gateway's response hook is the one place the result passes before any caller sees it. Redacting keeps a result whose effect already happened; refusing it would hide that effect. The redactor runs before the guard so the guard sees the redacted result, and on its own workers so a large result does not delay releases. Redacting on the agent side would put the credential on the agent host. Redaction is best-effort suppression of the listed literal forms, not a containment boundary: a hex dump, re-wrapped base64, Unicode lookalikes and a value split across strings are not found. The control is short-lived, target-bound credentials; effector releases and short-lived upstream credentials remove the asset instead of the echo and stay preferred where a target supports them. JSON-RPC error text and event-stream side messages skip the response hook in agentgateway v1.7.0; see [THREAT_MODEL.md](THREAT_MODEL.md).

## D21. Scopes pair tools with resources

**Decision:** a task scope is `{"permissions": [{"tools": [...], "resources": [...], "max_cost_per_call": n}, ...]}` (agent-warrant 0.4.0). A call is allowed only when one permission covers both its tool and its resource and its cost is at most that permission's cap; otherwise decide refuses it as `out_of_scope` (no permission covers the pair) or `cost_over_call_cap`. A delegated link narrows per permission: each child permission must sit inside one parent permission, with a cap no higher. agent-warrant bounds a scope at 16 permissions and 64 entries, and agent-bailiff's 4,096 B task file is the lower limit in practice; `task issue` refuses a larger scope before signing. Decide and the custodian share one scope check, `scope_pattern.scope_refusal`. A v1 scope, with `tools`, `resources` and `max_cost_per_call` at the top level and no `permissions`, is read as one permission and accepted only on a root issued before `scope_v1_cutoff`, set in both decide's and the custodian's config; `init` writes 0, which accepts no v1 root. `task issue` issues v2 only. Decide logs each v1 root it accepts as `scope_v1_accepted`; the docket entry format is unchanged.

**Why:** a v1 scope is a cross product. A task meant to read `payroll` and write `todo` must list both tools and both resources, so it can also write `payroll`. Binding tables already limit which tool and resource pairs a deployment releases credentials for (`no_binding`), but not per task or per delegation. A list of permissions, each pairing tools with resources, is the shape of RFC 9396 `authorization_details`, which pairs `actions` with `locations` in each object ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)). Listing explicit tool and resource pairs grows as tools times resources: 4 tools on 20 repos is 80 entries, past the 64-entry bound. A relationship store such as OpenFGA needs an online lookup, which breaks offline chain verification and attenuation. Recording the scope version in the docket would change the entry codec, which old and new readers each refuse; v1 roots last at most 86,400 s, so docket entries before the cutoff plus that are the only v1 candidates. Raising the task file limit would put a larger root in a header on every call, through gateway header limits that were not measured. Keeping v1 readable until a cutoff lets roots issued before an upgrade finish their work; an issuer key can still mint v1 roots, with free pairing, until the cutoff. See [UPGRADE.md](UPGRADE.md) for the cutoff and rollout order and [THREAT_MODEL.md](THREAT_MODEL.md) for the residuals.

## D22. Credential checks at provisioning

**Decision:** `CredentialStore.put`, and so `put-credential`, refuses a credential the custodian could not release or echo redaction cannot cover: a value that is not printable ASCII without leading or trailing space or tab; a Basic token, the only scheme the redactor decodes, that is not base64 of a UTF-8 `user:password`; and a value with a form under 12 characters, the forms being the ones the redactor matches (D20), computed by the same code. `--accept-unredactable` stores such a credential with the exception `unredactable` in the row's `exception` column, which is also part of the AES-GCM associated data and the key-wrap context, and logs a warning naming the credential id and target. Storing it again without the flag clears the exception; the flag is refused for a credential that needs none. At release the custodian runs the same check: a credential that fails it without an exception is refused as `credential_unredactable` and the problem is logged; one with an exception is released with a warning. Opening a store adds the nullable column to a store that lacks it.

**Why:** the release-time warning reached neither the agent nor the person who stored the credential, and came only once the credential was in use. The operator storing it is the one who can replace it. Binding the exception into the encryption context means a write to the store file cannot add or remove an exception without the key encryption key, and a row an earlier `put-credential` rewrote under a recorded exception does not decrypt, instead of being released under a stale exception. Tokens of other schemes stay opaque: the redactor knows no structure in them, so a short field inside a longer token is neither matched nor checked. See [UPGRADE.md](UPGRADE.md) for stores written by an earlier release.

## Deferred

- Target-bound minting and an OpenBao or KMS key backend, with a release-only custodian key.
- Effector targets other than Kubernetes, and more than one effector instance.
- A `CheckResponse` hook for outcomes (reconciliation covers them). The response hook only redacts echoed credentials (D20).
- A standards check of the chain format against RFC 8693 and the OAuth Transaction Tokens draft before 1.0.
