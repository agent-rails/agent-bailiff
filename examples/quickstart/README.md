# Governed tool access quickstart

A Docker Compose stack in which a scripted agent calls Gitea through agentgateway and gitea-mcp. The agent holds a task chain and its own signing key, never the Gitea token. Decide checks each `tools/call` against the task's scope, budget and replay ledger; the custodian injects the Gitea token only for an allowed call; allows, releases, revokes and most refusals go to a signed docket that an operator verifies.

Requirements: Docker with Compose v2 and `jq`. Run every command from this directory.

## What runs

| Service | uid | Role |
| --- | --- | --- |
| `gitea`, `gitea-mcp` | image default | Upstream Git service and its MCP server (`gitea-mcp-server:1.13.0`) |
| `gateway` | 10004 | agentgateway v1.7.0 with the decide and custodian processors, `failClosed` |
| `decide` | 10002 | Verifies the chain, checks scope and budget, writes the ledger |
| `custodian` | 10003 | Holds the encrypted Gitea token, releases it per allowed call |
| `docket` | 10001 | Signed append-only record sink |
| `reader` | 10005 | `agent-bailiff docket verify`, read-only, docket reader group |
| `control` | 10002 | Operator revoke, run on demand |
| `rule` | 10002 | `rule` profile: revokes a task on an out-of-scope refusal |
| `exporter` | 10008 | `trace` profile: verified docket records to OTLP spans |
| `jaeger` | 10009 | `trace` profile: trace UI on `127.0.0.1:16686` |
| `agent` | 10006 | Scripted agent on the internal `edge` network only |
| `*-init`, `bootstrap`, `task-issuer`, `agent-key` | per component | One-shot setup |

Every bailiff container is read-only, drops all capabilities and sets `no-new-privileges`. Processes talk over Unix sockets on named volumes; each server checks the peer uid. Only `gitea`, `gitea-mcp`, `bootstrap` and `gateway` have a network beyond `edge`. gitea-mcp also publishes port 18080 on `127.0.0.1` (`GITEA_MCP_PORT`), for the spike test; a call there bypasses the gateway and carries no token.

The task scope is `gitea.issues.list` and `gitea.issues.read` on `gitea/issues`, budget 20, one hour. Three routes exist (`routes.json`): `list_issues`, `issue_read`, and `get_file_contents`, which the task scope does not include.

## Run it

```console
$ docker compose up --build --detach --wait
$ docker compose logs --no-log-prefix bootstrap
gitea: created org quickstart
gitea: created repo quickstart/demo
gitea: created repo quickstart/payroll
gitea: created file quickstart/payroll/salaries.csv
gitea: created issue quickstart/demo 'Triage the open issues'
gitea: created user agent
gitea: created read access for agent on quickstart/demo
gitea: created read access for agent on quickstart/payroll
{
  "what this token can reach": {
    "scopes": [
      "read:issue",
      "read:repository"
    ],
    "repositories": [
      "quickstart/demo",
      "quickstart/payroll"
    ],
    "probes": {
      "read own user": "refused (403)",
      "read issues in quickstart/demo": "allowed",
      "read salaries.csv in quickstart/payroll": "allowed",
      "create an issue in quickstart/demo": "refused (403)",
      "create a repository": "refused (403)",
      "list users as admin": "refused (403)"
    }
  }
}
credential: created
gitea: created
```

The probes are real calls made with the stored token, so this is the token's measured reach, not its intended reach. Gitea repository-scoped fine-grained tokens are Enterprise-only, so the token reads both repositories, including `salaries.csv`.

```console
$ docker compose run --rm -T agent run | tee run.json
{
  "task_id": "task-7a8ba7e75eb39931",
  "checks": [
    {"scenario": "allowed call reaches gitea", "expected": "result", "observed": "result", "pass": true},
    {"scenario": "injected out-of-scope call refused", "expected": "refused: out_of_scope", "observed": "refused: out_of_scope", "pass": true},
    {"scenario": "replayed call refused", "expected": "refused: already_*", "observed": "refused: already_issued", "pass": true},
    {"scenario": "disclosed: list_issues on payroll stays allowed", "expected": "result", "observed": "result", "pass": true},
    {"scenario": "disclosed: unrouted write tool refused", "expected": "refused: unknown_tool", "observed": "refused: unknown_tool", "pass": true}
  ]
}
```

- Allowed: `list_issues` and `issue_read` on `quickstart/demo` return results.
- Injected: `get_file_contents` for `salaries.csv` is refused by decide. The token could read the file; the task scope cannot.
- Replayed: the exact headers and body of an allowed call are resent and refused.
- Disclosed: `list_issues` on `quickstart/payroll` is allowed, see [limits](#what-this-does-not-show).
- Disclosed: `issue_write` has no route and is refused before any scope check.

The operator reads the docket, then revokes the task from a verified record:

```console
$ TASK=$(jq -r .task_id run.json)
$ docker compose run --rm -T reader --task "$TASK"
LINE	AT	WRITER	SEQ	DECISION	TOOL	RESOURCE	REASON	NOTE
1	2026-11-20T08:37:52Z	decide.quickstart	1	allow	gitea.issues.list	gitea/issues	ok	-
2	2026-11-20T08:37:52Z	custodian.quickstart	1	release	gitea.issues.list	gitea/issues	ok	released, target outcome unknown
3	2026-11-20T08:37:52Z	decide.quickstart	2	allow	gitea.issues.read	gitea/issues	ok	-
4	2026-11-20T08:37:52Z	custodian.quickstart	2	release	gitea.issues.read	gitea/issues	ok	released, target outcome unknown
5	2026-11-20T08:37:52Z	decide.quickstart	3	refuse	gitea.contents.read	gitea/contents	out_of_scope	-
6	2026-11-20T08:37:52Z	decide.quickstart	4	refuse	gitea.issues.list	gitea/issues	already_issued	-
7	2026-11-20T08:37:52Z	decide.quickstart	5	allow	gitea.issues.list	gitea/issues	ok	-
8	2026-11-20T08:37:52Z	custodian.quickstart	3	release	gitea.issues.list	gitea/issues	ok	released, target outcome unknown
agent-bailiff docket verify: 8 records verified, 8 printed
$ docker compose run --rm -T reader --task "$TASK" --json \
    | jq -r 'select(.writer == "decide.quickstart" and .entry.decision == "allow") | .token' | tail -n 1 \
    | docker compose run --rm -T control revoke --config /var/lib/bailiff/control/config.json --actor operator --level task --record -
agent-bailiff docket verify: 8 records verified, 8 printed
{"action": "revoke", "entry_id": "559b397da81140499e7e1acaf5eebcfb", "handles": {"task": "task-7a8ba7e75eb39931", "tenant": "quickstart"}, "reason": "task", "trace_id": "87ec2205f838a0b1282af3fe66682273"}
$ docker compose run --rm -T agent after-revoke
{
  "task_id": "task-7a8ba7e75eb39931",
  "checks": [
    {"scenario": "call after revoke refused", "expected": "refused: chain_invalid", "observed": "refused: chain_invalid", "pass": true}
  ]
}
$ docker compose run --rm -T reader
...
9	2026-11-20T08:37:54Z	control.quickstart	1	revoke	-	-	task	-
agent-bailiff docket verify: 9 records verified, 9 printed
```

The `revoke` record is the operator's; the agent container mounts neither the control key nor the ledger. The refusal after the revoke is not in the docket: decide could not verify the chain, so it logs the refusal instead of recording it.

## Tracing and the revoke rule

Two optional profiles. `trace` runs Jaeger and `agent-bailiff docket export`; `rule` runs `rule.py`, a rule (not detection) that revokes a task when decide refuses one of its `gitea.contents.read` calls as `out_of_scope`.

```console
$ docker compose --profile trace --profile rule up --build --detach --wait
$ docker compose run --rm -T agent inject | tee inject.json
{
  "task_id": "task-a03d0f63b02ae5a0",
  "checks": [
    {"scenario": "allowed call reaches gitea", "expected": "result", "observed": "result", "pass": true},
    {"scenario": "injected out-of-scope call refused", "expected": "refused: out_of_scope", "observed": "refused: out_of_scope", "pass": true}
  ]
}
$ docker compose logs --no-log-prefix rule
{"entry_id": "ce93d73633cb4f31a90c34d5a69e7c50", "line": 5, "rule": "out_of_scope", "task": "task-a03d0f63b02ae5a0", "tenant": "quickstart"}
$ docker compose run --rm -T reader --task "$(jq -r .task_id inject.json)"
...
5	2026-11-20T10:16:21Z	decide.quickstart	3	refuse	gitea.contents.read	gitea/contents	out_of_scope	-
6	2026-11-20T10:16:21Z	rule.quickstart	1	revoke	-	-	task	-
agent-bailiff docket verify: 6 records verified, 6 printed
$ docker compose run --rm -T agent after-revoke
...
    {"scenario": "call after revoke refused", "expected": "refused: chain_invalid", "observed": "refused: chain_invalid", "pass": true}
```

`inject` stops after the refused call, so no later scenario races the revoke. Jaeger is at <http://127.0.0.1:16686> (`JAEGER_PORT`). Each docket writer is one service, for example `agent-bailiff-rule.quickstart`. The revoke span is a child of the `decide refuse` span in the same trace.

- The rule matches signed fields only: writer `decide.quickstart`, decision `refuse`, reason `out_of_scope`, and a configured tool. It sees only what decide recorded, and it decides nothing about intent.
- It follows the verified docket with its own checkpoint (`rule-data`), saved after each batch it handled. A restart does not revoke again. A crash before the checkpoint is saved repeats every revoke in that batch on restart: one extra `revoke` record per task, no second effect, because the ledger revoke is idempotent.
- The rule exits on any failed revoke (ledger busy, docket unreachable, or a revoke applied whose docket record was not acknowledged) and compose restarts it (`restart: on-failure`); the restart repeats the unsaved batch, which records any missing revoke. A record that fails every time shows as a restart loop in `docker compose ps`; while it loops, later refusals are not revoked.
- The revoke is asynchronous. Between decide's refusal and the revoke, at least one 0.5 s poll, the task's in-scope calls are still allowed. A refusal the docket did not record never reaches the rule.
- It signs as its own docket writer, `rule.quickstart`, so it never shares a sequence with the operator `control` command. It runs as decide's uid, like `control`; see H1.
- Spans come from verified docket records, never from the call path. The exporter reads the docket read-only, as uid 10008 in the docket reader group, on an internal network that reaches only Jaeger. A slow or stopped exporter delays spans; it never delays or refuses a call. The gateway itself is not traced.
- Export is not evidence. Jaeger is a view; the signed docket is the record, and `docket verify` checks it.
- The Jaeger UI has no login. Spans carry no secrets or arguments, but they show each record's principal, agent key and tenant/task handles to anyone who can reach `127.0.0.1` on this host.
- Jaeger marks each span with a "Negative duration detected" warning. Docket records are instants, so every span has zero duration; the warning is cosmetic.

Remove the stack and its volumes, including any profile services:

```console
$ rm -f run.json inject.json
$ docker compose --profile "*" down --volumes --remove-orphans
```

`tests/test_quickstart_stack.py`, `tests/test_quickstart.py`, `tests/test_quickstart_trace.py`, `tests/test_quickstart_canary.py` and `tests/test_quickstart_load.py` run the same stack under `AGENT_BAILIFF_TEST_QUICKSTART=1` (load also needs `AGENT_BAILIFF_TEST_QUICKSTART_LOAD=1`).

## What this shows

- Scoped claims: decide allows a call only when the tool and resource are in the task scope, the budget has room and the call was not seen before. The scope names a tool and a fixed resource; it does not read tool arguments.
- The agent never holds the Gitea token. The canary test reads the stored token and scans for it, its base64 form and the base64 of `token <value>` across every bailiff named volume (not Gitea's own `gitea-data` and `gitea-config`), the agent container's whole filesystem and environment, and the logs of every service. The only place the test permits a hit is Gitea's own logs. It passed on agent-warrant 0.3.0.
- Each release is bound to one decide allow, and the custodian limits releases to 60 per task per 60 seconds (`rate_limit`, `rate_window`).
- An operator revoke stops later calls on the task, and so does the rule's revoke after an out-of-scope refusal.
- Load baseline with tracing on (`benchmarks/quickstart-2026-11-20.json`, one Apple-silicon Docker Desktop host, `list_issues`, 20 calls per client): every call returned a result and none was refused with `docket_unavailable`. Backlog is the docket records not yet exported when the clients finished; catch-up is the time until the exporter's checkpoint reached the end of the docket.

  | Clients | Calls | Calls/s | p50 ms | p99 ms | Backlog | Catch-up s |
  | --- | --- | --- | --- | --- | --- | --- |
  | 1 | 20 | 26.3 | 36.6 | 58.4 | 0 | 0.3 |
  | 4 | 80 | 71.3 | 53.4 | 77.7 | 28 | 1.7 |
  | 16 | 320 | 86.1 | 197.5 | 281.9 | 69 | 1.7 |
  | 32 | 640 | 85.0 | 365.9 | 655.4 | 25 | 1.7 |

  Throughput flattens near 86 calls per second from 16 clients; latency then grows with queueing. The run without tracing (`benchmarks/quickstart-2026-11-19.json`) plateaued near 88 calls per second; one run each on one host cannot separate that gap from noise. This is one host and one tool. It is not a capacity claim.

## What this does not show

- No stop of an in-flight call. Once the custodian releases a token, the call proceeds; a revoke stops only later calls.
- No rollback or compensation of an upstream effect.
- No approval service. Decide can refuse with `needs_approval`; nothing here grants approval.
- Credential passthrough (H4): gitea-mcp receives the injected `Authorization` header and forwards it to Gitea. MCP guidance forbids a server accepting a token issued for another service; this stack trusts gitea-mcp as part of the upstream. A compromised gitea-mcp holds every released token for the length of a call.
- Token reach is wider than the task. The token reads `quickstart/payroll`, including `salaries.csv`. Decide refuses `get_file_contents` only because that tool is outside the task scope.
- `list_issues` on `quickstart/payroll` stays allowed: the resource is `gitea/issues`, not a repository, so the scope cannot tell `demo` from `payroll`.
- `issue_read` accepts any `method` value gitea-mcp offers. Decide does not inspect it; the read-only token scope is what keeps it read-only.
- gitea-mcp's `tools/list` exposes 48 tools, writes included, and the gateway returns all of them. Only the three routed tools can be called; the decide processor refuses any other name with `unknown_tool` before a scope check.
- The rule is not detection. It acts on one signed refusal pattern for one configured tool; misuse that decide allows, or refuses for another reason, does not trigger it. An agent probing the payroll repo with `list_issues` (`gitea.issues.list`) is refused but not revoked.
- The `bootstrap` container can read the Gitea admin password from the `gitea-admin` volume, to create the agent user and token. The running `custodian` container has the same uid (10003) but does not mount that volume.
- Evidence is scoped:
  - Not every refusal is recorded. An `unknown_tool` refusal, a refusal on an unverifiable chain (`chain_invalid`, including a call after a revoke) and any refusal past 16 of the same reason and tool per task per 60 s write no record. The first `out_of_scope` refusal of `gitea.contents.read` in a window is always recorded, so the rule sees it.
  - A `release` record means the custodian released the token, not that Gitea applied the call: `released, target outcome unknown`.
  - The docket owner (uid 10001) can truncate the docket. The reader verifies signatures and order of what is there, not that nothing was removed from the end.
- Limits of this setup:
  - H1: each service runs as its own uid, except `control` and `rule`, which run as decide's uid (10002) because they write the decide-owned ledger. Both mount `decide-data` read-only for decide's config, so they can also read decide's signing key; anyone who can run `control`, or who controls the `rule` container, can sign as decide. The isolation rests on uids and socket peer checks, not on separate hosts.
  - H2: state lives in named volumes only; a bind mount on macOS breaks socket ownership.
  - H3: containers share the host kernel. Isolation is as strong as separate host users, no stronger.
  - H5: the agent is a script. This shows what the gateway enforces, not how a model behaves under injection.
  - H6: an allowed tool used for harm inside its scope is not stopped (OWASP ASI02, LLM06).
  - H7: tracing is optional (`trace` profile), built after the fact from verified docket records, and off the call path. It is not evidence; the docket is. Span delivery is at least once: a restart after a failed export can send a span again.
  - H8: the task root comes from a local issuer key, not a human login. A later login flow uses device code; the password grant is forbidden (RFC 9700 section 2.4).
- The gateway config is `gateway.json`, not `gateway.yaml`: `check-config` reads JSON only, and `gateway-check` verifies that same file against the routes and bindings before the gateway starts.
