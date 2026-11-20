# Governed tool access quickstart

A Docker Compose stack in which a scripted agent calls Gitea through agentgateway and gitea-mcp. The agent holds a task chain and its own signing key, never the Gitea token. Decide checks each `tools/call` against the task's scope, budget and replay ledger; the custodian injects the Gitea token only for an allowed call; every allow, release, refuse and revoke goes to a signed docket that an operator verifies.

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
    {"scenario": "call after operator revoke refused", "expected": "refused: chain_invalid", "observed": "refused: chain_invalid", "pass": true}
  ]
}
$ docker compose run --rm -T reader
...
9	2026-11-20T08:37:54Z	control.quickstart	1	revoke	-	-	task	-
10	2026-11-20T08:37:55Z	decide.quickstart	6	refuse	gitea.issues.list	gitea/issues	chain_invalid	-
agent-bailiff docket verify: 10 records verified, 10 printed
```

The `revoke` record is the operator's; the agent container mounts neither the control key nor the ledger. The refusal after the revoke (line 10) carries no task handle, because decide could not verify the chain, so `--task` filters it out.

Remove the stack and its volumes:

```console
$ rm run.json
$ docker compose down --volumes --remove-orphans
```

`tests/test_quickstart_stack.py`, `tests/test_quickstart_canary.py` and `tests/test_quickstart_load.py` run the same stack under `AGENT_BAILIFF_TEST_QUICKSTART=1` (load also needs `AGENT_BAILIFF_TEST_QUICKSTART_LOAD=1`).

## What this shows

- Scoped claims: decide allows a call only when the tool and resource are in the task scope, the budget has room and the call was not seen before. The scope names a tool and a fixed resource; it does not read tool arguments.
- The agent never holds the Gitea token. The canary test reads the stored token and scans for it, its base64 form and the base64 of `token <value>` across every named volume, the agent container's whole filesystem and environment, and the logs of every service. The only place the test permits a hit is Gitea's own logs. It passed on agent-warrant 0.3.0.
- Each release is bound to one decide allow, and the custodian limits releases to 60 per task per 60 seconds (`rate_limit`, `rate_window`).
- An operator revoke stops later calls on the task.
- Load baseline (`benchmarks/quickstart-2026-11-19.json`, one Apple-silicon Docker Desktop host, `list_issues`, 20 calls per client): every call returned a result and none was refused with `docket_unavailable`.

  | Clients | Calls | Calls/s | p50 ms | p99 ms |
  | --- | --- | --- | --- | --- |
  | 1 | 20 | 29.0 | 33.4 | 48.5 |
  | 4 | 80 | 68.0 | 56.1 | 77.9 |
  | 16 | 320 | 88.5 | 182.8 | 284.6 |
  | 32 | 640 | 88.3 | 358.5 | 604.5 |

  Throughput flattens near 88 calls per second from 16 clients; latency then grows with queueing. This is one host and one tool. It is not a capacity claim.

## What this does not show

- No stop of an in-flight call. Once the custodian releases a token, the call proceeds; a revoke stops only later calls.
- No rollback or compensation of an upstream effect.
- No approval service. Decide can refuse with `needs_approval`; nothing here grants approval.
- Credential passthrough (H4): gitea-mcp receives the injected `Authorization` header and forwards it to Gitea. MCP guidance forbids a server accepting a token issued for another service; this stack trusts gitea-mcp as part of the upstream. A compromised gitea-mcp holds every released token for the length of a call.
- Token reach is wider than the task. The token reads `quickstart/payroll`, including `salaries.csv`. Decide refuses `get_file_contents` only because that tool is outside the task scope.
- `list_issues` on `quickstart/payroll` stays allowed: the resource is `gitea/issues`, not a repository, so the scope cannot tell `demo` from `payroll`.
- `issue_read` accepts any `method` value gitea-mcp offers. Decide does not inspect it; the read-only token scope is what keeps it read-only.
- gitea-mcp's `tools/list` exposes 48 tools, writes included, and the gateway returns all of them. Only the three routed tools can be called; the decide processor refuses any other name with `unknown_tool` before a scope check.
- The `bootstrap` container can read the Gitea admin password from the `gitea-admin` volume, to create the agent user and token. The running `custodian` container has the same uid (10003) but does not mount that volume.
- Evidence is scoped:
  - Not every refusal is recorded. An `unknown_tool` refusal writes no record, and a refusal on an unverifiable chain has no task handle.
  - A `release` record means the custodian released the token, not that Gitea applied the call: `released, target outcome unknown`.
  - The docket owner (uid 10001) can truncate the docket. The reader verifies signatures and order of what is there, not that nothing was removed from the end.
- Limits of this setup:
  - H1: each service runs as its own uid. The isolation rests on uids and socket peer checks, not on separate hosts.
  - H2: state lives in named volumes only; a bind mount on macOS breaks socket ownership.
  - H3: containers share the host kernel. Isolation is as strong as separate host users, no stronger.
  - H5: the agent is a script. This shows what the gateway enforces, not how a model behaves under injection.
  - H6: an allowed tool used for harm inside its scope is not stopped (OWASP ASI02, LLM06).
  - H7: there is no tracing in this stack. When tracing is added it stays off the call path and is not evidence; the docket is.
  - H8: the task root comes from a local issuer key, not a human login. A later login flow uses device code; the password grant is forbidden (RFC 9700 section 2.4).
- The gateway config is `gateway.json`, not `gateway.yaml`: `check-config` reads JSON only, and `gateway-check` verifies that same file against the routes and bindings before the gateway starts.
