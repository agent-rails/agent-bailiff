# Governed tool access quickstart

A Docker Compose stack in which a scripted agent calls Gitea through agentgateway and gitea-mcp. The agent holds a task chain and its own signing key, never the Gitea token. Decide checks each `tools/call` against the task's scope, budget and replay ledger; the custodian injects the Gitea token only for an allowed call; allows, releases, revokes and most refusals go to a signed docket that an operator verifies.

Requirements: Docker Engine 28.3.3 or later with Compose v2.20 or later, and `jq`. Older engines let other hosts on the network reach ports published on `127.0.0.1` (moby/moby#49325, CVE-2025-54388). Run every command from this directory.

The upstream is chosen by `UPSTREAM`, which names a config in `upstreams/`, or in the directory `BAILIFF_UPSTREAMS` names (see [`upstreams/schema.md`](upstreams/schema.md)). Plain `docker compose up` runs `stub`: `stub-upstream`, an in-repo Streamable HTTP MCP server with in-memory notes, and no Gitea. The stub stack stores no credential, so every call fails until the operator stores one; the stub accepts any value:

```console
$ head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' \
    | docker compose run --rm --no-deps -T custodian -m agent_bailiff.cli custodian put-credential \
      --config /var/lib/bailiff/custodian/config.json --tenant quickstart --credential-id stub-token --target stub
```

The walkthrough below uses Gitea, which runs only under the `gitea` profile, so first:

```console
$ export UPSTREAM=gitea COMPOSE_PROFILES=gitea
```

## What runs

| Service | uid | Role |
| --- | --- | --- |
| `stub-upstream` | 10011 | Default upstream: Streamable HTTP MCP server, refuses a `tools/call` without an `Authorization` header; its `echo_auth` tool returns the credential it received, raw and in base64, so the custodian's redaction can be seen |
| `gitea`, `gitea-mcp` | image default | `gitea` profile: upstream Git service and its MCP server (`gitea-mcp-server:1.13.0`) |
| `gateway` | 10004 | agentgateway v1.7.0 with the decide, custodian and redactor processors and the refusal guard, `failClosed` |
| `decide` | 10002 | Verifies the chain, checks scope and budget, writes the ledger |
| `custodian` | 10003 | Holds the encrypted Gitea token, releases it per allowed call, and redacts it from that call's result on its own response socket |
| `docket` | 10001 | Signed append-only record sink |
| `reader` | 10005 | `agent-bailiff docket verify`, read-only, docket reader group |
| `control` | 10002 | Operator revoke, run on demand |
| `rule` | 10002 | `rule` profile: revokes a task on an out-of-scope refusal or a capped refusal budget |
| `exporter` | 10008 | `trace` profile: verified docket records to OTLP spans |
| `jaeger` | 10010 | `trace` profile: trace UI on `127.0.0.1:16686` |
| `archiver` | 10009 | `archive` profile: `agent-bailiff docket archive`, sealed segments to tmpfs and receipts |
| `agent` | 10006 | Scripted agent on the internal `edge` network only |
| `gitea-mcp-spike` | image default | `spike` profile: a second gitea-mcp with a host port, for the spike test only |
| `*-init`, `gateway-init` | per component | One-shot setup; `gateway-init` writes the gateway config with the upstream config's target |
| `gitea-secret`, `gitea-admin`, `bootstrap`, `agent-key`, `gitea-task` | per component | `gitea` profile: seed Gitea, store its token, issue the walkthrough task |
| `task-issuer` | 10007 | `operator` profile: `agent-bailiff task issue` into the bind-mounted `BAILIFF_TASK_DIR` (default `./tasks`), which must exist, owned by uid 10007 and not group or other writable |

Every bailiff container and gitea-mcp is read-only, drops all capabilities and sets `no-new-privileges`. Processes talk over Unix sockets on named volumes; each server checks the peer uid. The upstream servers, `bootstrap` and `gateway` have a network beyond `edge`: `upstream`, which is internal too. Only the gateway also joins `egress`, a routable network with no destination filter: Docker publishes a port only for a container on a routable network, and an `https://` upstream needs it. Bootstrap refuses an upstream URL that names a stack service, `localhost`, or a loopback, link-local, unspecified or multicast address. The gateway publishes its MCP port on `127.0.0.1` only (`GATEWAY_PORT`, default 18090). Any local user can connect to that port; the task chain and the agent's key gate calls, not the port. The `spike` profile adds `gitea-mcp-spike`, which publishes port 18080 on `127.0.0.1` (`GITEA_MCP_PORT`) for `tests/test_quickstart_spike.py`; a call there bypasses the gateway and carries no token.

Every service has a memory and process limit (`mem_limit`, `pids_limit`), with swap capped at the memory limit (`memswap_limit`), set at about three times the peak measured during the 32-client load run (`gitea` and `gitea-admin` 768 MiB and 256 processes, gitea-mcp 128 MiB and 64, every other service 256 MiB and 128). A runaway or forking process stops at its own container's limit instead of starving the host. There are no CPU limits, so one busy service can still slow the others.

The task scope is `gitea.issues.list` and `gitea.issues.read` on `gitea/repos/quickstart/demo/*`, budget 20, one hour. Three routes exist (`upstreams/gitea-routes.json`, named by the upstream config `upstreams/gitea.json`, see [`upstreams/schema.md`](upstreams/schema.md)): `list_issues`, `issue_read`, and `get_file_contents`, which the task scope does not include. Each route builds its resource from the call's `owner` and `repo` arguments, for example `gitea/repos/quickstart/demo/issues`, so the scope names one repository. The custodian bindings cover `gitea/repos/quickstart/*`.

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
  "task_id": "task-04c2212456940c17",
  "checks": [
    {"scenario": "allowed call reaches gitea", "expected": "result", "observed": "result", "pass": true},
    {"scenario": "injected out-of-scope call refused", "expected": "refused: out_of_scope", "observed": "refused: out_of_scope", "pass": true},
    {"scenario": "replayed call refused", "expected": "refused: already_*", "observed": "refused: already_issued", "pass": true},
    {"scenario": "other repository refused", "expected": "refused: out_of_scope", "observed": "refused: out_of_scope", "pass": true},
    {"scenario": "disclosed: unrouted write tool refused", "expected": "refused: unknown_tool", "observed": "refused: unknown_tool", "pass": true}
  ]
}
```

- Allowed: `list_issues` and `issue_read` on `quickstart/demo` return results.
- Injected: `get_file_contents` for `salaries.csv` is refused by decide. The token could read the file; the task scope cannot.
- Replayed: the exact headers and body of an allowed call are resent and refused.
- Other repository: `list_issues` on `quickstart/payroll` is refused. Its resource is `gitea/repos/quickstart/payroll/issues`, outside the scope.
- Disclosed: `issue_write` has no route and is refused before any scope check.

The operator reads the docket, then revokes the task from a verified record:

```console
$ TASK=$(jq -r .task_id run.json)
$ docker compose run --rm -T reader --task "$TASK"
LINE	AT	WRITER	SEQ	DECISION	TOOL	RESOURCE	REASON	NOTE
1	2026-11-22T14:07:02Z	issuer-docket.quickstart	1	grant	-	-	-	task grant
2	2026-11-22T14:07:15Z	decide.quickstart	1	allow	gitea.issues.list	gitea/repos/quickstart/demo/issues	ok	-
3	2026-11-22T14:07:15Z	custodian.quickstart	1	release	gitea.issues.list	gitea/repos/quickstart/demo/issues	ok	released, target outcome unknown
4	2026-11-22T14:07:15Z	decide.quickstart	2	allow	gitea.issues.read	gitea/repos/quickstart/demo/issues	ok	-
5	2026-11-22T14:07:15Z	custodian.quickstart	2	release	gitea.issues.read	gitea/repos/quickstart/demo/issues	ok	released, target outcome unknown
6	2026-11-22T14:07:15Z	decide.quickstart	3	refuse	gitea.contents.read	gitea/repos/quickstart/payroll/contents	out_of_scope	-
7	2026-11-22T14:07:15Z	decide.quickstart	4	refuse	gitea.issues.list	gitea/repos/quickstart/demo/issues	already_issued	-
8	2026-11-22T14:07:15Z	decide.quickstart	5	refuse	gitea.issues.list	gitea/repos/quickstart/payroll/issues	out_of_scope	-
agent-bailiff docket verify: 8 records verified, 8 printed
$ docker compose run --rm -T reader --task "$TASK" --json \
    | jq -r 'select(.writer == "decide.quickstart" and .entry.decision == "allow") | .token' | tail -n 1 \
    | docker compose run --rm -T control revoke --config /var/lib/bailiff/control/config.json --actor operator --level task --record -
agent-bailiff docket verify: 8 records verified, 8 printed
{"action": "revoke", "entry_id": "79825d1dbf414a17bb8ba0de44109e00", "handles": {"task": "task-04c2212456940c17", "tenant": "quickstart"}, "reason": "task", "trace_id": "399b2cd9174d87289639cb12dd9211b4"}
$ docker compose run --rm -T agent after-revoke
{
  "task_id": "task-04c2212456940c17",
  "checks": [
    {"scenario": "call after revoke refused", "expected": "refused: chain_invalid", "observed": "refused: chain_invalid", "pass": true}
  ]
}
$ docker compose run --rm -T reader
...
9	2026-11-22T14:07:17Z	control.quickstart	1	revoke	-	-	task	-
agent-bailiff docket verify: 9 records verified, 9 printed
```

The `revoke` record is the operator's; the agent container mounts neither the control key nor the ledger. The refusal after the revoke is not in the docket: decide could not verify the chain, so it logs the refusal instead of recording it.

## Tracing and the revoke rule

Two optional profiles. `trace` runs Jaeger and `agent-bailiff docket export`; `rule` runs `rule.py`, a rule (not detection) that revokes a task when decide refuses one of its `gitea.contents.read` calls as `out_of_scope` or records `refusals_capped` for it.

```console
$ COMPOSE_PROFILES=gitea,trace,rule docker compose up --build --detach --wait
$ docker compose run --rm -T agent inject | tee inject.json
{
  "task_id": "task-90033a566373be1b",
  "checks": [
    {"scenario": "allowed call reaches gitea", "expected": "result", "observed": "result", "pass": true},
    {"scenario": "injected out-of-scope call refused", "expected": "refused: out_of_scope", "observed": "refused: out_of_scope", "pass": true}
  ]
}
$ docker compose logs --no-log-prefix rule
{"entry_id": "854cbba532a24c23ac69d9c2697d70b7", "line": 6, "rule": "out_of_scope", "task": "task-90033a566373be1b", "tenant": "quickstart"}
$ docker compose run --rm -T reader --task "$(jq -r .task_id inject.json)"
...
6	2026-11-22T14:14:38Z	decide.quickstart	3	refuse	gitea.contents.read	gitea/repos/quickstart/payroll/contents	out_of_scope	-
7	2026-11-22T14:14:39Z	rule.quickstart	1	revoke	-	-	task	-
agent-bailiff docket verify: 7 records verified, 7 printed
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

## Archive

The `archive` profile runs `agent-bailiff docket archive` as uid 10009 in the docket reader group, with no network. It reads the docket read-only, copies each sealed segment and writes a receipt for it to `docket-receipts`, which the docket reads before it removes a segment.

```console
$ COMPOSE_PROFILES=gitea,archive docker compose up --build --detach --wait
$ docker compose run --rm -T reader --receipts /var/lib/bailiff/receipts
...
agent-bailiff docket verify: 9 records verified, 9 printed
agent-bailiff docket verify: 0 retained segments match their receipts
```

- The archive and the archiver's checkpoint are on tmpfs, so they are lost when the container stops. Two named volumes share one device, and the archiver refuses an archive on the docket's device; tmpfs is the only other device compose gives without host setup. In production, mount separate storage at the archive path.
- The quickstart cuts a segment at 256 MiB and keeps 16 GiB, so a demo run seals no segment and removes nothing. `tests/test_docket_rotation_e2e.py` covers cut, archive and removal.
- Only the archiver can read the archive, so `docket verify --archive` and `docket export --archive` cannot run against it from the reader or exporter here.

Remove the stack and its volumes, including any profile services:

```console
$ rm -f run.json inject.json
$ docker compose --profile "*" down --volumes --remove-orphans
```

`tests/test_quickstart_stack.py`, `tests/test_quickstart.py`, `tests/test_quickstart_trace.py`, `tests/test_quickstart_canary.py` and `tests/test_quickstart_load.py` run the Gitea stack, `tests/test_quickstart_default.py` the default stub stack, `tests/test_adopt_stack.py` the adopter path on it (credential, route draft, agent key, task issue, stdio proxy; the proxy runs as `AGENT_BAILIFF_TEST_AGENT_USER` without `--allow-shared-user`, or as the test's own user with it when that variable is unset; one test also runs `proxy run` as the test's own user without the flag and expects a refusal that names the Docker socket), and `tests/test_quickstart_tls.py` an `https://` upstream behind a configured CA, under `AGENT_BAILIFF_TEST_QUICKSTART=1` (load also needs `AGENT_BAILIFF_TEST_QUICKSTART_LOAD=1`).

## What this shows

- Scoped claims: decide allows a call only when the tool and resource are in the task scope, the budget has room and the call was not seen before. The resource comes from the route: a fixed string, or a template filled from named arguments that must be identifiers (`[A-Za-z0-9_][A-Za-z0-9._-]{0,99}`, and the filled resource must be a valid scope entry). A resource grant must be exact or end at `/*`, and a tool grant exact or end at `.*`; `task issue` refuses any other pattern, and decide refuses a task whose leaf grant is one with `unbounded_scope`.
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
- Token reach is wider than the task. The token reads `quickstart/payroll`, including `salaries.csv`. Decide refuses `get_file_contents` on `payroll` because neither the tool nor the repository is in the task scope.
- Only `owner` and `repo` are checked. Every other argument reaches gitea-mcp unchecked (gitea-mcp-server 1.13.0 `tools/list`):
  - `list_issues`: `assigned_by`, `before`, `created_by`, `labels`, `mentioned_by`, `milestones`, `page`, `per_page`, `since`, `state`, `type`.
  - `issue_read`: `attachment_id`, `attachment_uuid`, `comment_id`, `issue_number`, `method`, `output_path`, `page`, `per_page`.
  - `get_file_contents`: `end_line`, `path`, `ref`, `sha`, `start_line`, `with_lines`.
- Resources compare byte for byte. `list_issues` with `repo` `Demo` or `DEMO` resolves to `gitea/repos/quickstart/Demo/issues` and is refused as `out_of_scope`; a scope must name the repository in the case the agent sends.
- `issue_read` accepts any `method` value gitea-mcp offers. Decide does not inspect it; the read-only token scope is what keeps it read-only.
- gitea-mcp's `tools/list` exposes 48 tools, writes included, and the gateway returns all of them. Only the three routed tools can be called; the decide processor refuses any other name with `unknown_tool` before a scope check.
- The rule is not detection. It acts on an `out_of_scope` refusal of one configured tool, or on 17 agent-caused refusals of one task in 60 s; misuse that decide allows, or a few refusals for another reason, does not trigger it. An agent probing the payroll repo with `list_issues` (`gitea.issues.list`) a few times is refused as `out_of_scope` but not revoked.
- Evidence is scoped:
  - Not every refusal is recorded. An `unknown_tool` refusal, a refusal on an unverifiable chain (`chain_invalid`, including a call after a revoke) and, per task in 60 s, refusals past the 17th caused by the agent's request (scope, cost, binding, policy) or past the 17th of any other reason write no record. The 17th agent-caused refusal is recorded as `refusals_capped` and the rule revokes on it as on `out_of_scope`, so padding a task with refusals does not hide a later probe. Suspension, outage and replay refusals get `operational_refusals_capped`, which does not revoke. Past 4096 windows in one tenant per 60 s, decide records one `tenant_refusals_capped` marker and the rule takes no action (THREAT_MODEL "Unrecorded refusals").
  - A `release` record means the custodian released the token, not that Gitea applied the call: `released, target outcome unknown`.
  - The docket owner (uid 10001) can truncate the docket. The reader verifies signatures and order of what is there, not that nothing was removed from the end.
- Limits of this setup:
  - H1: each long-running Bailiff service runs as its own uid, except `rule`, which runs, like the operator's one-shot `control`, as decide's uid (10002) because they write the decide-owned ledger. Both mount `decide-data` read-only for decide's config, so they can also read decide's signing key; anyone who can run `control`, or who controls the `rule` container, can sign as decide. The one-shot `custodian-init`, `gitea-secret`, `bootstrap` and `gateway-check` run as the custodian's uid (10003). That uid owns the Gitea admin password in the `gitea-admin` volume, which `bootstrap` reads to create the agent user and token; the running `custodian` does not mount that volume. `bootstrap` and `gateway-check` mount `custodian-data`, which holds the custodian's signing key and the key encryption key (`kek`) next to the encrypted `credentials.db`, so anything running as uid 10003 can decrypt the Gitea token and, as with decide's key, sign as the custodian; forged custodian records pass `docket verify`. `gitea-admin` runs as uid 1000 and mounts Gitea's data and config read-write. The isolation rests on uids and socket peer checks, not on separate hosts.
  - H2: state lives in named volumes only; a bind mount on macOS breaks socket ownership.
  - H3: containers share the host kernel. Isolation is as strong as separate host users, no stronger.
  - H5: the agent is a script. This shows what the gateway enforces, not how a model behaves under injection.
  - H6: an allowed tool used for harm inside its scope is not stopped (OWASP ASI02, LLM06).
  - H7: tracing is optional (`trace` profile), built after the fact from verified docket records, and off the call path. It is not evidence; the docket is. Span delivery is at least once: a restart after a failed export can send a span again. The trace id is the one in the agent's `traceparent` header, which the leaf proof does not bind, so the agent chooses which trace the decide and custodian records join, including another task's. The gateway forwards `traceparent` and `tracestate` to the upstream as the agent sent them.
  - H8: the task root comes from a local issuer key, not a human login. A later login flow uses device code; the password grant is forbidden (RFC 9700 section 2.4).
- The gateway config is `gateway.json`, not `gateway.yaml`: `check-config` reads JSON only, and `gateway-check` verifies that same file against the routes and bindings before the gateway starts.
