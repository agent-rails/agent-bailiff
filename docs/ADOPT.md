# Adopting agent-bailiff

This guide puts one agent host (Claude Code, Cursor or any client that launches stdio MCP servers) in front of one Streamable HTTP MCP server through agent-bailiff. The agent gets a short-lived task: a scope, a budget and an expiry, bound to a key only the agent holds. Decide checks every call against that task, and the custodian adds the server's credential to allowed calls only, so the agent host never holds it. The server receives the credential on every allowed call. If it echoes the credential in a call's result, the custodian replaces it with `[redacted by agent-bailiff]` before the agent sees the result; it cannot do that for error messages, short credentials or transformed echoes, so the server must still be trusted with the credential.

Linux and macOS only.

## Two users

Two OS users take part, and the separation between them is what the guide depends on.

- **Operator**: runs the Docker Compose stack, stores the credential and issues tasks.
- **Agent user**: runs the agent host and `agent-bailiff proxy`.

The agent user must not reach the Docker daemon. Anyone who can reach it can read the issuer key and the encrypted credential store from the stack's volumes, mint their own tasks and get the credential, bypassing decide. On Linux, keep the agent user out of the `docker` group. On macOS, Docker Desktop and OrbStack give the socket to the logged-in user, so run the agent host as a separate macOS user, in a VM or in a devcontainer. CI runs the proxy as a second Linux user that cannot open the Docker socket or the issuer key (`tests/test_adopt_stack.py`).

`agent-bailiff proxy run` detects this when it starts. It tries to connect to the Docker daemon at `DOCKER_HOST` when that is a `unix://` URL, `/var/run/docker.sock`, `.docker/run/docker.sock`, `.orbstack/run/docker.sock` and `.colima/default/docker.sock` under both `$HOME` and the passwd home directory of the user, `$XDG_RUNTIME_DIR/docker.sock` and `/run/user/<uid>/docker.sock`. Any listener, and any existing socket at one of those paths that the user can write to, makes it refuse to start. A socket with no daemon behind it still counts, because Docker is available to the user as soon as a daemon starts there. A candidate is skipped only when the path does not exist, is not a socket, or is a socket the user is denied access to and cannot write. A connect that times out or fails for any other reason counts as reachable. A `DOCKER_HOST` that is not a `unix://` URL (`tcp://`, `ssh://`) is not tested and counts as reachable. The error names each endpoint. The check does not cover:

- a Docker daemon at another socket path, such as a rootless socket outside the paths above, or one reached through a wrapper or a remote host;
- a Docker context: `DOCKER_CONTEXT` and `currentContext` in `~/.docker/config.json` are not resolved;
- environment other than `DOCKER_HOST` and `XDG_RUNTIME_DIR`: a `HOME` override is covered by the passwd home, but a `DOCKER_HOST` that names a socket the user could reach by another path is only tested at that path;
- a user who is added to the `docker` group, or gets `sudo`, after the proxy started;
- a user who can read the issuer key or the stack's volumes by another route: the issuer key lives in the Docker volume `issuer-data`, whose host path the proxy cannot know, so the proxy does not check it;
- the other proxy commands, `keygen` and `tools`, which do not run the check.

The check detects a misconfiguration at start; it is not a boundary. The MCP host config that launches the proxy must not be writable by the agent user: a user who can edit it can add `--allow-shared-user` or change the environment the check reads, and the check no longer applies.

For single-user development, `proxy run --allow-shared-user` skips the refusal and prints one warning on stderr naming what was reachable. With that flag the agent can mint its own tasks, so the task scope does not bind it. There is no environment variable for it. In the agent host config, add `"--allow-shared-user"` to `args` only on a development machine.

Every directory above the task directory must be owned by the operator or root and must not be writable by the agent user. `task issue` refuses a symlink only as the last path component. The agent user must still be able to search every one of those directories, or the proxy cannot open `task.json`. A task directory under the operator's home works only if the home allows that; check with `sudo -u agent test -r <task dir>/task.json` after step 4.

## Requirements

- Operator: Docker Engine 28.3.3 or later, Compose v2.20 or later, `git`, `jq`. On Linux, Engine 28.2.0 to 28.3.2 stops isolating published ports after a firewalld reload, so a host with a route to the bridge network can reach ports published on `127.0.0.1` (CVE-2025-54388).
- Agent user: Python 3.13 and [uv](https://docs.astral.sh/uv/).
- The upstream: one Streamable HTTP MCP server that takes one static credential in one request header. It runs either as a service you add to the stack or at an `https://` URL. stdio and SSE servers, OAuth token refresh and more than one upstream are not supported.

## 1. Install

As the agent user, and again as the operator, who runs `routes generate`:

```console
$ uv tool install git+https://github.com/agent-rails/agent-bailiff@v0.1.0
$ agent-bailiff proxy --help
```

The operator also clones the same tag, since the stack is built from `examples/quickstart`:

```console
$ git clone --branch v0.1.0 https://github.com/agent-rails/agent-bailiff
$ cd agent-bailiff/examples/quickstart
```

## 2. Describe the upstream

Make a directory for your upstream config, for example `~/bailiff/upstreams`, mode 0755, with files that are 0644: the stack's containers run as their own uids and read it read-only. Write the config `notes.json` (fields in [`upstreams/schema.md`](../examples/quickstart/upstreams/schema.md)):

```json
{
  "version": 1,
  "service": "notes",
  "url": "https://notes.example.com/mcp",
  "credential_id": "notes-token",
  "credential_header": "Authorization",
  "target": "notes",
  "binding_resource": "notes/*",
  "routes_file": "notes-routes.json"
}
```

The stack needs at least one route to start. Until the routes are drafted from the server (step 5), write one for a tool you know the server has, with a fixed resource:

```json
{"routes": [{"service": "notes", "name": "read_note", "tool": "notes.read_note", "resource": "notes/seed"}]}
```

## 3. Start the stack

As the operator, from `examples/quickstart`:

```console
$ mkdir -p -m 0755 "$HOME/bailiff/tasks"
$ printf 'UPSTREAM=notes\nBAILIFF_UPSTREAMS=%s\nBAILIFF_TASK_DIR=%s\n' "$HOME/bailiff/upstreams" "$HOME/bailiff/tasks" > .env
$ docker compose up --build --detach --wait
```

Compose reads `.env` from this directory for every later command. Without these variables it falls back to the bundled stub upstream and `./tasks` without an error, so keep the file. The gateway listens on `127.0.0.1:18090` (`GATEWAY_PORT`). Any local user can connect to that port, but a call goes through only with a valid task and the agent's key.

For a Gitea upstream, add `provider`, `provider_api_url` and `required_permissions` to the upstream config ([`upstreams/schema.md`](../examples/quickstart/upstreams/schema.md)) and check the token before storing it, from the operator's host, which reaches the provider; the custodian has no network. The check refuses a token with scopes beyond `required_permissions` or private reach outside `binding_resource`, and on a pass prints the token's fingerprint (D25 in [DECISIONS.md](DECISIONS.md)):

```console
$ agent-bailiff credential-check --provider gitea --api-url https://gitea.example.com/api/v1 \
    --binding-resource 'gitea/repos/acme/*' --required read:issue --required read:repository < gitea-token.txt
{"fingerprint": "<sha256>", "login": "acme-bot", "private_repositories": 2, "scopes": ["read:issue", "read:repository"]}
```

Then pass the printed fingerprint to `put-credential --expect-fingerprint`, which stores nothing unless stdin holds the same token. The check is point-in-time: run it again when the token's user gains access. Use a dedicated bot user that can read only the repositories the bindings cover. `put-credential --accept-broader` stores a refused token, and every release of it is docketed as `broader`.

Store the credential. The custodian reads it from stdin. Keep the token file mode 0600, owned by the operator, and delete it once the command prints `stored`, or pipe the token from a secret manager. The command refuses a credential that echo redaction cannot cover, such as one with a form under 12 characters (D22 in [DECISIONS.md](DECISIONS.md)):

```console
$ docker compose run --rm --no-deps -T custodian -m agent_bailiff.cli custodian put-credential \
    --config /var/lib/bailiff/custodian/config.json --tenant quickstart \
    --credential-id notes-token --target notes < notes-token.txt
stored
```

`custodian check-credentials --config /var/lib/bailiff/custodian/config.json` lists every stored credential the custodian would refuse to release, and every binding with no stored credential, and exits 1 if there is any. Run it after upgrading, before restarting the custodian ([UPGRADE.md](UPGRADE.md)).

Give the task directory to the issuer's uid (10007). Compose does not create it, and it must not be group or other writable:

```console
$ docker compose --profile operator run --rm --no-deps --user 0:0 --cap-add CHOWN \
    --entrypoint chown task-issuer 10007:10007 /out
```

## 4. Issue a task

The agent user makes a fresh key for each task and passes only its public half to the operator:

```console
$ mkdir -m 0700 ~/.bailiff-keys
$ agent-bailiff proxy keygen --key-dir ~/.bailiff-keys
oa5bveQCZ3-a-9zg9TUN3MntJk9T_yIfkt7LoHUCtZ8
```

The operator issues the task to that key:

```console
$ docker compose --profile operator run --rm --no-deps -T task-issuer \
    --purpose triage-notes \
    --scope '{"permissions": [{"tools": ["notes.read_note", "notes.write_note"], "resources": ["notes/todo"], "max_cost_per_call": 1}]}' \
    --budget 20 --subject=oa5bveQCZ3-a-9zg9TUN3MntJk9T_yIfkt7LoHUCtZ8
agent-bailiff task issue: wrote /out/task.json, expires at 1795523898, grant_id 6c1f0e5d2b7a4e8f9a3d1c0b5e7f2a46
task-f0f2af5ac610e8db
```

Pass the key as `--subject=KEY`, since a key can start with `-`. A task lasts one hour by default (`--ttl` in seconds, at most 86400). The stack's issuer allows a budget of at most 100, and every call costs 1. `--max-depth` defaults to 0, which means the agent cannot delegate. The task is written to `$BAILIFF_TASK_DIR/task.json`, mode 0644, so the agent user can read it.

Before it writes `task.json`, `task issue` records a grant for the task in the docket with the issuer's own docket-writer key, so the docket service must be running. If the docket refuses the grant, no task is written. If the docket does not acknowledge it, the error names the `grant_id` that may be recorded and keeps `task.json.pending`; rerunning the same command reuses that root and `grant_id`. To give it up instead, revoke it from its grant (step 7). See [DOCKET.md](DOCKET.md), Grants from task issue.

The scope is a list of permissions. A call is allowed only when one permission lists both its tool and its resource, so to let the agent read every note but write only `notes/todo`, give each its own permission:

```json
{"permissions": [
  {"tools": ["notes.read_note"], "resources": ["notes/*"], "max_cost_per_call": 1},
  {"tools": ["notes.write_note"], "resources": ["notes/todo"], "max_cost_per_call": 1}
]}
```

`task.json` holds at most 4,096 bytes, and `task issue` refuses a scope that does not fit; two permissions over 20 resources fit in about 1,700 bytes. A resource grant must be exact or end at `/*`. A tool grant can end at `.*`, but that also covers any tool routed later under the same prefix, so grant exact tools.

## 5. Draft the routes

A route maps an upstream tool to a tool id and a resource, and the resource is what the task scope is checked against. The agent user lists the server's tools through the gateway, using any task:

```console
$ agent-bailiff proxy tools --task-file ~/bailiff/tasks/task.json --key-dir ~/.bailiff-keys \
    --gateway-url http://127.0.0.1:18090/mcp > tools.json
```

The operator drafts a route for every tool:

```console
$ agent-bailiff routes generate --tools tools.json --service notes --out draft-routes.json
agent-bailiff routes generate: wrote 3 route(s) to draft-routes.json; fill each resource
```

`tools.json` comes from the upstream, so treat it as untrusted input. The generator rejects tool names that are not valid scope ids and lists them on stderr. It routes nothing on its own: every resource in the draft is empty, and decide refuses to load the file until each one is filled. Then:

- Delete each tool the agent should not have. The proxy does not list a tool missing from its routes and rejects a call to it; a tool missing only from decide's routes is refused as `unknown_tool`.
- Give each remaining tool a resource. A fixed resource such as `notes/all` scopes only by tool. A template filled from named arguments, such as `notes/{note}` with `"schema": [{"name": "note", "kind": "identifier"}]`, scopes per object. Arguments that do not build the resource reach the upstream unchecked.

Replace `notes-routes.json` with the edited draft and apply it. Compose reruns the setup steps and restarts decide and the custodian:

```console
$ docker compose up --detach --wait
```

The proxy must use the same routes as decide. Give the agent user a read-only copy of `notes-routes.json`, and replace that copy whenever the operator's file changes. The proxy logs the sha256 of its routes at startup, so the two files can be compared. A route that the proxy has and decide lacks is refused as `unknown_tool`.

## 6. Connect the agent host

The agent host launches the proxy over stdio. For Claude Code, add it to `.mcp.json` (Cursor uses the same shape in `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "bailiff": {
      "type": "stdio",
      "command": "agent-bailiff",
      "args": [
        "proxy", "run",
        "--task-file", "/home/operator/bailiff/tasks/task.json",
        "--key-dir", "/home/agent/.bailiff-keys",
        "--gateway-url", "http://127.0.0.1:18090/mcp",
        "--routes", "/home/agent/bailiff/notes-routes.json"
      ]
    }
  }
}
```

The config holds paths only, with no key or token. The proxy lists only routed tools, with their upstream names and descriptions, and removes tool annotations. It reads the tool list once per process, so restart the agent host after a route change.

A call to a tool the proxy has no route for is rejected as a JSON-RPC error. Any other call that does not return a result comes back as a tool error, which starts with a reason and tells the model what to do next:

| Reason | Meaning | Operator's next step |
| --- | --- | --- |
| `out_of_scope`, `reservation_refused`, `unknown_tool`, `chain_invalid` and other refusals | The call was refused and the gateway did not forward it. The model is told to stop and not retry | Widen the scope, raise the budget or add the route if the call should be allowed |
| `needs_approval` | Policy asks for a human approval, which this stack cannot grant | None in this release |
| `suspended` | An operator suspended agent-bailiff. The model is told not to retry until it resumes | `control resume` when ready |
| `docket_unavailable`, `ledger_unavailable`, `internal_error` | A component was unavailable and budget for the attempt may already be spent. The model may retry twice | Check `docker compose ps` and the service logs |
| `task_expired` | The task's expiry has passed and nothing was sent | Renew (step 7) |
| `no_task` | `task.json` does not exist | Issue a task (step 4) |
| `outcome_unknown` | The call was sent and may have taken effect. The model is told not to retry, and the proxy never retries a call | Check the upstream's state |
| `gateway_unavailable` | The gateway did not answer and nothing was sent. The model may retry twice | Check `docker compose ps` |
| No reason prefix | `task.json` is unreadable or invalid, the key directory has no key for the task, or the arguments do not fit the route | Check the file permissions, the key directory and the route's schema |

## 7. Renew and revoke

To renew, run step 4 again: the agent user makes a new key, and the operator issues a new task to it. The proxy reads `task.json` again before each call, switches to the new task, and deletes every key in the key directory except the new task's key and the newest one. Give each agent host its own key directory, or one proxy can delete another's key. Neither the agent host nor the proxy needs a restart. Deleting a key is cleanup, not revocation: the old task stays valid until it expires, and a copy of its key still works.

To stop a task now, the operator revokes it from the signed docket:

```console
$ set -o pipefail
$ docker compose --profile operator run --rm --no-deps -T --entrypoint python reader \
    -m agent_bailiff.cli docket tasks --docket /var/lib/bailiff/docket/docket.log \
    --decide-pin /pins/decide/decide.json --custodian-pin /pins/custodian/custodian.json \
    --control-pin /pins/control/control.json --control-pin /pins/rule/rule.json \
    --grant-pin /pins/issuer/issuer-docket.json --issuers /var/lib/bailiff/reader/issuers.json --json \
  | jq -r 'select(.tenant == "quickstart" and .task == "task-f0f2af5ac610e8db" and .root_status == "verified").record' \
  | docker compose --profile operator run --rm --no-deps -T control revoke \
    --config /var/lib/bailiff/control/config.json --actor operator --level task --record -
{"action": "revoke", "entry_id": "f8b39d6075144028b685cf000ec13743", "handles": {"task": "task-f0f2af5ac610e8db", "tenant": "quickstart"}, "reason": "task", "trace_id": "d5e3fffdc4062c1688be463c7b6a243c"}
```

`--issuers` is the reader's own issuers file, written by `reader-init` on each `docker compose up` from the issuer pin, as decide's `issuers` are. If you edit decide's `issuers` by hand, edit this file to match, or ROOT reads `invalid` for valid roots. The filter selects only a row whose task root an allowed issuer signed, so a grant forged in another tenant's name hands over no record. `pipefail` gives the pipeline a non-zero status when `docket tasks` exits non-zero, even though the revoke still runs on the selected verified row: 4 means the docket holds an invalid or undecodable grant, 3 that some records were not counted. Read its stderr when that happens.

After the revoke, every call on the task is refused as `chain_invalid`. A task that has made no call is listed from its grant, and its `record` is the grant, so it is revoked the same way. Once the issuer records grants, `docket tasks` also needs the issuer's docket-writer public key as `--grant-pin`, and control needs that writer in its `grant_writers` and the issuer in its `issuers`. See [DOCKET.md](DOCKET.md) for `docket tasks`, `docket grants` and `docket verify`.

To remove the stack and its volumes, including the issuer key and the stored credential:

```console
$ docker compose --profile "*" down --volumes --remove-orphans
```

## Limits

- The upstream server receives the credential on every allowed call and is trusted with it.
- `credential-check` covers Gitea only, as the provider reports it at the moment it runs. Nothing proves a stored credential passed it.
- Upstream tool names, descriptions and results reach the model, and any of them can carry instructions. The task scope bounds what an instructed agent can do. It cannot stop a call that is in scope.
- The gateway reaches the upstream over a network with no destination filter. Bootstrap refuses a URL that names one of the stack's own components, `localhost`, or a loopback, link-local, unspecified or multicast IP address written in standard form. It does not refuse private ranges, other spellings of an IPv4 address such as `2130706433`, or a hostname that resolves to a local address.
- With `ca_file` in the upstream config, the gateway trusts only those certificates for the upstream, not the system roots.
- The agent user can read its own key and `task.json`, so anything running as that user can make calls within the task until it expires or is revoked.

- Echo redaction is best-effort suppression of literal forms in a call's own result, not a containment boundary. A form under 12 characters, such as a short Basic password (`put-credential` refuses one unless stored with `--accept-unredactable`), an echo split across strings or transformed, JSON-RPC error text and event-stream side messages are not redacted. The proxy never shows the model error text or side messages, but any client that reaches the gateway port directly, the agent user included, can read them. Prefer short-lived, target-bound credentials.

## Upgrading to echo redaction

A stack from before echo redaction needs both the custodian's response socket and the gateway config's redactor. `docker compose up --build` ships both together. Elsewhere, upgrade the custodian first, so its response socket is listening, then the gateway config; roll back in the reverse order. A gateway config with the redactor in front of a custodian without the response socket fails every call after the upstream acted, and the client reports `outcome_unknown`. Releases made before the gateway runs the redactor leave in-flight entries that expire after `inflight_ttl`.

`inflight_ttl` defaults to 180 s and the custodian refuses a value under 150 s: check-config caps the gateway's upstream timeouts at 120 s, and the entry must outlive the slowest non-streamed call by a margin of 30 s, or a slow call acts upstream and then fails as `response_unmatched`. An event stream held open past `inflight_ttl` is not covered: neither upstream timeout bounds a stream body, and `responseIdleTimeout` cuts only a stream that goes silent, not one that keeps sending messages (see AGENTGATEWAY.md).

Size the custodian's `inflight_max` at least 2 x peak releases per second x `inflight_ttl`. A full map refuses new releases before the upstream acts, and the agent sees `release_refused`. Keep `inflight_per_tenant` well below `inflight_max` (default 512 of 4096) so a few busy tenants cannot fill the map and refuse every other tenant.

A result is capped at 4 MiB before and after redaction. The redacted result is re-encoded with ASCII escapes, so a result near the cap with many characters outside the Basic Multilingual Plane (each 4 bytes in UTF-8, 12 bytes escaped) can exceed the cap only after redaction; it is refused as `response_oversize` after the upstream acted.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full list. The quickstart's [README](../examples/quickstart/README.md) runs the same stack against Gitea (`UPSTREAM=gitea COMPOSE_PROFILES=gitea`).
