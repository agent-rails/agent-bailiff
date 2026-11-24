# Adopting agent-bailiff

This guide puts one agent host (Claude Code, Cursor or any client that launches stdio MCP servers) in front of one Streamable HTTP MCP server through agent-bailiff. The agent gets a short-lived task: a scope, a budget and an expiry, bound to a key only the agent holds. Decide checks every call against that task, and the custodian adds the server's credential to allowed calls only, so the agent host never holds it. The server receives the credential on every allowed call and its results reach the agent unchanged, so the server must be trusted not to return it.

Linux and macOS only.

## Two users

Two OS users take part, and the separation between them is what the guide depends on.

- **Operator**: runs the Docker Compose stack, stores the credential and issues tasks.
- **Agent user**: runs the agent host and `agent-bailiff proxy`.

The agent user must not reach the Docker daemon. Anyone who can reach it can read the issuer key and the encrypted credential store from the stack's volumes, mint their own tasks and get the credential, bypassing decide. On Linux, keep the agent user out of the `docker` group. On macOS, Docker Desktop and OrbStack give the socket to the logged-in user, so run the agent host as a separate macOS user, in a VM or in a devcontainer. CI runs the proxy as a second Linux user that cannot open the Docker socket or the issuer key (`tests/test_adopt_stack.py`).

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

Store the credential. The custodian reads it from stdin. Keep the token file mode 0600, owned by the operator, and delete it once the command prints `stored`, or pipe the token from a secret manager:

```console
$ docker compose run --rm --no-deps -T custodian -m agent_bailiff.cli custodian put-credential \
    --config /var/lib/bailiff/custodian/config.json --tenant quickstart \
    --credential-id notes-token --target notes < notes-token.txt
stored
```

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
    --scope '{"tools": ["notes.read_note", "notes.write_note"], "resources": ["notes/todo"], "max_cost_per_call": 1}' \
    --budget 20 --subject=oa5bveQCZ3-a-9zg9TUN3MntJk9T_yIfkt7LoHUCtZ8
agent-bailiff task issue: wrote /out/task.json, expires at 1795523898
task-f0f2af5ac610e8db
```

Pass the key as `--subject=KEY`, since a key can start with `-`. A task lasts one hour by default (`--ttl` in seconds, at most 86400). The stack's issuer allows a budget of at most 100, and every call costs 1. `--max-depth` defaults to 0, which means the agent cannot delegate. The task is written to `$BAILIFF_TASK_DIR/task.json`, mode 0644, so the agent user can read it.

A resource grant must be exact or end at `/*`. A tool grant can end at `.*`, but that also covers any tool routed later under the same prefix, so grant exact tools.

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
$ docker compose --profile operator run --rm --no-deps -T --entrypoint python reader \
    -m agent_bailiff.cli docket tasks --docket /var/lib/bailiff/docket/docket.log \
    --pin /pins/decide/decide.json --pin /pins/custodian/custodian.json \
    --control-pin /pins/control/control.json --control-pin /pins/rule/rule.json --json \
  | jq -r 'select(.task == "task-f0f2af5ac610e8db").record' \
  | docker compose --profile operator run --rm --no-deps -T control revoke \
    --config /var/lib/bailiff/control/config.json --actor operator --level task --record -
{"action": "revoke", "entry_id": "f8b39d6075144028b685cf000ec13743", "handles": {"task": "task-f0f2af5ac610e8db", "tenant": "quickstart"}, "reason": "task", "trace_id": "d5e3fffdc4062c1688be463c7b6a243c"}
```

After that, every call on the task is refused as `chain_invalid`. A task that has made no allowed call has no docket record, so it cannot be revoked this way; it ends at its expiry. See [DOCKET.md](DOCKET.md) for `docket tasks` and `docket verify`.

To remove the stack and its volumes, including the issuer key and the stored credential:

```console
$ docker compose --profile "*" down --volumes --remove-orphans
```

## Limits

- The upstream server receives the credential on every allowed call and is trusted with it.
- Upstream tool names, descriptions and results reach the model, and any of them can carry instructions. The task scope bounds what an instructed agent can do. It cannot stop a call that is in scope.
- The gateway reaches the upstream over a network with no destination filter. Bootstrap refuses a URL that names one of the stack's own components, `localhost`, or a loopback, link-local, unspecified or multicast IP address written in standard form. It does not refuse private ranges, other spellings of an IPv4 address such as `2130706433`, or a hostname that resolves to a local address.
- With `ca_file` in the upstream config, the gateway trusts only those certificates for the upstream, not the system roots.
- The agent user can read its own key and `task.json`, so anything running as that user can make calls within the task until it expires or is revoked.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full list. The quickstart's [README](../examples/quickstart/README.md) runs the same stack against Gitea (`UPSTREAM=gitea COMPOSE_PROFILES=gitea`).
