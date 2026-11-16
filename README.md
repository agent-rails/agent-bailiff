# agent-bailiff

Lets an AI agent use a credential for one approved tool call without ever holding that credential.

Status: pre-release. Interfaces and wire formats may change. Not ready for production use.

## Why

An agent that holds API keys can use them for anything, including after a prompt injection. Keeping keys in a gateway helps, but if the component that decides a call also holds the keys, one compromise of it exposes every credential.

agent-bailiff splits that job:

- Each effect is bounded to the agent's task: one call, one operation, one credential release.
- The component that decides holds no secrets. The component that holds secrets re-checks the authority itself before every decrypt, so a compromised decider cannot bulk-decrypt the store.
- Every decision and release is a signed docket entry, joined by trace id and operation id.

## How it works

```mermaid
flowchart LR
    A[agent] -->|MCP tools/call| G[agentgateway]
    G -->|1 check| D[decide]
    G -->|2 check + clearance| C[custodian]
    G -->|request + credential header| U[upstream MCP server]
    D --> K[docket]
    C --> K
```

1. **decide** verifies the agent's delegation chain and its proof for this exact call, checks scope, cost, policy and suspension, reserves the operation in the ledger, and returns a signed single-use clearance. It holds no secrets.
2. **custodian** re-verifies the chain, proof and reservation on its own, applies canary checks, decrypts the credential, checks suspension, then claims the operation once under a per-task rate limit and sets the credential as a header on the upstream request. It removes the agent's own `authorization`, `cookie` and credential headers.
3. **docket** is a separate process that appends a signed, hash-chained entry for each decision and release.

Each component is meant to run as its own OS user. Each listens on a Unix socket that accepts only its configured peer uids. The ledger and the suspension directory (`<ledger>.suspension`, mode 0750) are owned by decide and shared read-only with the custodian through the ledger group. Their parent directory must be in that group and not group or other writable.

## What it does not protect

- The upstream MCP server receives the credential and is trusted.
- Root on the host can read every component's keys.
- A completed effect is not undone.
- Suspension is checked by decide before it issues a clearance and by the custodian just before it claims a release. A release that has already passed the custodian's check completes.
- The ledger and suspension checks read mode bits, owner and group. They do not inspect ACLs, and they check only the immediate parent directory.
- Revocation works on a delegation link, a task, a tenant or a task root. There is no revocation of an agent key across every chain that uses it.
- Control revokes the handles in a record signed by a pinned decide or custodian key. It checks that a tenant handle matches the record's tenant, but trusts that signer for the root and link bindings, so a compromised decide or custodian key can name any binding.
- agentgateway v1.7.0 cannot check client notifications. See [docs/AGENTGATEWAY.md](docs/AGENTGATEWAY.md) for this and the other adapter limits.

## Packages

| Module | Role |
|---|---|
| `agent_bailiff.decide` | Verify a call and issue a clearance |
| `agent_bailiff.custodian` | Store credentials encrypted; release one per clearance |
| `agent_bailiff.docket` | Signed, append-only security trace |
| `agent_bailiff.adapters.agentgateway` | agentgateway `ExtMcp` processors and `check-config` |
| `agent_bailiff.signing` | Ed25519 signed records over canonical JSON |

Built on [agent-warrant](https://github.com/agent-rails/agent-warrant) (task roots, delegation chains, ledger) and [toolcall-authz](https://github.com/agent-rails/toolcall-authz) (policy).

## Requirements

- Python 3.13
- Linux or macOS (peer credentials on Unix sockets)
- [agentgateway](https://github.com/agentgateway/agentgateway) v1.7.0 for the gateway adapter

## Usage

Not yet on PyPI; install from source (see Development).

Check a gateway config before starting agentgateway. Run it as the custodian's user, because it reads the credential binding table:

```sh
python -m agent_bailiff.adapters.agentgateway check-config \
  --gateway-config gateway.json \
  --routes routes.json \
  --bindings bindings.json \
  --decide-socket /run/bailiff/decide/decide.sock \
  --custodian-socket /run/bailiff/custodian/custodian.sock
```

It refuses any config the processors cannot enforce, such as `failOpen`, a missing header allowlist, the wrong processor order or a TCP processor target.

Each component has its own commands, run as that component's uid:

- `agent-bailiff init {decide,custodian,control,docket}` creates the component's signing key and a config that denies everything until it is filled in.
- `agent-bailiff {decide,custodian,docket} run --config FILE` runs a service until SIGTERM or SIGINT.
- `agent-bailiff control revoke|suspend|resume` runs as decide's uid. `revoke` and `suspend` take one signed docket line as `--record`; `revoke` takes `--level link|task|tenant|root`.

## Documentation

- [docs/AGENTGATEWAY.md](docs/AGENTGATEWAY.md): adapter method surface, sockets, config rules and limits
- [docs/DOCKET.md](docs/DOCKET.md): docket trust model and operations

## Development

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-ci.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
PYTHON=.venv/bin/python sh adapters/agentgateway/scripts/fetch_proto.sh
.venv/bin/ruff check && .venv/bin/ruff format --check && .venv/bin/mypy && .venv/bin/pytest -q
```

`fetch_proto.sh` downloads the agentgateway `ExtMcp` proto (v1.7.0, commit `26f5aeb`), checks its sha256 and generates the Python stubs; they are not committed.

The end-to-end tests run against the agentgateway v1.7.0 release binary. `adapters/agentgateway/scripts/fetch_gateway.sh` downloads it into `~/.cache/agent-bailiff`, checked against `adapters/agentgateway/agentgateway-v1.7.0.sha256`; without it those tests are skipped.

## License

Apache-2.0. See [LICENSE](LICENSE).
