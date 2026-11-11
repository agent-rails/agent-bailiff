# agent-bailiff

agent-bailiff is a separate enforcement layer for AI agent tool calls, built on [agent-warrant](https://github.com/agent-rails/agent-warrant) and [toolcall-authz](https://github.com/agent-rails/toolcall-authz).

Status: pre-release. Interfaces and wire formats may change. Not ready for production use.

## What exists

- `agent_bailiff.signing`: Ed25519 signed, typed, versioned records over canonical JSON.
  - `sign(private_key, kid, typ, body)` returns a compact `payload.signature` token.
  - `verify(token, pinned_keys, expected_typ, allowed_fields)` returns `Verified` or `Refused(reason)` for any token input. Invalid configuration (`pinned_keys` not a mapping of non-empty str key ids to Ed25519 public keys, `allowed_fields` not a collection of non-empty str names, an empty or non-str `expected_typ`) raises `TypeError` or `ValueError` before the token is read.
  - `token_hash(token)` is the base64url SHA-256 of a token.
- `agent_bailiff.docket`: an append-only, signed, per-writer hash-chained security trace.
  - `DocketSink` serves appends on a Unix socket and fsyncs each entry before acknowledging it.
  - `DocketClient` signs and appends entries, authenticates the sink by peer uid and detects a sink rolled back behind entries it saw acknowledged.
  - `verify_docket` checks every signature and chain link; `repair` moves a torn final line aside.
- `agent_bailiff.decide`: holds no secrets.
  - `Decider.check(request, now)` verifies the delegation chain and leaf proof, checks scope, cost, policy and suspension, reserves the operation in the agent-warrant ledger, records a docket entry and returns a signed single-operation `Clearance`.
  - `Decider.record_outcome` and `Decider.reconcile` move issued operations to a terminal state.
- `agent_bailiff.custodian`: holds the credentials.
  - `CredentialStore` keeps credentials envelope-encrypted under a `KeyBackend` (`LocalBackend` for a separate local OS user).
  - `Custodian.release(clearance, request, now)` re-verifies the chain, leaf proof and ledger reservation itself, checks the `BindingTable`, the one-use `ClaimsStore` claim, the per-task rate limit and canaries, then returns the credential header and records a docket entry.
- `agent_bailiff.adapters.agentgateway`: agentgateway v1.7.0 `ExtMcp` processors.
  - `DecideProcessor` passes the clearance to the next processor as metadata; `CustodianProcessor` sets the credential header and strips agent credentials from the upstream request.
  - `ProcessorServer` serves each processor on a Unix socket that accepts only the gateway's uid.
  - `python -m agent_bailiff.adapters.agentgateway check-config` refuses a gateway config the processors cannot enforce.

See [docs/DOCKET.md](docs/DOCKET.md) for the docket trust model and operations.
See [docs/AGENTGATEWAY.md](docs/AGENTGATEWAY.md) for the agentgateway adapter's exposure, socket and config limits.

The sink and client need peer credentials on Unix sockets: Linux (`SO_PEERCRED`) or macOS (`getpeereid`).

## Development

The agentgateway `ExtMcp` proto is not vendored. `adapters/agentgateway/scripts/fetch_proto.sh` downloads it from agentgateway v1.7.0 (commit `26f5aeb`), checks its sha256 and generates the Python stubs into `agent_bailiff/adapters/agentgateway/_proto/` (gitignored). Run it before the checks.

`tests/test_agentgateway_e2e.py` runs both processors behind the agentgateway v1.7.0 release binary. `adapters/agentgateway/scripts/fetch_gateway.sh` downloads that binary (darwin-arm64 or linux-amd64) into `~/.cache/agent-bailiff`, checked against `adapters/agentgateway/agentgateway-v1.7.0.sha256`; without it the test is skipped.

Python 3.13.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-ci.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
PYTHON=.venv/bin/python sh adapters/agentgateway/scripts/fetch_proto.sh
.venv/bin/ruff check && .venv/bin/ruff format --check && .venv/bin/mypy && .venv/bin/pytest -q
```
