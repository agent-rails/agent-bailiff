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

See [docs/DOCKET.md](docs/DOCKET.md) for the docket trust model and operations.

The sink and client need peer credentials on Unix sockets: Linux (`SO_PEERCRED`) or macOS (`getpeereid`).

## Development

Python 3.13.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-ci.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/ruff check && .venv/bin/ruff format --check && .venv/bin/mypy && .venv/bin/pytest -q
```
