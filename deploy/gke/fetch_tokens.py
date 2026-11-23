from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from agent_bailiff.custodian.files import OwnedFileError, read_owned
from agent_bailiff.effector.kubernetes import MAX_TOKEN_BYTES, MAX_TOKEN_LIFETIME_SECONDS, token_lifetime

MIN_REMAINING_SECONDS = 60
FIELDS = ("effector", "audit")

Fetch = Callable[[str, str], bytes]


class FetchError(Exception):
    pass


def fetch_secret(project: str, secret: str) -> bytes:
    command = ["gcloud", "secrets", "versions", "access", "latest", "--secret", secret, "--project", project]
    done = subprocess.run(command, capture_output=True, check=False, timeout=60)
    if done.returncode != 0:
        raise FetchError(f"gcloud could not read {secret}: {done.stderr.decode(errors='replace').strip()}")
    return done.stdout


def expiry(token: str) -> int:
    lifetime = token_lifetime(token)
    if lifetime is None or not 0 < lifetime <= MAX_TOKEN_LIFETIME_SECONDS:
        raise FetchError(f"a fetched token does not live at most {MAX_TOKEN_LIFETIME_SECONDS} s")
    part = token.split(".")[1]
    return int(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["exp"])


def tokens(content: bytes, now: float) -> dict[str, str]:
    try:
        decoded = json.loads(content)
    except ValueError:
        raise FetchError("the secret is not JSON") from None
    if not isinstance(decoded, dict) or sorted(decoded) != sorted(FIELDS):
        raise FetchError(f"the secret must hold exactly {', '.join(FIELDS)}")
    found = {}
    for field in FIELDS:
        token = decoded[field]
        if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES:
            raise FetchError(f"the {field} token is not a string of at most {MAX_TOKEN_BYTES} bytes")
        if expiry(token) - now < MIN_REMAINING_SECONDS:
            raise FetchError(f"the {field} token expires within {MIN_REMAINING_SECONDS} s; the minter is not running")
        found[field] = token
    return found


def current(path: Path) -> str | None:
    if not os.path.lexists(path):
        return None
    try:
        return read_owned(path, "token file", MAX_TOKEN_BYTES).decode("ascii").strip()
    except OwnedFileError as exc:
        raise FetchError(str(exc)) from None


def replace(path: Path, token: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, token.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
    except OSError:
        os.unlink(temporary)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(project: str, secret: str, paths: dict[str, Path], fetch: Fetch = fetch_secret) -> list[str]:
    found = tokens(fetch(project, secret), time.time())
    written = []
    for field in FIELDS:
        if current(paths[field]) == found[field]:
            continue
        replace(paths[field], found[field])
        written.append(field)
    return written


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Copy the minted effector and audit tokens into their 0600 files.")
    parser.add_argument("--project", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--effector-token", type=Path, required=True)
    parser.add_argument("--audit-token", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        written = run(args.project, args.secret, {"effector": args.effector_token, "audit": args.audit_token})
    except FetchError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps({"written": written}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
