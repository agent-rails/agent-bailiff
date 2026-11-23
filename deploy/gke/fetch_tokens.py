from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from agent_bailiff.custodian.files import OwnedFileError, create_owned, read_owned
from agent_bailiff.effector.kubernetes import MAX_TOKEN_BYTES, MAX_TOKEN_LIFETIME_SECONDS

MIN_REMAINING_SECONDS = 60
CLOCK_SKEW_SECONDS = 60
MAX_ERROR_CHARS = 300
FIELDS = ("effector", "audit")

Fetch = Callable[[str, str], bytes]


class FetchError(Exception):
    pass


def fetch_secret(project: str, secret: str) -> bytes:
    command = ["gcloud", "secrets", "versions", "access", "latest", "--secret", secret, "--project", project]
    try:
        done = subprocess.run(command, capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FetchError(f"gcloud could not run: {type(exc).__name__}") from None
    if done.returncode != 0:
        message = done.stderr.decode("ascii", errors="replace").strip()[:MAX_ERROR_CHARS]
        raise FetchError(f"gcloud could not read {secret} (exit {done.returncode}): {message}")
    return done.stdout


def claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if not token.isascii() or len(parts) != 3:
        raise FetchError("a fetched token is not an ASCII JWT")
    try:
        decoded = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise FetchError("a fetched token has unreadable claims") from None
    if not isinstance(decoded, dict):
        raise FetchError("a fetched token has unreadable claims")
    return decoded


def check(field: str, token: object, subject: str, now: float) -> str:
    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES:
        raise FetchError(f"the {field} token is not a string of at most {MAX_TOKEN_BYTES} bytes")
    found = claims(token)
    if found.get("sub") != subject:
        raise FetchError(f"the {field} token names {found.get('sub')!r}, not {subject}")
    issued, expires = found.get("iat"), found.get("exp")
    if type(issued) is not int or type(expires) is not int:
        raise FetchError(f"the {field} token has no integer iat and exp")
    if not 0 < expires - issued <= MAX_TOKEN_LIFETIME_SECONDS:
        raise FetchError(f"the {field} token does not live at most {MAX_TOKEN_LIFETIME_SECONDS} s")
    if issued > now + CLOCK_SKEW_SECONDS:
        raise FetchError(f"the {field} token was issued in the future")
    if expires - now < MIN_REMAINING_SECONDS:
        raise FetchError(f"the {field} token expires within {MIN_REMAINING_SECONDS} s; the minter is not running")
    return token


def tokens(content: bytes, subjects: Mapping[str, str], now: float) -> dict[str, str]:
    try:
        decoded = json.loads(content)
    except ValueError:
        raise FetchError("the secret is not JSON") from None
    if not isinstance(decoded, dict) or sorted(decoded) != sorted(FIELDS):
        raise FetchError(f"the secret must hold exactly {', '.join(FIELDS)}")
    return {field: check(field, decoded[field], subjects[field], now) for field in FIELDS}


def current(path: Path) -> str | None:
    if not os.path.lexists(path):
        return None
    try:
        return read_owned(path, "token file", MAX_TOKEN_BYTES).decode("ascii").strip()
    except (OwnedFileError, UnicodeDecodeError) as exc:
        raise FetchError(f"{path}: {exc}") from None


def replace(path: Path, token: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    try:
        create_owned(temporary, "token file", token.encode("ascii"))
        os.replace(temporary, path)
    except (OwnedFileError, OSError) as exc:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise FetchError(f"{path}: {exc}") from None
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(
    project: str, secret: str, paths: Mapping[str, Path], subjects: Mapping[str, str], fetch: Fetch = fetch_secret
) -> list[str]:
    found = tokens(fetch(project, secret), subjects, time.time())
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
    parser.add_argument("--namespace", default="bailiff-system")
    parser.add_argument("--effector-account", default="effector")
    parser.add_argument("--audit-account", default="effector-audit")
    parser.add_argument("--effector-token", type=Path, required=True)
    parser.add_argument("--audit-token", type=Path, required=True)
    args = parser.parse_args(argv)
    subjects = {
        "effector": f"system:serviceaccount:{args.namespace}:{args.effector_account}",
        "audit": f"system:serviceaccount:{args.namespace}:{args.audit_account}",
    }
    paths = {"effector": args.effector_token, "audit": args.audit_token}
    try:
        written = run(args.project, args.secret, paths, subjects)
    except FetchError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps({"written": written}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
