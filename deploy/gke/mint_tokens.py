from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

TOKEN_SECONDS = 600
TIMEOUT_SECONDS = 10
METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
SECRET_MANAGER = "https://secretmanager.googleapis.com/v1"
NAME = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?")
SECRET = re.compile(r"projects/[a-z0-9-]+/secrets/[A-Za-z0-9_-]+")
MAX_PAGES = 10
HOST = re.compile(r"[a-z0-9.-]+\.gke\.goog")

Send = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, bytes]]


class MintError(Exception):
    pass


def send(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def settings(environ: Mapping[str, str]) -> dict[str, str]:
    rules = {
        "BAILIFF_CLUSTER_HOST": HOST,
        "BAILIFF_NAMESPACE": NAME,
        "BAILIFF_EFFECTOR_ACCOUNT": NAME,
        "BAILIFF_AUDIT_ACCOUNT": NAME,
        "BAILIFF_SECRET": SECRET,
    }
    values = {}
    for key, pattern in rules.items():
        value = environ.get(key, "")
        if not pattern.fullmatch(value):
            raise MintError(f"{key} must match {pattern.pattern}, found {value!r}")
        values[key] = value
    return values


def access_token(transport: Send) -> str:
    status, body = transport("GET", METADATA_TOKEN, {"Metadata-Flavor": "Google"}, None)
    if status != 200:
        raise MintError(f"the metadata server answered {status}")
    return str(json.loads(body)["access_token"])


def claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise MintError("the minted token is not a JWT")
    try:
        decoded = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise MintError("the minted token has unreadable claims") from None
    if not isinstance(decoded, dict):
        raise MintError("the minted token has unreadable claims")
    return decoded


def mint(transport: Send, bearer: str, host: str, namespace: str, account: str) -> str:
    path = f"/api/v1/namespaces/{namespace}/serviceaccounts/{account}/token"
    body = json.dumps(
        {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": TOKEN_SECONDS}}
    ).encode()
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json", "Accept": "application/json"}
    status, answer = transport("POST", f"https://{host}{path}", headers, body)
    if status != 201:
        raise MintError(f"the token request for {namespace}/{account} answered {status}")
    token = str(json.loads(answer)["status"]["token"])
    found = claims(token)
    subject = f"system:serviceaccount:{namespace}:{account}"
    if found.get("sub") != subject:
        raise MintError(f"the token for {namespace}/{account} names {found.get('sub')!r}, not {subject}")
    issued, expires = found.get("iat"), found.get("exp")
    if not isinstance(issued, int) or not isinstance(expires, int) or not 0 < expires - issued <= TOKEN_SECONDS:
        raise MintError(f"the token for {namespace}/{account} does not live at most {TOKEN_SECONDS} s")
    return token


def publish(transport: Send, bearer: str, secret: str, payload: bytes) -> str:
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    data = base64.b64encode(payload).decode()
    body = json.dumps({"payload": {"data": data}}).encode()
    status, answer = transport("POST", f"{SECRET_MANAGER}/{secret}:addVersion", headers, body)
    if status != 200:
        raise MintError(f"adding a version to {secret} answered {status}")
    return str(json.loads(answer)["name"])


def version_number(name: str) -> int:
    number = name.rsplit("/", 1)[-1]
    if not number.isdigit():
        raise MintError(f"unexpected version name {name}")
    return int(number)


def destroy_older(transport: Send, bearer: str, secret: str, keep: str) -> list[str]:
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    newest = version_number(keep)
    names = []
    page = ""
    for _ in range(MAX_PAGES):
        query = {"filter": "state:ENABLED OR state:DISABLED", "pageSize": 100} | ({"pageToken": page} if page else {})
        url = f"{SECRET_MANAGER}/{secret}/versions?{urllib.parse.urlencode(query)}"
        status, answer = transport("GET", url, headers, None)
        if status != 200:
            raise MintError(f"listing the versions of {secret} answered {status}")
        listed = json.loads(answer)
        if not isinstance(listed, dict):
            raise MintError(f"listing the versions of {secret} did not answer an object")
        names += [version["name"] for version in listed.get("versions", [])]
        page = listed.get("nextPageToken", "")
        if not page:
            break
    if page:
        raise MintError(f"{secret} has more than {MAX_PAGES} pages of versions")
    destroyed = []
    for name in sorted(names, key=version_number):
        if version_number(name) >= newest:
            continue
        status, _ = transport("POST", f"{SECRET_MANAGER}/{name}:destroy", headers, b"{}")
        if status != 200:
            raise MintError(f"destroying {name} answered {status}")
        destroyed.append(name)
    return destroyed


def run(environ: Mapping[str, str], transport: Send = send) -> dict[str, Any]:
    config = settings(environ)
    bearer = access_token(transport)
    namespace, host = config["BAILIFF_NAMESPACE"], config["BAILIFF_CLUSTER_HOST"]
    tokens = {
        "effector": mint(transport, bearer, host, namespace, config["BAILIFF_EFFECTOR_ACCOUNT"]),
        "audit": mint(transport, bearer, host, namespace, config["BAILIFF_AUDIT_ACCOUNT"]),
    }
    version = publish(transport, bearer, config["BAILIFF_SECRET"], json.dumps(tokens).encode())
    destroyed = destroy_older(transport, bearer, config["BAILIFF_SECRET"], version)
    return {"version": version, "destroyed": len(destroyed)}


def main() -> int:
    try:
        print(json.dumps(run(os.environ)))
    except (MintError, KeyError, ValueError, OSError) as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"[:500]}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
