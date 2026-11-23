import base64
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deploy" / "gke"))
import fetch_tokens  # noqa: E402
import mint_tokens as minter  # noqa: E402

SECRET = "projects/demo/secrets/bailiff-tokens"
ENVIRON = {
    "BAILIFF_CLUSTER_HOST": "gke-abc-123.europe-west1.gke.goog",
    "BAILIFF_NAMESPACE": "bailiff-system",
    "BAILIFF_EFFECTOR_ACCOUNT": "effector",
    "BAILIFF_AUDIT_ACCOUNT": "effector-audit",
    "BAILIFF_SECRET": SECRET,
}


def jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"e30.{payload}.sig"


def account_token(account, lifetime=600, issued=None, namespace="bailiff-system"):
    issued = int(time.time()) if issued is None else issued
    return jwt({"sub": f"system:serviceaccount:{namespace}:{account}", "iat": issued, "exp": issued + lifetime})


class Cloud:
    def __init__(self, tokens=None, versions=("v1", "v2")):
        self.calls = []
        self.tokens = tokens or {}
        self.versions = list(versions)
        self.added = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        if url == minter.METADATA_TOKEN:
            return 200, json.dumps({"access_token": "google-token"}).encode()
        if "/serviceaccounts/" in url:
            account = url.split("/serviceaccounts/")[1].split("/")[0]
            token = self.tokens.get(account, account_token(account))
            return 201, json.dumps({"status": {"token": token}}).encode()
        if url.endswith(":addVersion"):
            self.added.append(json.loads(base64.b64decode(json.loads(body)["payload"]["data"])))
            self.versions.append("v3")
            return 200, json.dumps({"name": f"{SECRET}/versions/v3"}).encode()
        if "/versions?" in url:
            return 200, json.dumps({"versions": [{"name": f"{SECRET}/versions/{v}"} for v in self.versions]}).encode()
        if url.endswith(":destroy"):
            return 200, b"{}"
        raise AssertionError(url)


def test_the_minter_publishes_both_tokens_and_destroys_every_older_version():
    cloud = Cloud()
    result = minter.run(ENVIRON, cloud)
    assert result == {"version": f"{SECRET}/versions/v3", "destroyed": 2}
    [published] = cloud.added
    assert sorted(published) == ["audit", "effector"]
    assert minter.claims(published["audit"])["sub"] == "system:serviceaccount:bailiff-system:effector-audit"
    destroyed = [url for method, url, _, _ in cloud.calls if url.endswith(":destroy")]
    assert destroyed == [
        f"{minter.SECRET_MANAGER}/{SECRET}/versions/v1:destroy",
        f"{minter.SECRET_MANAGER}/{SECRET}/versions/v2:destroy",
    ]


def test_the_minter_asks_for_ten_minute_tokens_with_the_google_identity():
    cloud = Cloud()
    minter.run(ENVIRON, cloud)
    requests = [call for call in cloud.calls if "/serviceaccounts/" in call[1]]
    assert [url for _, url, _, _ in requests] == [
        "https://gke-abc-123.europe-west1.gke.goog/api/v1/namespaces/bailiff-system/serviceaccounts/effector/token",
        "https://gke-abc-123.europe-west1.gke.goog/api/v1/namespaces/bailiff-system/serviceaccounts/effector-audit/token",
    ]
    for _, _, headers, body in requests:
        assert headers["Authorization"] == "Bearer google-token"
        assert json.loads(body)["spec"] == {"expirationSeconds": 600}


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (account_token("effector", lifetime=3600), "does not live at most 600 s"),
        (account_token("other"), "names 'system:serviceaccount:bailiff-system:other'"),
        ("not-a-jwt", "not a JWT"),
    ],
)
def test_the_minter_publishes_nothing_when_a_minted_token_is_wrong(token, message):
    cloud = Cloud(tokens={"effector": token})
    with pytest.raises(minter.MintError, match=message):
        minter.run(ENVIRON, cloud)
    assert cloud.added == []


def test_the_minter_keeps_older_versions_when_publishing_fails():
    cloud = Cloud()

    def failing(method, url, headers, body):
        if url.endswith(":addVersion"):
            cloud.calls.append((method, url, headers, body))
            return 403, b"{}"
        return cloud(method, url, headers, body)

    with pytest.raises(minter.MintError, match="answered 403"):
        minter.run(ENVIRON, failing)
    assert not [url for _, url, _, _ in cloud.calls if url.endswith(":destroy")]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("BAILIFF_CLUSTER_HOST", "evil.example.com"),
        ("BAILIFF_NAMESPACE", "../kube-system"),
        ("BAILIFF_SECRET", "projects/demo/secrets/x/versions/1"),
        ("BAILIFF_EFFECTOR_ACCOUNT", ""),
    ],
)
def test_the_minter_refuses_settings_outside_their_shape(key, value):
    cloud = Cloud()
    with pytest.raises(minter.MintError, match=key):
        minter.run(ENVIRON | {key: value}, cloud)
    assert cloud.calls == []


@pytest.fixture
def token_dir(tmp_path):
    directory = tmp_path / "tokens"
    directory.mkdir(mode=0o700)
    return {"effector": directory / "effector.token", "audit": directory / "audit.token"}


def secret(effector=None, audit=None, **extra):
    content = {"effector": effector or account_token("effector"), "audit": audit or account_token("effector-audit")}
    return lambda project, name: json.dumps(content | extra).encode()


def test_the_fetcher_writes_both_tokens_as_owner_only_files(token_dir):
    fetch = secret()
    assert fetch_tokens.run("demo", "bailiff-tokens", token_dir, fetch) == ["effector", "audit"]
    expected = json.loads(fetch("demo", "bailiff-tokens"))
    for field, path in token_dir.items():
        assert path.read_text() == expected[field]
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert sorted(p.name for p in token_dir["effector"].parent.iterdir()) == ["audit.token", "effector.token"]


def test_the_fetcher_leaves_unchanged_tokens_alone(token_dir):
    fetch = secret()
    fetch_tokens.run("demo", "bailiff-tokens", token_dir, fetch)
    inode = os.stat(token_dir["effector"]).st_ino
    assert fetch_tokens.run("demo", "bailiff-tokens", token_dir, fetch) == []
    assert os.stat(token_dir["effector"]).st_ino == inode


def test_the_fetcher_replaces_a_token_with_a_new_file(token_dir):
    fetch_tokens.run("demo", "bailiff-tokens", token_dir, secret())
    newer = account_token("effector", issued=int(time.time()) + 1)
    assert fetch_tokens.run("demo", "bailiff-tokens", token_dir, secret(effector=newer)) == ["effector"]
    assert token_dir["effector"].read_text() == newer


@pytest.mark.parametrize(
    ("fetch", "message"),
    [
        (lambda project, name: b"not json", "not JSON"),
        (secret(extra="x"), "exactly effector, audit"),
        (secret(audit=account_token("effector-audit", lifetime=3600)), "does not live at most 600 s"),
        (secret(effector=account_token("effector", issued=int(time.time()) - 560)), "expires within 60 s"),
    ],
)
def test_the_fetcher_writes_nothing_from_a_bad_secret(token_dir, fetch, message):
    with pytest.raises(fetch_tokens.FetchError, match=message):
        fetch_tokens.run("demo", "bailiff-tokens", token_dir, fetch)
    assert not any(path.exists() for path in token_dir.values())


def test_the_fetcher_refuses_an_existing_token_file_with_loose_mode(token_dir):
    token_dir["effector"].write_text("old")
    token_dir["effector"].chmod(0o644)
    with pytest.raises(fetch_tokens.FetchError, match="must have mode 0o600"):
        fetch_tokens.run("demo", "bailiff-tokens", token_dir, secret())
    assert token_dir["effector"].read_text() == "old"
