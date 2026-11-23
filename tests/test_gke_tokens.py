import base64
import json
import os
import sys
import time
import urllib.parse
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
SUBJECTS = {
    "effector": "system:serviceaccount:bailiff-system:effector",
    "audit": "system:serviceaccount:bailiff-system:effector-audit",
}


def jwt(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"e30.{payload}.sig"


def account_token(account, lifetime=600, issued=None, namespace="bailiff-system"):
    issued = int(time.time()) if issued is None else issued
    return jwt({"sub": f"system:serviceaccount:{namespace}:{account}", "iat": issued, "exp": issued + lifetime})


def version(number):
    return f"{SECRET}/versions/{number}"


class Cloud:
    def __init__(self, tokens=None, enabled=(1, 2), page_size=100):
        self.calls = []
        self.tokens = tokens or {}
        self.enabled = set(enabled)
        self.next = max(enabled, default=0) + 1
        self.page_size = page_size
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
            number, self.next = self.next, self.next + 1
            self.enabled.add(number)
            return 200, json.dumps({"name": version(number)}).encode()
        if "/versions?" in url:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            start = int(query.get("pageToken", ["0"])[0])
            listed = sorted(self.enabled, reverse=True)
            page = listed[start : start + self.page_size]
            answer = {"versions": [{"name": version(number)} for number in page]}
            if start + self.page_size < len(listed):
                answer["nextPageToken"] = str(start + self.page_size)
            return 200, json.dumps(answer).encode()
        if url.endswith(":destroy"):
            self.enabled.discard(int(url.rsplit("/", 1)[1].removesuffix(":destroy")))
            return 200, b"{}"
        raise AssertionError(url)

    def destroyed(self):
        return [url for _, url, _, _ in self.calls if url.endswith(":destroy")]


def test_the_minter_publishes_both_tokens_and_destroys_every_older_version():
    cloud = Cloud()
    result = minter.run(ENVIRON, cloud)
    assert result == {"version": version(3), "destroyed": 2}
    [published] = cloud.added
    assert sorted(published) == ["audit", "effector"]
    assert minter.claims(published["audit"])["sub"] == SUBJECTS["audit"]
    assert cloud.destroyed() == [
        f"{minter.SECRET_MANAGER}/{version(1)}:destroy",
        f"{minter.SECRET_MANAGER}/{version(2)}:destroy",
    ]
    assert cloud.enabled == {3}


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


def test_an_older_run_finishing_late_never_destroys_a_newer_version():
    cloud = Cloud(enabled=(1, 5))
    assert minter.destroy_older(cloud, "google-token", SECRET, version(3)) == [version(1)]
    assert cloud.enabled == {5}


def test_two_overlapping_runs_leave_the_newest_version_enabled():
    cloud = Cloud(enabled=(1,))
    first = minter.publish(cloud, "google-token", SECRET, b"{}")
    second = minter.publish(cloud, "google-token", SECRET, b"{}")
    minter.destroy_older(cloud, "google-token", SECRET, second)
    minter.destroy_older(cloud, "google-token", SECRET, first)
    assert cloud.enabled == {3}


def test_the_minter_destroys_older_versions_on_every_page():
    cloud = Cloud(enabled=range(1, 8), page_size=3)
    result = minter.run(ENVIRON, cloud)
    assert result["destroyed"] == 7
    assert cloud.enabled == {8}


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
    assert cloud.destroyed() == []


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


def fetch(token_dir, source):
    return fetch_tokens.run("demo", "bailiff-tokens", token_dir, SUBJECTS, source)


def test_the_fetcher_writes_both_tokens_as_owner_only_files(token_dir):
    source = secret()
    assert fetch(token_dir, source) == ["effector", "audit"]
    expected = json.loads(source("demo", "bailiff-tokens"))
    for field, path in token_dir.items():
        assert path.read_text() == expected[field]
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert sorted(p.name for p in token_dir["effector"].parent.iterdir()) == ["audit.token", "effector.token"]


def test_the_fetcher_leaves_unchanged_tokens_alone(token_dir):
    source = secret()
    fetch(token_dir, source)
    inode = os.stat(token_dir["effector"]).st_ino
    assert fetch(token_dir, source) == []
    assert os.stat(token_dir["effector"]).st_ino == inode


def test_the_fetcher_replaces_a_token_with_a_new_file(token_dir):
    fetch(token_dir, secret())
    newer = account_token("effector", issued=int(time.time()) + 1)
    assert fetch(token_dir, secret(effector=newer)) == ["effector"]
    assert token_dir["effector"].read_text() == newer


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (lambda project, name: b"not json", "not JSON"),
        (secret(extra="x"), "exactly effector, audit"),
        (secret(audit=account_token("effector-audit", lifetime=3600)), "does not live at most 600 s"),
        (secret(effector=account_token("effector", issued=int(time.time()) - 560)), "expires within 60 s"),
        (secret(effector=account_token("effector-audit"), audit=account_token("effector")), "names"),
        (secret(effector=account_token("default")), "names 'system:serviceaccount:bailiff-system:default'"),
        (secret(effector=account_token("effector", issued=int(time.time()) + 100000)), "issued in the future"),
        (secret(effector=account_token("effector") + "é"), "not an ASCII JWT"),
        (secret(effector="a.b"), "not an ASCII JWT"),
    ],
)
def test_the_fetcher_writes_nothing_from_a_bad_secret(token_dir, source, message):
    with pytest.raises(fetch_tokens.FetchError, match=message):
        fetch(token_dir, source)
    assert list(token_dir["effector"].parent.iterdir()) == []


def test_the_fetcher_refuses_an_existing_token_file_with_loose_mode(token_dir):
    token_dir["effector"].write_text("old")
    token_dir["effector"].chmod(0o644)
    with pytest.raises(fetch_tokens.FetchError, match="must have mode 0o600"):
        fetch(token_dir, secret())
    assert token_dir["effector"].read_text() == "old"


def test_the_fetcher_refuses_a_directory_others_can_write(token_dir):
    token_dir["effector"].parent.chmod(0o777)
    with pytest.raises(fetch_tokens.FetchError, match="not writable by group or others"):
        fetch(token_dir, secret())
    assert list(token_dir["effector"].parent.iterdir()) == []


def test_the_fetcher_leaves_no_temporary_file_when_the_replace_fails(token_dir, monkeypatch):
    def fail(source, target):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(fetch_tokens.os, "replace", fail)
    with pytest.raises(fetch_tokens.FetchError, match="No space left"):
        fetch(token_dir, secret())
    assert list(token_dir["effector"].parent.iterdir()) == []


def test_the_fetcher_reports_a_missing_gcloud_as_a_fetch_error(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("gcloud")

    monkeypatch.setattr(fetch_tokens.subprocess, "run", missing)
    with pytest.raises(fetch_tokens.FetchError, match="gcloud could not run: FileNotFoundError"):
        fetch_tokens.fetch_secret("demo", "bailiff-tokens")
