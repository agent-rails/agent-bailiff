import os
import sqlite3
import stat

import pytest

from agent_bailiff.custodian import (
    BackendError,
    CredentialStore,
    CredentialUnavailable,
    LocalBackend,
    OwnedFileError,
    credential_context,
)

SECRET = b"Bearer deploy-secret-value"


@pytest.fixture
def state(tmp_path):
    directory = tmp_path / "custodian"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


@pytest.fixture
def backend(state):
    return LocalBackend.generate(state / "kek")


@pytest.fixture
def store(state, backend):
    store = CredentialStore.create(state / "credentials.db", backend)
    yield store
    store.close()


def test_generated_kek_is_32_bytes_mode_0600_and_loads(state):
    path = state / "kek"
    generated = LocalBackend.generate(path)
    info = os.lstat(path)
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_size == 32
    context = credential_context("t", "c", "x")
    assert LocalBackend.load(path).unwrap(generated.wrap(b"k" * 32, context), context) == b"k" * 32


def test_generate_never_replaces_an_existing_kek(state):
    LocalBackend.generate(state / "kek")
    with pytest.raises(OwnedFileError, match="cannot create"):
        LocalBackend.generate(state / "kek")


def test_kek_with_a_loose_mode_is_refused(state):
    LocalBackend.generate(state / "kek")
    os.chmod(state / "kek", 0o640)
    with pytest.raises(OwnedFileError, match="mode"):
        LocalBackend.load(state / "kek")


def test_kek_symlink_is_not_followed(state):
    LocalBackend.generate(state / "real")
    os.symlink(state / "real", state / "kek")
    with pytest.raises(OwnedFileError, match="cannot open"):
        LocalBackend.load(state / "kek")


def test_kek_owned_by_another_uid_is_refused(state, monkeypatch):
    LocalBackend.generate(state / "kek")
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(OwnedFileError, match="owned by uid"):
        LocalBackend.load(state / "kek")


def test_kek_of_the_wrong_length_is_refused(state):
    fd = os.open(state / "kek", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"x" * 31)
    os.close(fd)
    with pytest.raises(BackendError, match="exactly 32 bytes"):
        LocalBackend.load(state / "kek")


def test_kek_with_a_hard_link_is_refused(state):
    LocalBackend.generate(state / "kek")
    os.link(state / "kek", state / "kek-copy")
    with pytest.raises(OwnedFileError, match="hard links"):
        LocalBackend.load(state / "kek")


def test_kek_in_a_group_writable_directory_is_refused(state):
    LocalBackend.generate(state / "kek")
    os.chmod(state, 0o770)
    with pytest.raises(OwnedFileError, match="directory"):
        LocalBackend.load(state / "kek")


def test_unwrap_under_another_context_fails(backend):
    wrapped = backend.wrap(b"k" * 32, credential_context("tenant-a", "deploy-api", "deploy.example"))
    with pytest.raises(BackendError):
        backend.unwrap(wrapped, credential_context("tenant-a", "signer", "deploy.example"))


def test_stored_credential_round_trips_and_is_not_stored_in_plaintext(state, store):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    assert store.get("tenant-a", "deploy-api", "deploy.example") == SECRET
    assert SECRET not in (state / "credentials.db").read_bytes()
    assert stat.S_IMODE(os.lstat(state / "credentials.db").st_mode) == 0o600


def test_put_replaces_a_credential(store):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    store.put("tenant-a", "deploy-api", "deploy.example", b"rotated")
    assert store.get("tenant-a", "deploy-api", "deploy.example") == b"rotated"


def test_reopened_store_decrypts_with_the_loaded_kek(state, store):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    reopened = CredentialStore.open(state / "credentials.db", LocalBackend.load(state / "kek"))
    try:
        assert reopened.get("tenant-a", "deploy-api", "deploy.example") == SECRET
    finally:
        reopened.close()


def test_store_under_another_kek_does_not_decrypt(state, store):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    other = CredentialStore.open(state / "credentials.db", LocalBackend(os.urandom(32)))
    try:
        with pytest.raises(CredentialUnavailable):
            other.get("tenant-a", "deploy-api", "deploy.example")
    finally:
        other.close()


def test_missing_credential_is_unavailable(store):
    with pytest.raises(CredentialUnavailable):
        store.get("tenant-a", "deploy-api", "deploy.example")


@pytest.mark.parametrize(
    "moved",
    [
        ("tenant-b", "deploy-api", "deploy.example"),
        ("tenant-a", "signer", "deploy.example"),
        ("tenant-a", "deploy-api", "other.example"),
    ],
)
def test_row_moved_to_another_binding_fails_its_aad(state, store, moved):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute("INSERT INTO credentials SELECT ?, ?, ?, wrapped_dek, nonce, ciphertext FROM credentials", moved)
    connection.commit()
    connection.close()
    with pytest.raises(CredentialUnavailable, match="does not decrypt"):
        store.get(*moved)


def test_store_with_a_loose_mode_is_refused(state, store, backend):
    os.chmod(state / "credentials.db", 0o644)
    with pytest.raises(OwnedFileError, match="mode"):
        CredentialStore.open(state / "credentials.db", backend)


def test_create_never_replaces_a_store(state, store, backend):
    with pytest.raises(OwnedFileError, match="cannot create"):
        CredentialStore.create(state / "credentials.db", backend)


def test_context_refuses_empty_fields():
    with pytest.raises(ValueError, match="target"):
        credential_context("tenant-a", "deploy-api", "")
