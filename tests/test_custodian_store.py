import base64
import dataclasses
import logging
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_bailiff.custodian import (
    BackendError,
    CredentialStore,
    CredentialUnavailable,
    LocalBackend,
    OwnedFileError,
    credential_context,
    files,
)
from agent_bailiff.custodian.files import create_owned
from agent_bailiff.custodian.store import (
    ADD_EXCEPTION,
    CredentialCheck,
    CredentialProblem,
    StoredCredential,
    UnredactableCredential,
    _add_exception_column,
    decode_exceptions,
    encode_exceptions,
)

SECRET = b"Bearer deploy-secret-value"
SHORT = b"Bearer short-key"
BINDING = ("tenant-a", "deploy-api", "deploy.example")
OLD_SCHEMA = """
CREATE TABLE credentials (
    tenant TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    target TEXT NOT NULL,
    wrapped_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (tenant, credential_id, target)
);
"""


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
    assert store.get("tenant-a", "deploy-api", "deploy.example") == StoredCredential(SECRET, frozenset())
    assert SECRET not in (state / "credentials.db").read_bytes()
    assert stat.S_IMODE(os.lstat(state / "credentials.db").st_mode) == 0o600


def test_put_replaces_a_credential(store):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    store.put("tenant-a", "deploy-api", "deploy.example", b"Bearer rotated-secret")
    assert store.get("tenant-a", "deploy-api", "deploy.example").secret == b"Bearer rotated-secret"


def test_reopened_store_decrypts_with_the_loaded_kek(state, store):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    reopened = CredentialStore.open(state / "credentials.db", LocalBackend.load(state / "kek"))
    try:
        assert reopened.get("tenant-a", "deploy-api", "deploy.example").secret == SECRET
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
    connection.execute(
        "INSERT INTO credentials SELECT ?, ?, ?, wrapped_dek, nonce, ciphertext, exception FROM credentials", moved
    )
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


def replace_with_another_store(path, backend):
    CredentialStore.create(path.parent / "other.db", backend).close()
    os.replace(path.parent / "other.db", path)


@pytest.mark.parametrize(
    "tamper",
    [
        lambda path, backend: os.chmod(path, 0o644),
        lambda path, backend: os.link(path, path.parent / "credentials-copy.db"),
        replace_with_another_store,
    ],
)
def test_store_changed_after_open_is_refused(state, store, backend, tamper):
    store.put("tenant-a", "deploy-api", "deploy.example", SECRET)
    tamper(state / "credentials.db", backend)
    with pytest.raises(CredentialUnavailable, match="unreadable"):
        store.get("tenant-a", "deploy-api", "deploy.example")


def test_a_short_write_under_a_file_size_limit_leaves_no_kek(state):
    script = (
        "import resource, signal, sys\n"
        "from pathlib import Path\n"
        "from agent_bailiff.custodian.files import OwnedFileError, create_owned\n"
        "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
        "resource.setrlimit(resource.RLIMIT_FSIZE, (10, 10))\n"
        "try:\n"
        "    create_owned(Path(sys.argv[1]), 'kek', b'k' * 32)\n"
        "except OwnedFileError as exc:\n"
        "    print(exc)\n"
        "    sys.exit(3)\n"
    )
    done = subprocess.run([sys.executable, "-c", script, str(state / "kek")], capture_output=True, text=True)
    assert done.returncode == 3, done.stdout + done.stderr
    assert "cannot write the kek" in done.stdout
    assert not (state / "kek").exists()


FILE_SIZE_LIMIT = (
    "import os, resource, signal, sys\n"
    "from pathlib import Path\n"
    "from agent_bailiff.custodian import CredentialStore, LocalBackend, OwnedFileError\n"
    "path = Path(sys.argv[1])\n"
    "backend = LocalBackend.load(path.parent / 'kek')\n"
    "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
    "limit = int(sys.argv[2]) if len(sys.argv) > 2 else os.path.getsize(path)\n"
    "resource.setrlimit(resource.RLIMIT_FSIZE, (limit, resource.RLIM_INFINITY))\n"
)


def test_a_put_the_disk_cannot_hold_names_the_store_and_keeps_what_was_stored(state, store):
    store.put(*BINDING, SECRET)
    script = FILE_SIZE_LIMIT + (
        "store = CredentialStore.open(path, backend)\n"
        "refused = 0\n"
        "for credential_id in ('deploy-api', 'other-api'):\n"
        "    try:\n"
        "        store.put('tenant-a', credential_id, 'deploy.example', b'Bearer grown-' + b'g' * 20000)\n"
        "    except OwnedFileError as exc:\n"
        "        print(exc)\n"
        "        refused += 1\n"
        "sys.exit(3 if refused == 2 else 4)\n"
    )
    path = state / "credentials.db"
    done = subprocess.run(
        [sys.executable, "-c", script, str(path)], capture_output=True, text=True, timeout=30, check=False
    )
    output = done.stdout + done.stderr
    assert done.returncode == 3, output
    assert output.count(f"cannot write the credential store at {path}: its storage failed (SQLITE_IOERR_WRITE)") == 2
    assert "Traceback" not in output and "grown-" not in output
    reopened = CredentialStore.open(path, LocalBackend.load(state / "kek"))
    try:
        assert reopened.get(*BINDING) == StoredCredential(SECRET, frozenset())
        with pytest.raises(CredentialUnavailable, match="no credential"):
            reopened.get("tenant-a", "other-api", "deploy.example")
    finally:
        reopened.close()


def test_a_migration_the_disk_cannot_hold_names_the_store_and_leaves_it_unmigrated(state, backend):
    path = state / "legacy.db"
    legacy_store(path, backend, SECRET)
    connection = sqlite3.connect(path)
    try:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    finally:
        connection.close()
    assert os.path.getsize(path) > page_size
    script = FILE_SIZE_LIMIT + (
        "try:\n"
        "    CredentialStore.open(path, backend)\n"
        "except OwnedFileError as exc:\n"
        "    print(exc)\n"
        "    sys.exit(3)\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script, str(path), str(page_size)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 3, done.stdout + done.stderr
    assert done.stdout == f"cannot open the credential store at {path}: its storage failed (SQLITE_IOERR_WRITE)\n"
    connection = sqlite3.connect(path)
    try:
        assert "exception" not in {row[1] for row in connection.execute("PRAGMA table_info(credentials)")}
    finally:
        connection.close()
    store = CredentialStore.open(path, backend)
    try:
        assert store.get(*BINDING) == StoredCredential(SECRET, frozenset())
    finally:
        store.close()


def test_a_refused_write_does_not_echo_the_values_it_was_given(state, store):
    path = state / "credentials.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TRIGGER echo BEFORE INSERT ON credentials BEGIN "
        "SELECT RAISE(ABORT, NEW.tenant || ':' || hex(NEW.ciphertext) || ':' || hex(NEW.wrapped_dek)); END"
    )
    connection.commit()
    connection.close()
    with pytest.raises(OwnedFileError) as raised:
        store.put("tenant-leak-marker", "deploy-api", "deploy.example", SECRET)
    message = str(raised.value)
    assert (
        message == f"cannot write the credential store at {path}: the database refused it (SQLITE_CONSTRAINT_TRIGGER)"
    )
    assert "tenant-leak-marker" not in message


def test_a_busy_older_store_is_refused_as_busy(state, backend, monkeypatch):
    path = state / "legacy.db"
    legacy_store(path, backend, SECRET)
    monkeypatch.setattr(files, "BUSY_TIMEOUT_SECONDS", 0)
    writer = sqlite3.connect(path, isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(OwnedFileError) as raised:
            CredentialStore.open(path, backend)
    finally:
        writer.execute("ROLLBACK")
        writer.close()
    assert str(raised.value) == f"cannot open the credential store at {path}: it is busy (SQLITE_BUSY)"


class RollbackFails:
    in_transaction = True

    def execute(self, sql):
        if sql == ADD_EXCEPTION:
            raise sqlite3.OperationalError("disk I/O error")
        if sql == "ROLLBACK":
            raise sqlite3.OperationalError("cannot rollback")
        return iter(())


def test_a_failed_rollback_keeps_the_migration_error():
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error") as raised:
        _add_exception_column(RollbackFails())
    assert any("rollback also failed" in note for note in raised.value.__notes__)


def test_opening_a_file_that_is_not_a_database_names_the_store(state, backend):
    path = state / "garbage.db"
    create_owned(path, "credential store", b"not a database " * 512)
    with pytest.raises(OwnedFileError) as raised:
        CredentialStore.open(path, backend)
    assert (
        str(raised.value) == f"cannot open the credential store at {path}: it is not a usable database (SQLITE_NOTADB)"
    )


def test_a_put_on_a_closed_store_is_a_programming_error(state, backend):
    store = CredentialStore.create(state / "credentials.db", backend)
    store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        store.put(*BINDING, SECRET)


def basic(pair):
    return b"Basic " + base64.b64encode(pair)


@pytest.mark.parametrize(
    "secret",
    [
        b"short-key",
        SHORT,
        basic(b"deploy-user:shortpw"),
        basic(b"deploy-user:\xff\xfe-not-utf-8-password"),
        basic(b"deploy-user-without-a-separator"),
        b"Basic not-base64-at-all!",
    ],
)
def test_put_refuses_a_credential_echo_redaction_cannot_cover(store, secret):
    with pytest.raises(ValueError, match="cannot be redacted from results"):
        store.put(*BINDING, secret)
    with pytest.raises(CredentialUnavailable, match="no credential"):
        store.get(*BINDING)


@pytest.mark.parametrize(
    "secret", [b"Bearer caf\xc3\xa9-secret-value", b" Bearer deploy-secret", b"Bearer deploy\nsecret"]
)
def test_put_refuses_a_secret_that_is_not_a_header_value(store, secret):
    with pytest.raises(ValueError, match="printable ASCII"):
        store.put(*BINDING, secret)
    with pytest.raises(CredentialUnavailable, match="no credential"):
        store.get(*BINDING)


def test_put_names_the_problem_without_the_credential(store):
    with pytest.raises(UnredactableCredential) as raised:
        store.put(*BINDING, basic(b"deploy-user:\xff\xfe-not-utf-8-password"))
    assert str(raised.value) == (
        "credential cannot be redacted from results: its basic token is not base64 of a UTF-8 user:password"
    )
    with pytest.raises(UnredactableCredential) as raised:
        store.put(*BINDING, SHORT)
    assert "shorter than 12 characters" in str(raised.value) and "short-key" not in str(raised.value)


def test_an_accepted_exception_is_stored_with_the_credential_and_logged(state, store, caplog):
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.store"):
        store.put(*BINDING, SHORT, accept_unredactable=True)
    assert store.get(*BINDING) == StoredCredential(SHORT, frozenset({"unredactable"}))
    assert "'deploy-api'" in caplog.text and "unredactable exception" in caplog.text
    assert "short-key" not in caplog.text
    connection = sqlite3.connect(state / "credentials.db")
    try:
        assert connection.execute("SELECT exception FROM credentials").fetchall() == [("unredactable",)]
    finally:
        connection.close()


def test_an_accepted_broader_exception_is_stored_with_the_credential_and_logged(state, store, caplog):
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.store"):
        store.put(*BINDING, SECRET, accept_broader=True)
    assert store.get(*BINDING) == StoredCredential(SECRET, frozenset({"broader"}))
    assert "'deploy-api'" in caplog.text and "accepted broader exception" in caplog.text
    assert "deploy-secret-value" not in caplog.text
    connection = sqlite3.connect(state / "credentials.db")
    try:
        assert connection.execute("SELECT exception FROM credentials").fetchall() == [("broader",)]
    finally:
        connection.close()


def test_both_exceptions_are_stored_as_one_sorted_value(state, store):
    store.put(*BINDING, SHORT, accept_unredactable=True, accept_broader=True)
    assert store.get(*BINDING) == StoredCredential(SHORT, frozenset({"broader", "unredactable"}))
    assert store.check() == CredentialCheck(1, ())
    connection = sqlite3.connect(state / "credentials.db")
    try:
        assert connection.execute("SELECT exception FROM credentials").fetchall() == [("broader,unredactable",)]
    finally:
        connection.close()


def test_storing_again_without_broader_clears_it(store):
    store.put(*BINDING, SECRET, accept_broader=True)
    store.put(*BINDING, SECRET)
    assert store.get(*BINDING) == StoredCredential(SECRET, frozenset())


def test_a_broader_exception_alone_does_not_pass_an_unredactable_credential(state, store, backend):
    insert_unchecked(state / "credentials.db", backend, BINDING, SHORT, "broader")
    [problem] = store.check().problems
    assert "has no accepted exception" in problem.problem


def test_an_exception_for_a_credential_that_can_be_redacted_is_refused(store):
    with pytest.raises(ValueError, match="can be redacted"):
        store.put(*BINDING, SECRET, accept_unredactable=True)
    with pytest.raises(CredentialUnavailable, match="no credential"):
        store.get(*BINDING)


def test_storing_again_without_the_exception_clears_it(store):
    store.put(*BINDING, SHORT, accept_unredactable=True)
    store.put(*BINDING, SECRET)
    assert store.get(*BINDING) == StoredCredential(SECRET, frozenset())


@pytest.mark.parametrize(
    ("secret", "accept", "exception"),
    [
        (SECRET, False, "unredactable"),
        (SHORT, True, None),
        (SHORT, True, "another"),
        (SHORT, True, "unredactable,unredactable"),
        (SHORT, True, ""),
    ],
)
def test_an_exception_changed_in_the_file_does_not_decrypt(state, store, secret, accept, exception):
    store.put(*BINDING, secret, accept_unredactable=accept)
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute("UPDATE credentials SET exception = ?", (exception,))
    connection.commit()
    connection.close()
    with pytest.raises(CredentialUnavailable, match="does not decrypt"):
        store.get(*BINDING)


EARLIER_CONTEXTS = {
    None: b'{"credential_id":"deploy-api","target":"deploy.example","tenant":"tenant-a"}',
    "unredactable": b'{"credential_id":"deploy-api","exception":"unredactable",'
    b'"target":"deploy.example","tenant":"tenant-a"}',
}


def test_exceptions_encode_as_a_sorted_comma_joined_set():
    assert encode_exceptions(frozenset()) is None
    assert encode_exceptions(frozenset({"unredactable"})) == "unredactable"
    assert decode_exceptions(None) == frozenset()
    assert decode_exceptions("unredactable") == frozenset({"unredactable"})
    both = frozenset({"unredactable", "broader"})
    assert encode_exceptions(both) == "broader,unredactable"
    assert decode_exceptions("broader,unredactable") == both


@pytest.mark.parametrize(
    "value",
    [
        "",
        "unknown",
        "Unredactable",
        "unredactable,unredactable",
        "unredactable,",
        ",unredactable",
        " unredactable",
        b"x",
        "unredactable,broader",
        "broader,broader",
    ],
)
def test_a_value_that_is_not_a_canonical_exception_set_is_refused(value):
    with pytest.raises(ValueError, match="credential exceptions"):
        decode_exceptions(value)


@pytest.mark.parametrize("exceptions", [frozenset({"unknown"}), {"unredactable"}, ("unredactable",)])
def test_only_a_frozenset_of_known_exceptions_encodes(exceptions):
    with pytest.raises(ValueError, match="credential exception"):
        encode_exceptions(exceptions)


@pytest.mark.parametrize("exception", [None, "unredactable"])
def test_a_context_with_at_most_one_exception_is_the_earlier_bytes(exception):
    assert credential_context(*BINDING, decode_exceptions(exception)) == EARLIER_CONTEXTS[exception]


@pytest.mark.parametrize(("secret", "exception"), [(SECRET, None), (SHORT, "unredactable")])
def test_a_row_written_under_the_earlier_context_decrypts(state, store, backend, secret, exception):
    context = EARLIER_CONTEXTS[exception]
    dek = os.urandom(32)
    nonce = os.urandom(12)
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute(
        "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?)",
        (*BINDING, backend.wrap(dek, context), nonce, AESGCM(dek).encrypt(nonce, secret, context), exception),
    )
    connection.commit()
    connection.close()
    assert store.get(*BINDING) == StoredCredential(secret, decode_exceptions(exception))
    assert store.check() == CredentialCheck(1, ())


def legacy_store(path, backend, secret):
    create_owned(path, "credential store", b"")
    connection = sqlite3.connect(path)
    connection.executescript(OLD_SCHEMA)
    context = credential_context(*BINDING)
    dek = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, secret, context)
    connection.execute(
        "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?)", (*BINDING, backend.wrap(dek, context), nonce, ciphertext)
    )
    connection.commit()
    connection.close()


def test_opening_an_older_store_adds_the_exception_column_and_keeps_its_credentials(state, backend):
    path = state / "legacy.db"
    legacy_store(path, backend, SHORT)
    store = CredentialStore.open(path, backend)
    try:
        assert store.get(*BINDING) == StoredCredential(SHORT, frozenset())
    finally:
        store.close()
    connection = sqlite3.connect(path)
    try:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(credentials)")]
    finally:
        connection.close()
    assert columns[-1] == "exception"
    CredentialStore.open(path, backend).close()


def test_opening_a_database_without_the_credentials_table_is_refused(state, backend):
    create_owned(state / "empty.db", "credential store", b"")
    with pytest.raises(OwnedFileError, match="not a usable database"):
        CredentialStore.open(state / "empty.db", backend)


def test_opening_a_migrated_store_does_not_wait_for_a_writer(state, store, backend, monkeypatch):
    store.put(*BINDING, SECRET)
    monkeypatch.setattr(files, "BUSY_TIMEOUT_SECONDS", 0)
    writer = sqlite3.connect(state / "credentials.db", isolation_level=None)
    writer.execute("BEGIN IMMEDIATE")
    try:
        reopened = CredentialStore.open(state / "credentials.db", backend)
        reopened.close()
    finally:
        writer.execute("ROLLBACK")
        writer.close()


def test_concurrent_opens_of_an_older_store_add_the_column_once(state, backend):
    path = state / "legacy.db"
    legacy_store(path, backend, SECRET)
    barrier = threading.Barrier(8)

    def open_store():
        barrier.wait()
        CredentialStore.open(path, backend).close()

    with ThreadPoolExecutor(8) as pool:
        for future in [pool.submit(open_store) for _ in range(8)]:
            future.result()
    connection = sqlite3.connect(path)
    try:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(credentials)")]
    finally:
        connection.close()
    assert columns.count("exception") == 1
    store = CredentialStore.open(path, backend)
    try:
        assert store.get(*BINDING) == StoredCredential(SECRET, frozenset())
    finally:
        store.close()


def insert_unchecked(path, backend, binding, secret, exception=None):
    context = credential_context(*binding, decode_exceptions(exception))
    dek = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, secret, context)
    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?)",
        (*binding, backend.wrap(dek, context), nonce, ciphertext, exception),
    )
    connection.commit()
    connection.close()


def test_check_of_an_empty_store_finds_nothing(store):
    assert store.check() == CredentialCheck(0, ())


def test_check_passes_redactable_credentials_and_accepted_exceptions(store):
    store.put(*BINDING, SECRET)
    store.put("tenant-a", "short-api", "deploy.example", SHORT, accept_unredactable=True)
    assert store.check() == CredentialCheck(2, ())


@pytest.mark.parametrize(
    ("secret", "problem"),
    [
        (SHORT, "shorter than 12 characters"),
        (basic(b"deploy-user:shortpw"), "shorter than 12 characters"),
        (basic(b"deploy-user:\xff\xfe-not-utf-8-password"), "not base64 of a UTF-8 user:password"),
        (b"Bearer caf\xc3\xa9-secret-value", "not printable ASCII"),
        (b" Bearer deploy-secret-value", "not printable ASCII"),
    ],
)
def test_check_reports_a_credential_release_would_refuse(state, store, backend, secret, problem):
    insert_unchecked(state / "credentials.db", backend, BINDING, secret)
    check = store.check()
    assert check.checked == 1
    assert [(found.tenant, found.credential_id, found.target) for found in check.problems] == [BINDING]
    assert problem in check.problems[0].problem
    assert secret.decode("latin-1").strip() not in check.problems[0].problem


def test_check_reports_a_credential_that_does_not_decrypt(state, store):
    store.put(*BINDING, SECRET)
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute("UPDATE credentials SET exception = 'unredactable'")
    connection.commit()
    connection.close()
    assert store.check() == CredentialCheck(
        1, (CredentialProblem(*BINDING, "credential does not decrypt under its binding"),)
    )


def test_check_reports_every_failing_credential_in_order(state, store, backend):
    store.put(*BINDING, SECRET)
    insert_unchecked(state / "credentials.db", backend, ("tenant-b", "z-api", "deploy.example"), SHORT)
    insert_unchecked(state / "credentials.db", backend, ("tenant-a", "a-api", "deploy.example"), SHORT)
    check = store.check()
    assert check.checked == 3
    assert [found.tenant + "/" + found.credential_id for found in check.problems] == [
        "tenant-a/a-api",
        "tenant-b/z-api",
    ]


def test_check_of_a_legacy_store_reports_its_unchecked_credentials(state, backend):
    path = state / "legacy.db"
    legacy_store(path, backend, SHORT)
    store = CredentialStore.open(path, backend)
    try:
        check = store.check()
    finally:
        store.close()
    assert check.checked == 1 and "shorter than 12 characters" in check.problems[0].problem


def test_check_of_a_store_changed_after_open_is_refused(state, store, backend):
    store.put(*BINDING, SECRET)
    replace_with_another_store(state / "credentials.db", backend)
    with pytest.raises(CredentialUnavailable, match="unreadable"):
        store.check()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("tenant", b"tenant-a"),
        ("nonce", "not-bytes"),
        ("nonce", 7),
        ("ciphertext", "not-bytes"),
        ("wrapped_dek", 7),
    ],
)
def test_check_reports_a_malformed_row_without_stopping(state, store, column, value):
    store.put(*BINDING, SECRET)
    store.put("tenant-a", "other-api", "deploy.example", SECRET)
    connection = sqlite3.connect(state / "credentials.db")
    connection.execute(f"UPDATE credentials SET {column} = ? WHERE credential_id = 'deploy-api'", (value,))
    connection.commit()
    connection.close()
    check = store.check()
    assert check.checked == 2
    assert [found.problem for found in check.problems] == ["credential row is malformed"]
    assert all(isinstance(field, str) for field in dataclasses.astuple(check.problems[0]))


def test_check_reports_a_required_binding_with_no_stored_credential(store):
    store.put(*BINDING, SECRET)
    missing = ("tenant-b", "deploy-api", "deploy.example")
    assert store.check({BINDING, missing}) == CredentialCheck(
        1, (CredentialProblem(*missing, "no credential is stored for this binding"),)
    )
