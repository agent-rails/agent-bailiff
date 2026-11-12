import os
import shutil
import tempfile
from pathlib import Path

import pytest
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.custodian.files import OwnedFileError
from agent_bailiff.keys import (
    PublicKeyRecord,
    generate_signing_key,
    key_id,
    load_signing_key,
    parse_pinned_keys,
)

SMALL_ORDER_KEY = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


@pytest.fixture
def directory():
    path = Path(tempfile.mkdtemp(prefix="by-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


def test_a_generated_key_is_private_and_loads_back(directory):
    record = generate_signing_key(directory / "signing.key", "decide")
    info = os.lstat(directory / "signing.key")
    assert (info.st_mode & 0o777, info.st_uid, info.st_size) == (0o600, os.geteuid(), 32)
    key = load_signing_key(directory / "signing.key")
    assert encode_public_key(key.public_key()) == encode_public_key(record.public_key)
    assert record.kid == key_id("decide", key.public_key())
    assert record.component == "decide"


def test_key_ids_name_the_component_and_differ_per_key():
    first = Ed25519PrivateKey.generate().public_key()
    second = Ed25519PrivateKey.generate().public_key()
    assert key_id("decide", first).startswith("decide-")
    assert key_id("decide", first) != key_id("decide", second)
    assert key_id("decide", first) != key_id("custodian", first)
    assert key_id("decide", first) == key_id("decide", first)


def test_generate_never_overwrites_a_key(directory):
    generate_signing_key(directory / "signing.key", "decide")
    before = (directory / "signing.key").read_bytes()
    with pytest.raises(OwnedFileError):
        generate_signing_key(directory / "signing.key", "decide")
    assert (directory / "signing.key").read_bytes() == before


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o400, 0o660])
def test_a_key_file_with_the_wrong_mode_is_refused(directory, mode):
    generate_signing_key(directory / "signing.key", "decide")
    os.chmod(directory / "signing.key", mode)
    with pytest.raises(OwnedFileError):
        load_signing_key(directory / "signing.key")


def test_a_key_file_of_another_uid_is_refused(directory, monkeypatch):
    generate_signing_key(directory / "signing.key", "decide")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(OwnedFileError):
        load_signing_key(directory / "signing.key")


def test_a_key_in_a_group_writable_directory_is_refused(directory):
    generate_signing_key(directory / "signing.key", "decide")
    os.chmod(directory, 0o770)
    with pytest.raises(OwnedFileError):
        load_signing_key(directory / "signing.key")


def test_a_symlinked_key_is_refused(directory):
    generate_signing_key(directory / "signing.key", "decide")
    (directory / "link.key").symlink_to(directory / "signing.key")
    with pytest.raises(OwnedFileError):
        load_signing_key(directory / "link.key")


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_a_key_file_of_the_wrong_length_is_refused(directory, size):
    path = directory / "signing.key"
    path.write_bytes(b"k" * size)
    os.chmod(path, 0o600)
    with pytest.raises((ValueError, OwnedFileError)):
        load_signing_key(path)


def test_a_public_key_record_round_trips(directory):
    record = generate_signing_key(directory / "signing.key", "custodian")
    assert PublicKeyRecord.from_document(record.to_document()) == record


def bad_documents():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    good = {"component": "decide", "kid": key_id("decide", key), "public_key": encode_public_key(key)}
    other = encode_public_key(Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key())
    return {
        "wrong_kid": {**good, "kid": "decide-1"},
        "kid_for_another_key": {**good, "public_key": other},
        "kid_for_another_component": {**good, "component": "custodian"},
        "extra_field": {**good, "note": "x"},
        "missing_field": {key: value for key, value in good.items() if key != "kid"},
        "small_order_key": {**good, "public_key": SMALL_ORDER_KEY},
        "not_base64": {**good, "public_key": "!!"},
        "padded_key": {**good, "public_key": good["public_key"] + "="},
        "number_component": {**good, "component": 1},
        "bad_component": {**good, "component": "de cide"},
        "not_an_object": [good],
    }


@pytest.mark.parametrize("name", sorted(bad_documents()))
def test_a_bad_public_key_record_is_refused(name):
    with pytest.raises(ValueError):
        PublicKeyRecord.from_document(bad_documents()[name])


def test_pinned_keys_parse_and_check_each_kid():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    kid = key_id("decide", key)
    pinned = parse_pinned_keys("decide", {kid: encode_public_key(key)})
    assert list(pinned) == [kid]
    assert encode_public_key(pinned[kid]) == encode_public_key(key)


@pytest.mark.parametrize(
    "document",
    [
        {},
        [],
        {"decide-1": "x"},
        {"decide-0123456789abcdef": SMALL_ORDER_KEY},
        "key",
    ],
)
def test_bad_pinned_keys_are_refused(document):
    with pytest.raises(ValueError):
        parse_pinned_keys("decide", document)


def test_a_pinned_key_under_another_components_kid_is_refused():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    with pytest.raises(ValueError):
        parse_pinned_keys("custodian", {key_id("decide", key): encode_public_key(key)})
