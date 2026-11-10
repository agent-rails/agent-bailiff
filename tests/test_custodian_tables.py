import json
import os

import pytest

from agent_bailiff.custodian import (
    BindingTable,
    BindingTableError,
    ClaimsStore,
    ClaimsUnavailable,
    CredentialBinding,
    OwnedFileError,
    TaskRateLimiter,
)

NOW = 1_800_000_000
DEPLOY = {
    "tenant": "tenant-a",
    "tool": "deploy.service",
    "resource": "env/staging/*",
    "credential_id": "deploy-api",
    "target": "deploy.example",
    "header_name": "Authorization",
    "canary": False,
}


@pytest.fixture
def state(tmp_path):
    directory = tmp_path / "custodian"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def write_table(path, document, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.write(fd, json.dumps(document).encode())
    os.close(fd)
    os.chmod(path, mode)
    return path


def test_binding_table_loads_and_resolves_one_match(state):
    table = BindingTable.load(write_table(state / "bindings.json", {"bindings": [DEPLOY]}))
    binding = table.resolve("tenant-a", "deploy.service", "env/staging/api")
    assert binding == CredentialBinding(**DEPLOY)


@pytest.mark.parametrize(
    ("tenant", "tool", "resource"),
    [
        ("tenant-b", "deploy.service", "env/staging/api"),
        ("tenant-a", "deploy.delete", "env/staging/api"),
        ("tenant-a", "deploy.service", "env/prod/api"),
        ("tenant-a", "deploy.service", "ENV/staging/api"),
    ],
)
def test_no_match_resolves_to_none(tenant, tool, resource):
    assert BindingTable([CredentialBinding(**DEPLOY)]).resolve(tenant, tool, resource) is None


def test_two_matches_resolve_to_none():
    other = CredentialBinding(**{**DEPLOY, "resource": "env/*", "credential_id": "admin"})
    table = BindingTable([CredentialBinding(**DEPLOY), other])
    assert table.resolve("tenant-a", "deploy.service", "env/staging/api") is None
    assert table.resolve("tenant-a", "deploy.service", "env/prod/api") == other


@pytest.mark.parametrize(
    "document",
    [
        [DEPLOY],
        {"bindings": [DEPLOY], "extra": 1},
        {"bindings": [{**DEPLOY, "extra": 1}]},
        {"bindings": [{key: value for key, value in DEPLOY.items() if key != "canary"}]},
        {"bindings": [{**DEPLOY, "canary": 1}]},
        {"bindings": [{**DEPLOY, "header_name": "X Bad"}]},
        {"bindings": [{**DEPLOY, "credential_id": ""}]},
    ],
)
def test_malformed_binding_table_is_refused(state, document):
    with pytest.raises(BindingTableError):
        BindingTable.load(write_table(state / "bindings.json", document))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resource", "env/*/api"),
        ("resource", "env/staging*"),
        ("resource", "env/../prod/*"),
        ("tool", "deploy.*"),
    ],
)
def test_binding_outside_the_scope_grammar_is_refused(field, value):
    with pytest.raises(BindingTableError):
        CredentialBinding(**{**DEPLOY, field: value})


@pytest.mark.parametrize(
    ("pattern", "resource"), [("env/staging/?", "env/staging/x"), ("env/staging/[ab]", "env/staging/a")]
)
def test_glob_characters_in_a_binding_are_literal(pattern, resource):
    binding = CredentialBinding(**{**DEPLOY, "resource": pattern})
    table = BindingTable([binding])
    assert table.resolve("tenant-a", "deploy.service", resource) is None
    assert table.resolve("tenant-a", "deploy.service", pattern) == binding


@pytest.mark.parametrize("resource", ["env/staging/../prod/api", "env/staging/./api", "env/staging//api"])
def test_binding_does_not_match_a_resource_the_scope_grammar_refuses(resource):
    assert BindingTable([CredentialBinding(**DEPLOY)]).resolve("tenant-a", "deploy.service", resource) is None


def test_duplicate_keys_are_refused(state):
    path = state / "bindings.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b'{"bindings": [], "bindings": []}')
    os.close(fd)
    with pytest.raises(BindingTableError, match="duplicate"):
        BindingTable.load(path)


def test_binding_table_with_a_loose_mode_is_refused(state):
    with pytest.raises(OwnedFileError, match="mode"):
        BindingTable.load(write_table(state / "bindings.json", {"bindings": [DEPLOY]}, mode=0o644))


def test_claim_is_once_per_op_id_and_survives_a_restart(state):
    claims = ClaimsStore.create(state / "claims.db")
    assert claims.claim("op-1", NOW)
    assert not claims.claim("op-1", NOW + 1)
    claims.close()
    reopened = ClaimsStore.open(state / "claims.db")
    try:
        assert not reopened.claim("op-1", NOW + 2)
        assert reopened.claim("op-2", NOW + 2)
    finally:
        reopened.close()


def test_deny_is_per_task_and_survives_a_restart(state):
    claims = ClaimsStore.create(state / "claims.db")
    claims.deny("tenant-a", "task-1", NOW)
    claims.deny("tenant-a", "task-1", NOW + 1)
    claims.close()
    reopened = ClaimsStore.open(state / "claims.db")
    try:
        assert reopened.is_denied("tenant-a", "task-1")
        assert not reopened.is_denied("tenant-a", "task-2")
        assert not reopened.is_denied("tenant-b", "task-1")
    finally:
        reopened.close()


def test_claims_database_with_a_loose_mode_is_refused(state):
    ClaimsStore.create(state / "claims.db").close()
    os.chmod(state / "claims.db", 0o640)
    with pytest.raises(OwnedFileError, match="mode"):
        ClaimsStore.open(state / "claims.db")


def test_rate_limit_is_per_task_and_slides():
    limiter = TaskRateLimiter(2, 10)
    assert limiter.allow("tenant-a", "task-1", NOW)
    assert limiter.allow("tenant-a", "task-1", NOW + 1)
    assert not limiter.allow("tenant-a", "task-1", NOW + 2)
    assert limiter.allow("tenant-a", "task-2", NOW + 2)
    assert limiter.allow("tenant-a", "task-1", NOW + 10)
    assert not limiter.allow("tenant-a", "task-1", NOW + 10)


@pytest.mark.parametrize(("limit", "window"), [(0, 10), (1, 0), (True, 10)])
def test_rate_limit_refuses_bad_configuration(limit, window):
    with pytest.raises(ValueError):
        TaskRateLimiter(limit, window)


def replace_with_another_database(path):
    ClaimsStore.create(path.parent / "other.db").close()
    os.replace(path.parent / "other.db", path)


@pytest.mark.parametrize(
    "tamper",
    [
        lambda path: os.chmod(path, 0o644),
        lambda path: os.link(path, path.parent / "claims-copy.db"),
        replace_with_another_database,
    ],
)
def test_claims_database_changed_after_open_is_refused(state, tamper):
    claims = ClaimsStore.create(state / "claims.db")
    try:
        tamper(state / "claims.db")
        with pytest.raises(ClaimsUnavailable):
            claims.claim("op-1", NOW)
        with pytest.raises(ClaimsUnavailable):
            claims.is_denied("tenant-a", "task-1")
    finally:
        claims.close()
