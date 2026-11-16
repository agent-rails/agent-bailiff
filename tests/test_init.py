import io
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest
import test_service
from agent_warrant.identity import encode_public_key
from test_decide import POLICY, TENANT
from test_service import (
    ISSUERS,
    ROUTES,
    SECRET,
    DocketThread,
    call_message,
    check,
)

from agent_bailiff import cli
from agent_bailiff.keys import PublicKeyRecord, generate_signing_key, load_signing_key
from agent_bailiff.service import run
from agent_bailiff.service.settings import load_control, load_custodian, load_decide, load_docket

UID = os.geteuid()
GID = os.getegid()
live = test_service.live


def private(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


@pytest.fixture
def root():
    path = Path(tempfile.mkdtemp(prefix="bi-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


@pytest.fixture
def ledger_dir(root):
    directory = root / "ledger"
    directory.mkdir(mode=0o750)
    os.chown(directory, -1, GID)
    os.chmod(directory, 0o750)
    return directory


def init(*arguments, capsys):
    code = cli.main(["init", *map(str, arguments)])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def keyed(root, *arguments, capsys):
    code, out, err = init(*arguments, capsys=capsys)
    assert code == 0, err
    pin = root / f"{arguments[0]}-{arguments[arguments.index('--name') + 1]}.pub.json"
    pin.write_text(out)
    return pin


def init_all(root, ledger_dir, capsys):
    run_dir = private(root / "run")
    sockets = {name: run_dir / name[0] / f"{name}.sock" for name in ("docket", "decide", "custodian")}
    docket = ["--docket-socket", sockets["docket"], "--docket-uid", UID]
    gateway = ["--gateway-uid", UID, "--gateway-group", GID]
    decide_pin = keyed(
        root,
        "decide",
        "--dir", private(root / "decide"),
        "--name", "decide.example",
        "--custodian", "custodian.example",
        "--ledger", ledger_dir / "ledger.db",
        "--ledger-group", GID,
        "--socket", sockets["decide"],
        *docket,
        *gateway,
        capsys=capsys,
    )  # fmt: skip
    custodian_pin = keyed(
        root,
        "custodian",
        "--dir", private(root / "custodian"),
        "--name", "custodian.example",
        "--decide-pin", decide_pin,
        "--ledger", ledger_dir / "ledger.db",
        "--ledger-uid", UID,
        "--ledger-group", GID,
        "--socket", sockets["custodian"],
        *docket,
        *gateway,
        capsys=capsys,
    )  # fmt: skip
    control_pin = keyed(
        root,
        "control",
        "--dir", private(root / "control"),
        "--name", "control",
        "--decide-config", root / "decide" / "config.json",
        "--pin", decide_pin,
        "--pin", custodian_pin,
        *docket,
        capsys=capsys,
    )  # fmt: skip
    code, out, err = init(
        "docket",
        "--dir", private(root / "docket"),
        "--socket", sockets["docket"],
        "--socket-group", GID,
        "--allowed-uid", UID,
        "--pin", decide_pin,
        "--pin", custodian_pin,
        "--pin", control_pin,
        capsys=capsys,
    )  # fmt: skip
    assert (code, out) == (0, ""), err
    return sockets, {"decide": decide_pin, "custodian": custodian_pin, "control": control_pin}


def mode(path):
    info = os.lstat(path)
    return stat.S_IMODE(info.st_mode), info.st_uid


def test_init_writes_private_keys_and_configs_that_load(root, ledger_dir, capsys):
    sockets, pins = init_all(root, ledger_dir, capsys)
    for name in ("decide", "custodian", "control"):
        assert mode(root / name / "signing.key") == (0o600, UID)
        record = PublicKeyRecord.from_document(json.loads(pins[name].read_text()))
        key = load_signing_key(root / name / "signing.key")
        assert encode_public_key(record.public_key) == encode_public_key(key.public_key())
    for name in ("decide", "custodian", "control", "docket"):
        assert mode(root / name / "config.json") == (0o600, UID)
    for directory in ("decide/suspension", "decide/grpc", "decide/docket-state", "custodian/grpc"):
        assert mode(root / directory) == (0o700, UID)
    for name in ("kek", "credentials.db", "claims.db", "bindings.json", "routes.json"):
        assert mode(root / "custodian" / name) == (0o600, UID)
    assert mode(ledger_dir / "ledger.db") == (0o640, UID)
    decide = load_decide(root / "decide" / "config.json")
    custodian = load_custodian(root / "custodian" / "config.json")
    docket = load_docket(root / "docket" / "config.json")
    control = load_control(root / "control" / "config.json")
    decide_record = PublicKeyRecord.from_document(json.loads(pins["decide"].read_text()))
    assert list(custodian.decide_keys) == [decide_record.kid] and custodian.decider == "decide.example"
    assert set(docket.writers) == {"decide.example", "custodian.example", "control"}
    assert set(control.writers) == {"decide.example", "custodian.example"}
    assert control.decide_config == root / "decide" / "config.json"
    assert decide.bindings == () and decide.policy.policy.rules == []


def test_init_never_overwrites(root, ledger_dir, capsys):
    init_all(root, ledger_dir, capsys)
    before = (root / "decide" / "signing.key").read_bytes()
    code, out, err = init(
        "control",
        "--dir", root / "decide",
        "--name", "control",
        "--decide-config", root / "decide" / "config.json",
        "--pin", root / "custodian-custodian.example.pub.json",
        "--docket-socket", "/run/d.sock",
        "--docket-uid", UID,
        capsys=capsys,
    )  # fmt: skip
    assert code == cli.EXIT_REFUSED and "never overwrites" in err
    assert (root / "decide" / "signing.key").read_bytes() == before


def control_init(root, directory, pin, capsys):
    return init(
        "control",
        "--dir", directory,
        "--name", "control",
        "--decide-config", root / "decide.json",
        "--pin", pin,
        "--docket-socket", "/run/d.sock",
        "--docket-uid", UID,
        capsys=capsys,
    )  # fmt: skip


@pytest.fixture
def decide_pin(root):
    directory = private(root / "keys")
    record = generate_signing_key(directory / "decide.key", "decide.example")
    path = root / "decide.pub.json"
    path.write_text(json.dumps(record.to_document()))
    return path


@pytest.mark.parametrize("directory_mode", [0o750, 0o770, 0o701, 0o777])
def test_init_refuses_a_directory_open_to_others(root, decide_pin, capsys, directory_mode):
    directory = private(root / "control")
    os.chmod(directory, directory_mode)
    code, out, err = control_init(root, directory, decide_pin, capsys)
    assert code == cli.EXIT_REFUSED and "mode 0700" in err
    assert os.listdir(directory) == []


def test_init_refuses_a_directory_of_another_uid(root, decide_pin, capsys, monkeypatch):
    directory = private(root / "control")
    monkeypatch.setattr(os, "geteuid", lambda: UID + 1)
    code, out, err = control_init(root, directory, decide_pin, capsys)
    assert code == cli.EXIT_REFUSED
    assert os.listdir(directory) == []


def test_init_refuses_a_relative_directory(root, decide_pin, capsys):
    code, out, err = control_init(root, Path("relative"), decide_pin, capsys)
    assert code == cli.EXIT_REFUSED and "absolute" in err


def tampered_pins(decide_pin):
    good = json.loads(decide_pin.read_text())
    return {
        "wrong_kid": {**good, "kid": "decide.example-AAAAAAAAAAAAAAAA"},
        "other_component": {**good, "component": "custodian.example"},
        "extra_field": {**good, "x": 1},
        "bad_key": {**good, "public_key": "A" * 43},
    }


@pytest.mark.parametrize("name", ["wrong_kid", "other_component", "extra_field", "bad_key", "not_json", "too_big"])
def test_init_refuses_a_tampered_pin(root, decide_pin, capsys, name):
    pin = root / "pin.json"
    if name == "not_json":
        pin.write_text("{")
    elif name == "too_big":
        pin.write_text(" " * 5000)
    else:
        pin.write_text(json.dumps(tampered_pins(decide_pin)[name]))
    directory = private(root / "control")
    code, out, err = control_init(root, directory, pin, capsys)
    assert code == cli.EXIT_REFUSED and out == ""
    assert os.listdir(directory) == []


def test_control_init_refuses_its_own_writer_as_a_pin(root, capsys):
    keys = private(root / "keys")
    own = generate_signing_key(keys / "control.key", "control")
    pin = root / "control.pub.json"
    pin.write_text(json.dumps(own.to_document()))
    directory = private(root / "control")
    code, out, err = control_init(root, directory, pin, capsys)
    assert code == cli.EXIT_REFUSED and "own writer" in err
    assert os.listdir(directory) == []


def test_docket_init_writes_a_config_that_loads(root, decide_pin, capsys):
    directory = private(root / "docket")
    code, out, err = init(
        "docket",
        "--dir", directory,
        "--socket", root / "s" / "docket.sock",
        "--socket-group", GID,
        "--allowed-uid", UID,
        "--allowed-uid", UID,
        "--pin", decide_pin,
        capsys=capsys,
    )  # fmt: skip
    assert code == 0, err
    settings = load_docket(directory / "config.json")
    assert settings.allowed_uids == {UID} and list(settings.writers) == ["decide.example"]
    assert mode(directory / "config.json") == (0o600, UID)


def edit(path, change):
    document = json.loads(path.read_text())
    change(document)
    path.write_text(json.dumps(document))


def test_a_stack_built_by_init_releases_once_and_control_revokes(root, ledger_dir, capsys, live):
    sockets, _ = init_all(root, ledger_dir, capsys)
    binding = {"tenant": TENANT, "tool": "deploy.service", "resource": "env/staging/*"}
    binding |= {"credential_id": "deploy-api", "target": "deploy.example"}
    edit(
        root / "decide" / "config.json",
        lambda doc: doc.update(
            issuers=ISSUERS,
            bindings=[{**binding, "custodian": "custodian.example"}],
            policy={"id": "default", "version": "1", "document": POLICY},
            costs={"version": 1, "tools": {"deploy.service": 1}},
        ),
    )
    edit(root / "custodian" / "config.json", lambda doc: doc.update(issuers=ISSUERS))
    for name in ("decide", "custodian"):
        edit(root / name / "routes.json", lambda doc: doc.update(ROUTES))
    edit(
        root / "custodian" / "bindings.json",
        lambda doc: doc.update(bindings=[{**binding, "header_name": "Authorization", "canary": False}]),
    )
    docket = DocketThread(load_docket(root / "docket" / "config.json"))
    decide = custodian = None
    try:
        decide = run.start_decide(load_decide(root / "decide" / "config.json"))
        sys.stdin = io.TextIOWrapper(io.BytesIO(SECRET))
        try:
            arguments = ["custodian", "put-credential", "--config", str(root / "custodian" / "config.json")]
            arguments += ["--tenant", TENANT, "--credential-id", "deploy-api", "--target", "deploy.example"]
            assert cli.main(arguments) == 0
        finally:
            sys.stdin = sys.__stdin__
        custodian = run.start_custodian(load_custodian(root / "custodian" / "config.json"))
        request = live()
        decided = check(sockets["decide"], call_message(request))
        assert decided.WhichOneof("result") == "pass", decided
        released = check(sockets["custodian"], call_message(request, decided.metadata))
        assert [(item.key, item.value) for item in released.header_mutation.set] == [("Authorization", SECRET)]
        lines = (root / "docket" / "docket.log").read_text().splitlines()
        record = root / "record.txt"
        record.write_text(lines[0] + "\n")
        capsys.readouterr()
        control = ["control", "revoke", "--config", str(root / "control" / "config.json"), "--level", "task"]
        assert cli.main(control + ["--record", str(record), "--actor", "ops"]) == 0
        refused = check(sockets["decide"], call_message(live("n-2")))
        assert refused.error.reason == "chain_invalid"
    finally:
        for service in (custodian, decide):
            if service is not None:
                service.close()
        docket.stop()
