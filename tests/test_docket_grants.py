import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from agent_warrant.identity import encode_public_key
from agent_warrant.resolver import PinnedResolver
from agent_warrant.task_root import issue_task_root
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_docket import make_entry
from test_docket_report import GRANT_WRITERS, ISSUER_PIN, PINS, Docket, write_issuers
from test_docket_report import issuers_document as report_issuers_document

from agent_bailiff import cli
from agent_bailiff.control import Control, ControlRefused
from agent_bailiff.docket import Grant
from agent_bailiff.docket import grants as grants_module
from agent_bailiff.docket.grants import WILDCARD_NAMES_CAP, GrantReport
from agent_bailiff.docket.roles import WriterRoles
from agent_bailiff.docket.sink import VerifiedLine
from agent_bailiff.service.settings import ConfigError, load_issuers

ISSUED = 1_700_000_000
TTL = 3600
ROOT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(10, 42)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(11, 43)))
AGENT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(12, 44)))
SCOPE = {
    "permissions": [
        {"tools": ["github.create_issue", "github.comment"], "resources": ["repo:acme/app"], "max_cost_per_call": 5},
        {"tools": ["slack.post"], "resources": ["channel:ops", "channel:dev"], "max_cost_per_call": 1},
    ]
}
WILDCARD_SCOPE = {"permissions": [{"tools": ["github.*"], "resources": ["repo:acme/*"], "max_cost_per_call": 5}]}
ROW_FIELDS = {
    "status",
    "reason",
    "detail",
    "tenant",
    "task",
    "root",
    "issuer",
    "grant_id",
    "grant_line",
    "grant_records",
    "unused",
    "wildcards",
    "pairs_truncated",
    "budget",
    "authorized_cost",
    "authorized_cost_exact",
    "allows",
    "ttl",
    "ttl_used",
    "ttl_flags",
    "duplicate_roots",
    "duplicate_roots_truncated",
}


def issuers_document(tenants=None):
    return report_issuers_document(
        ROOT_KEY, "issuer-a", tenants or {"acme": {"principals": ["alice"], "principal_prefixes": []}}
    )


def make_root(*, key=ROOT_KEY, issuer="issuer-a", task_id="task-1", tenant="acme", principal="alice", scope=SCOPE):
    return issue_task_root(
        key,
        issuer=issuer,
        task_id=task_id,
        tenant_id=tenant,
        principal=principal,
        purpose="release-bot",
        budget=100,
        max_depth=1,
        issued_at=ISSUED,
        expires_at=ISSUED + TTL,
        scope=scope,
        subject=encode_public_key(AGENT_KEY.public_key()),
    )


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bg-", dir="/tmp"))
    yield path
    shutil.rmtree(path)


@pytest.fixture
def docket(workdir):
    path = workdir / "docket.log"
    path.touch(mode=0o600)
    return Docket(path)


@pytest.fixture
def pin_files(workdir):
    paths = {}
    for name, pin in {**PINS, "issuer": ISSUER_PIN}.items():
        paths[name] = workdir / f"{name}.pub.json"
        paths[name].write_text(json.dumps(pin.to_document()))
        os.chmod(paths[name], 0o644)
    return paths


@pytest.fixture
def issuers_file(workdir):
    return write_issuers(workdir / "issuers.json", issuers_document())


def grant(docket, root, grant_id="g-1", at=ISSUED):
    return docket.grant(Grant(grant_id=grant_id, at=at, root_token=root.encode()))


def allow(docket, root, number, *, op_id=None, tool="github.create_issue", resource="repo:acme/app", cost=1, **changes):
    handles = {"tenant": root.tenant_id, "task": root.task_id, "root": root.binding()}
    entry = make_entry(
        number,
        op_id=op_id or f"op-{number}",
        tool=tool,
        resource=resource,
        cost=cost,
        task_root=root.binding(),
        handles=handles,
        **changes,
    )
    return docket.append("decide", entry)


def report(docket, pin_files, issuers_file, *arguments, capsys):
    pins = ["--decide-pin", pin_files["decide"], "--pin", pin_files["custodian"], "--pin", pin_files["control"]]
    pins += ["--grant-pin", pin_files["issuer"], "--issuers", issuers_file]
    code = cli.main(["docket", "grants", "--docket", str(docket.path), *map(str, pins), *arguments])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


def json_report(docket, pin_files, issuers_file, capsys):
    code, out, err = report(docket, pin_files, issuers_file, "--json", capsys=capsys)
    return code, [json.loads(line) for line in out], err


def test_a_granted_root_lists_the_pairs_it_never_used(docket, pin_files, issuers_file, capsys):
    root = make_root()
    grant(docket, root)
    allow(docket, root, 1)
    allow(docket, root, 2, tool="slack.post", resource="channel:ops")
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    [row] = rows
    assert set(row) == ROW_FIELDS
    assert (row["status"], row["reason"], row["tenant"], row["task"]) == ("granted", None, "acme", "task-1")
    assert (row["root"], row["issuer"], row["grant_id"], row["grant_line"]) == (root.binding(), "issuer-a", "g-1", 1)
    assert row["unused"] == [
        {"permission": 0, "tool": "github.comment", "resource": "repo:acme/app"},
        {"permission": 1, "tool": "slack.post", "resource": "channel:dev"},
    ]
    assert row["wildcards"] == [] and row["duplicate_roots"] == []
    assert "3 records verified, 1 roots, 0 invalid grants" in err


def test_a_granted_root_with_no_calls_lists_every_pair_unused(docket, pin_files, issuers_file, capsys):
    grant(docket, make_root())
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert len(row["unused"]) == 4
    assert (row["allows"], row["authorized_cost"], row["ttl_used"], row["ttl_flags"]) == (0, 0, None, [])


def test_a_root_used_without_a_grant_is_ungranted(docket, pin_files, issuers_file, capsys):
    root = make_root()
    allow(docket, root, 1, cost=2)
    docket.append(
        "control",
        make_entry(2, hop="control", decision="revoke", handles={"root": "other-root", "tenant": "acme", "task": "t"}),
    )
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert (row["status"], row["root"], row["tenant"], row["task"]) == ("ungranted", root.binding(), "acme", "task-1")
    assert (row["authorized_cost"], row["allows"], row["budget"], row["ttl"], row["unused"]) == (2, 1, None, None, [])


def test_a_root_seen_only_in_custodian_records_is_not_listed(docket, pin_files, issuers_file, capsys):
    root = make_root()
    handles = {"tenant": "acme", "task": "task-1", "root": root.binding()}
    docket.append("custodian", make_entry(1, hop="custodian", component="custodian", handles=handles))
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert rows == []
    assert "1 records verified, 0 roots" in err


def test_a_custodian_record_claiming_the_decide_hop_is_not_counted(docket, pin_files, issuers_file, capsys):
    root = make_root()
    grant(docket, root)
    allow(docket, root, 1, cost=2)
    other = make_root(task_id="task-m")
    for number, forged_root in ((2, root), (3, other)):
        handles = {"tenant": "acme", "task": forged_root.task_id, "root": forged_root.binding()}
        entry = make_entry(number, op_id=f"op-m{number}", cost=50, task_root=forged_root.binding(), handles=handles)
        docket.append("custodian", entry)
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == cli.EXIT_UNCOUNTED == 3
    assert (row["root"], row["allows"], row["authorized_cost"]) == (root.binding(), 1, 2)
    assert "docket grants: 2 records claim a hop their writer is not pinned for; they are not counted" in err


def test_the_mismatch_warning_comes_before_the_rows(docket, pin_files, issuers_file, monkeypatch):
    root = make_root()
    grant(docket, root)
    docket.append("custodian", make_entry(2, handles={"tenant": "acme", "task": "task-1", "root": root.binding()}))
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", stream)
    pins = ["--decide-pin", pin_files["decide"], "--pin", pin_files["custodian"], "--grant-pin", pin_files["issuer"]]
    code = cli.main(["docket", "grants", "--docket", str(docket.path), *map(str, pins), "--issuers", str(issuers_file)])
    lines = stream.getvalue().splitlines()
    assert code == cli.EXIT_UNCOUNTED
    assert "1 records claim a hop" in lines[0]
    assert lines[1].startswith("TENANT")


def test_uncounted_records_outrank_an_invalid_grant(docket, pin_files, issuers_file, capsys):
    docket.grant(Grant(grant_id="g-bad", at=ISSUED, root_token="not-a-root"))
    root = make_root()
    docket.append("custodian", make_entry(2, handles={"tenant": "acme", "task": "task-1", "root": root.binding()}))
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == cli.EXIT_UNCOUNTED
    assert [row["status"] for row in rows] == ["invalid_grant"]
    assert "1 invalid grants" in err


def test_a_verification_failure_outranks_uncounted_records(docket, pin_files, issuers_file, capsys):
    root = make_root()
    docket.append("custodian", make_entry(1, handles={"tenant": "acme", "task": "task-1", "root": root.binding()}))
    with docket.path.open("a") as handle:
        handle.write("garbage\n")
    code, out, err = report(docket, pin_files, issuers_file, "--json", capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert out == []
    assert "records claim a hop" not in err


def test_grants_requires_a_decide_pin(docket, pin_files, issuers_file, capsys):
    with pytest.raises(SystemExit):
        cli.main(["docket", "grants", "--docket", str(docket.path), "--issuers", str(issuers_file)])
    assert "--decide-pin" in capsys.readouterr().err


def test_a_writer_pinned_as_decide_and_as_plain_pin_is_refused(docket, pin_files, issuers_file, capsys):
    pins = ["--decide-pin", pin_files["decide"], "--pin", pin_files["decide"]]
    code = cli.main(["docket", "grants", "--docket", str(docket.path), *map(str, pins), "--issuers", str(issuers_file)])
    assert code == cli.EXIT_UNVERIFIED
    assert "writer decide is pinned as both --pin and --decide-pin" in capsys.readouterr().err


def test_uses_before_the_grant_still_join_the_root(docket, pin_files, issuers_file, capsys):
    root = make_root()
    allow(docket, root, 1)
    grant(docket, root)
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert (row["status"], row["allows"], row["grant_line"]) == ("granted", 1, 2)


@pytest.mark.parametrize(
    ("root_token", "reason"),
    [
        ("not-a-root", "malformed"),
        (make_root(issuer="issuer-b").encode(), "unknown_issuer"),
        (make_root(key=OTHER_KEY).encode(), "bad_signature"),
        (make_root(tenant="zeta").encode(), "issuer_not_allowed"),
        (make_root(principal="mallory").encode(), "issuer_not_allowed"),
    ],
)
def test_an_invalid_grant_is_its_own_row_and_exits_1(docket, pin_files, issuers_file, capsys, root_token, reason):
    grant(docket, make_root(task_id="task-0"), grant_id="g-0")
    docket.grant(Grant(grant_id="g-bad", at=ISSUED, root_token=root_token))
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == cli.EXIT_REFUSED
    assert sorted(row["status"] for row in rows) == ["granted", "invalid_grant"]
    [invalid] = [row for row in rows if row["status"] == "invalid_grant"]
    assert (invalid["reason"], invalid["grant_id"], invalid["grant_line"]) == (reason, "g-bad", 2)
    assert invalid["detail"]
    assert "1 invalid grants" in err


def test_an_invalid_grant_does_not_grant_its_root(docket, pin_files, issuers_file, capsys):
    forged = make_root(key=OTHER_KEY)
    grant(docket, forged)
    allow(docket, forged, 1)
    code, rows, _ = json_report(docket, pin_files, issuers_file, capsys)
    assert code == cli.EXIT_REFUSED
    assert sorted((row["status"], row["root"]) for row in rows) == [
        ("invalid_grant", forged.binding()),
        ("ungranted", forged.binding()),
    ]


def test_an_expired_root_is_still_granted(docket, pin_files, issuers_file, capsys):
    root = make_root()
    grant(docket, root, at=ISSUED + 10 * TTL)
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert row["status"] == "granted"


def test_wildcard_grants_list_names_used_under_them_up_to_the_cap(docket, pin_files, issuers_file, capsys):
    root = make_root(scope=WILDCARD_SCOPE)
    grant(docket, root)
    extra = 5
    for number in range(WILDCARD_NAMES_CAP + extra):
        allow(docket, root, number + 1, tool=f"github.tool_{number:02d}")
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    tool, resource = row["wildcards"]
    assert (tool["kind"], tool["pattern"], tool["permission"]) == ("tool", "github.*", 0)
    assert tool["used"] == [f"github.tool_{number:02d}" for number in range(WILDCARD_NAMES_CAP)]
    assert tool["truncated"] == extra
    assert (resource["kind"], resource["pattern"], resource["used"], resource["truncated"]) == (
        "resource",
        "repo:acme/*",
        ["repo:acme/app"],
        0,
    )
    assert row["unused"] == []


def test_authorized_cost_counts_each_operation_once(docket, pin_files, issuers_file, capsys):
    root = make_root()
    grant(docket, root)
    allow(docket, root, 1, op_id="op-a", cost=3)
    allow(docket, root, 2, op_id="op-a", cost=3)
    allow(docket, root, 3, op_id="op-b", cost=2)
    allow(docket, root, 4, op_id="op-c", cost=4, decision="refuse")
    allow(docket, root, 5, op_id="op-d", cost=4, decision="reconcile")
    allow(docket, root, 6, op_id="op-e", cost=4, hop="custodian", component="custodian")
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert (row["authorized_cost"], row["allows"], row["budget"], row["authorized_cost_exact"]) == (5, 2, 100, True)


@pytest.mark.parametrize(
    ("offsets", "ttl_used", "flags"),
    [
        ([10, 600], 600, []),
        ([-30, 600], 600, ["negative"]),
        ([10, TTL], TTL, ["after_expiry"]),
        ([-30, TTL + 5], TTL + 5, ["negative", "after_expiry"]),
    ],
)
def test_ttl_used_is_flagged_outside_the_root_lifetime(
    docket, pin_files, issuers_file, capsys, offsets, ttl_used, flags
):
    root = make_root()
    grant(docket, root)
    for number, offset in enumerate(offsets):
        allow(docket, root, number + 1, at=ISSUED + offset)
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert (row["ttl"], row["ttl_used"], row["ttl_flags"]) == (TTL, ttl_used, flags)


def test_two_roots_granted_for_one_task_flag_each_other(docket, pin_files, issuers_file, capsys):
    first = make_root()
    second = make_root(scope=WILDCARD_SCOPE)
    grant(docket, first, grant_id="g-1")
    grant(docket, second, grant_id="g-2")
    grant(docket, make_root(task_id="task-2"), grant_id="g-3")
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    flagged = {row["root"]: row["duplicate_roots"] for row in rows if row["task"] == "task-1"}
    assert flagged == {first.binding(): [second.binding()], second.binding(): [first.binding()]}
    assert [row["duplicate_roots"] for row in rows if row["task"] == "task-2"] == [[]]


def test_duplicate_roots_past_the_cap_are_counted_not_listed(docket, pin_files, issuers_file, capsys, monkeypatch):
    monkeypatch.setattr(grants_module, "DUPLICATE_ROOTS_CAP", 1)
    roots = [make_root(scope=scope) for scope in (SCOPE, WILDCARD_SCOPE, {"permissions": SCOPE["permissions"][:1]})]
    for number, root in enumerate(roots):
        grant(docket, root, grant_id=f"g-{number}")
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    bindings = sorted(root.binding() for root in roots)
    assert [(row["root"], row["duplicate_roots"], row["duplicate_roots_truncated"]) for row in rows] == [
        (bindings[0], [bindings[1]], 1),
        (bindings[1], [bindings[0]], 1),
        (bindings[2], [bindings[0]], 1),
    ]
    code, out, err = report(docket, pin_files, issuers_file, capsys=capsys)
    assert code == 0, err
    assert {line.split("\t")[-1] for line in out[1:]} == {"duplicate_roots,duplicate_roots_truncated"}


def test_the_same_root_granted_twice_is_one_row(docket, pin_files, issuers_file, capsys):
    root = make_root()
    grant(docket, root, grant_id="g-1")
    grant(docket, root, grant_id="g-1")
    code, [row], err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert (row["grant_id"], row["grant_line"], row["grant_records"], row["duplicate_roots"]) == ("g-1", 1, 2, [])


def test_rows_sort_by_tenant_task_and_root(docket, pin_files, issuers_file, capsys):
    grant(docket, make_root(task_id="task-b"), grant_id="g-b")
    grant(docket, make_root(task_id="task-a"), grant_id="g-a")
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert [row["task"] for row in rows] == ["task-a", "task-b"]


def test_the_table_summarises_each_root(docket, pin_files, issuers_file, capsys):
    root = make_root()
    grant(docket, root)
    allow(docket, root, 1, cost=3, at=ISSUED + TTL)
    code, out, err = report(docket, pin_files, issuers_file, capsys=capsys)
    assert code == 0, err
    assert out[0].split("\t") == [
        "TENANT", "TASK", "ROOT", "STATUS", "REASON", "UNUSED", "WILDCARDS", "COST", "TTL", "FLAGS"
    ]  # fmt: skip
    assert out[1].split("\t") == [
        "acme",
        "task-1",
        root.binding(),
        "granted",
        "-",
        "3",
        "0",
        "3/100",
        "3600/3600",
        "after_expiry",
    ]


def test_a_docket_that_fails_verification_exits_2_and_prints_nothing(docket, pin_files, issuers_file, capsys):
    grant(docket, make_root())
    with open(docket.path, "a") as stream:
        stream.write("not-a-record\n")
    code, out, err = report(docket, pin_files, issuers_file, "--json", capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED == 2
    assert out == []
    assert "line 2 fails verification" in err


def test_a_grant_without_its_grant_pin_fails_verification(docket, pin_files, issuers_file, capsys):
    grant(docket, make_root())
    pins = ["--decide-pin", str(pin_files["decide"]), "--pin", str(pin_files["custodian"])]
    code = cli.main(["docket", "grants", "--docket", str(docket.path), *pins, "--issuers", str(issuers_file)])
    assert code == cli.EXIT_UNVERIFIED
    assert "line 1 fails verification" in capsys.readouterr().err


@pytest.mark.parametrize("document", [[], {"issuer-a": {"public_key": "x"}}])
def test_an_unusable_issuers_file_exits_2(docket, pin_files, issuers_file, capsys, document):
    issuers_file.write_text(json.dumps(document))
    code, out, err = report(docket, pin_files, issuers_file, capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert out == []
    assert "docket grants refused: issuers" in err


def test_grants_refuse_an_empty_issuers_file(docket, pin_files, issuers_file, capsys):
    grant(docket, make_root())
    issuers_file.write_text("{}")
    code, out, err = report(docket, pin_files, issuers_file, capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert out == []
    assert "docket grants refused: issuers file must name at least one issuer" in err


def test_an_issuers_file_others_can_write_is_refused(docket, pin_files, issuers_file, capsys):
    os.chmod(issuers_file, 0o644)
    code, _, err = report(docket, pin_files, issuers_file, capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert "must have mode 0o600" in err


def test_a_decide_allow_without_a_cost_exits_2(docket, pin_files, issuers_file, capsys):
    allow(docket, make_root(), 1, cost=None)
    code, out, err = report(docket, pin_files, issuers_file, capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert "line 1 lacks an op_id, cost, tool or resource" in err


def test_a_forged_root_is_invalid_in_tasks_and_grants_and_refused_by_control(docket, pin_files, issuers_file, capsys):
    forged = make_root(key=OTHER_KEY)
    record = grant(docket, forged)
    pins = [item for name in ("decide", "custodian", "control") for item in (f"--{name}-pin", str(pin_files[name]))]
    pins += ["--grant-pin", str(pin_files["issuer"]), "--issuers", str(issuers_file)]
    cli.main(["docket", "tasks", "--docket", str(docket.path), *pins, "--json"])
    [task] = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert (task["tenant"], task["task"], task["granted"], task["record"]) == ("acme", "task-1", False, None)
    assert (task["root_status"], task["root_reason"], task["invalid_grants"]) == ("invalid", "bad_signature", 1)
    code, [row], _ = json_report(docket, pin_files, issuers_file, capsys)
    assert code == cli.EXIT_REFUSED
    assert (row["status"], row["reason"], row["root"]) == ("invalid_grant", "bad_signature", forged.binding())
    issuers = load_issuers(issuers_file)
    control = Control(
        "control",
        {"issuer": GRANT_WRITERS["issuer"]},
        None,
        None,
        None,
        "control.writer",
        resolver=issuers.resolver,
        trust_policy=issuers.trust_policy,
        grant_writers={"issuer"},
    )
    with pytest.raises(ControlRefused) as refused:
        control.revoke(record.token, "task", "ops", ISSUED)
    assert refused.value.reason == "root_bad_signature"


def roots_docket(docket):
    grant(docket, make_root(task_id="task-1"), grant_id="g-1")
    allow(docket, make_root(task_id="task-2"), 1)
    docket.grant(Grant(grant_id="g-bad", at=ISSUED, root_token="not-a-root"))


def test_roots_up_to_the_cap_are_reported(docket, pin_files, issuers_file, capsys, monkeypatch):
    monkeypatch.setattr(grants_module, "MAX_ROOTS", 3)
    roots_docket(docket)
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == cli.EXIT_REFUSED, err
    assert sorted(row["status"] for row in rows) == ["granted", "invalid_grant", "ungranted"]


def test_a_root_past_the_cap_exits_2_and_prints_nothing(docket, pin_files, issuers_file, capsys, monkeypatch):
    monkeypatch.setattr(grants_module, "MAX_ROOTS", 2)
    roots_docket(docket)
    code, out, err = report(docket, pin_files, issuers_file, "--json", capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert out == []
    assert "docket grants refused: the report tracks at most 2 roots and line 3 adds another" in err


def items_docket(docket):
    for task_id in ("task-1", "task-2"):
        root = make_root(task_id=task_id)
        allow(docket, root, 1, op_id=f"{task_id}-op")
        allow(docket, root, 2, op_id=f"{task_id}-op")


def test_op_ids_and_pairs_up_to_the_total_budget_are_reported(docket, pin_files, issuers_file, capsys, monkeypatch):
    monkeypatch.setattr(grants_module, "MAX_TRACKED_ITEMS", 4)
    items_docket(docket)
    code, rows, err = json_report(docket, pin_files, issuers_file, capsys)
    assert code == 0, err
    assert [(row["allows"], row["authorized_cost_exact"]) for row in rows] == [(1, True), (1, True)]


def test_op_ids_and_pairs_past_the_total_budget_exit_2_and_print_nothing(
    docket, pin_files, issuers_file, capsys, monkeypatch
):
    monkeypatch.setattr(grants_module, "MAX_TRACKED_ITEMS", 3)
    items_docket(docket)
    code, out, err = report(docket, pin_files, issuers_file, "--json", capsys=capsys)
    assert code == cli.EXIT_UNVERIFIED
    assert out == []
    assert "docket grants refused: the report tracks at most 3 op_ids and pairs and line 3 adds another" in err


def test_grants_requires_an_issuers_file(docket, pin_files, capsys):
    with pytest.raises(SystemExit):
        cli.main(["docket", "grants", "--docket", str(docket.path), "--pin", str(pin_files["decide"])])
    assert "--issuers" in capsys.readouterr().err


def test_load_issuers_reads_the_decide_issuers_section(issuers_file):
    issuers = load_issuers(issuers_file)
    assert issuers.trust_policy.check_issuer("issuer-a") is None
    assert issuers.resolver.resolve("issuer-a").public_bytes_raw() == ROOT_KEY.public_key().public_bytes_raw()


def test_load_issuers_refuses_a_bad_allowance(issuers_file):
    issuers_file.write_text(json.dumps(issuers_document({"acme": {"principals": "alice", "principal_prefixes": []}})))
    with pytest.raises(ConfigError, match=r"issuers file\.issuers\.issuer-a"):
        load_issuers(issuers_file)


def policy_report():
    allowance = IssuerAllowance(tenants={"acme": TenantAllowance(principals=["alice"])}, max_budget=1000, max_depth=2)
    resolver = PinnedResolver({"issuer-a": ROOT_KEY.public_key()})
    return GrantReport(resolver, IssuerTrustPolicy({"issuer-a": allowance}), DECIDE_ROLE)


DECIDE_ROLE = WriterRoles({"decide": frozenset({"decide"})})


def test_a_grant_report_needs_a_decide_writer():
    resolver = PinnedResolver({"issuer-a": ROOT_KEY.public_key()})
    with pytest.raises(ValueError, match="no writer is pinned for hop decide"):
        GrantReport(resolver, IssuerTrustPolicy({}), WriterRoles({"custodian": frozenset({"custodian"})}))


def verified(docket, record):
    return VerifiedLine(line=len(docket.records), record=record, start=0, end=0)


def test_distinct_pairs_past_the_cap_are_counted_not_kept(docket, monkeypatch):
    monkeypatch.setattr(grants_module, "MAX_PAIRS_PER_ROOT", 2)
    grants = policy_report()
    root = make_root(scope=WILDCARD_SCOPE)
    grants.add(verified(docket, grant(docket, root)))
    for number in range(4):
        grants.add(verified(docket, allow(docket, root, number + 1, tool=f"github.tool_{number}")))
    [row] = grants.rows()
    assert row.pairs_truncated == 2
    assert row.wildcards[0].used == ("github.tool_0", "github.tool_1")


def test_operations_past_the_cap_mark_the_cost_inexact(docket, monkeypatch):
    monkeypatch.setattr(grants_module, "MAX_OPS_PER_ROOT", 1)
    grants = policy_report()
    root = make_root()
    grants.add(verified(docket, grant(docket, root)))
    for number in (1, 2, 2):
        grants.add(verified(docket, allow(docket, root, number, op_id=f"op-{number}", cost=2)))
    [row] = grants.rows()
    assert (row.authorized_cost, row.allows, row.authorized_cost_exact) == (6, 3, False)


def test_items_past_a_per_root_cap_do_not_use_the_total_budget(docket, monkeypatch):
    monkeypatch.setattr(grants_module, "MAX_OPS_PER_ROOT", 1)
    monkeypatch.setattr(grants_module, "MAX_PAIRS_PER_ROOT", 1)
    monkeypatch.setattr(grants_module, "MAX_TRACKED_ITEMS", 2)
    grants = policy_report()
    root = make_root(scope=WILDCARD_SCOPE)
    for number in range(4):
        grants.add(verified(docket, allow(docket, root, number + 1, tool=f"github.tool_{number}")))
    [row] = grants.rows()
    assert (row.allows, row.pairs_truncated, row.authorized_cost_exact) == (4, 3, False)


def test_the_report_keeps_one_aggregate_per_root(docket):
    grants = policy_report()
    root = make_root()
    grants.add(verified(docket, grant(docket, root)))
    for number in range(50):
        grants.add(verified(docket, allow(docket, root, number + 1, op_id="op-1")))
    assert len(grants._roots) == 1
    assert grants._roots[root.binding()].ops == {"op-1"}


def test_rows_are_built_one_at_a_time_in_sort_order(docket, monkeypatch):
    grants = policy_report()
    for task_id in ("task-2", "task-1"):
        grants.add(verified(docket, grant(docket, make_root(task_id=task_id))))
    grants.add(verified(docket, docket.grant(Grant(grant_id="g-bad", at=ISSUED, root_token="not-a-root"))))
    built = []
    build = GrantReport._row
    monkeypatch.setattr(GrantReport, "_row", lambda self, *args: built.append(args[0]) or build(self, *args))
    rows = grants.rows()
    assert next(rows).status == "invalid_grant" and built == []
    assert next(rows).task == "task-1" and len(built) == 1
    assert next(rows).task == "task-2" and len(built) == 2
    assert next(rows, None) is None
