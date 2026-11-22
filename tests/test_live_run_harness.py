import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "live-run"))
import run  # noqa: E402


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BAILIFF_CACHE", str(tmp_path))
    return tmp_path / "agentgateway" / "v1.7.0"


def place(cache, name):
    cache.mkdir(parents=True)
    binary = cache / f"agentgateway-{name}"
    binary.write_bytes(b"")
    return binary


@pytest.mark.parametrize(
    ("system", "machine", "name"), [("darwin", "arm64", "darwin-arm64"), ("linux", "x86_64", "linux-amd64")]
)
def test_the_gateway_binary_is_the_pinned_one_for_the_platform(cache, monkeypatch, system, machine, name):
    binary = place(cache, name)
    monkeypatch.setattr(run.sys, "platform", system)
    monkeypatch.setattr(run.platform, "machine", lambda: machine)
    assert run.gateway_binary() == binary


@pytest.mark.parametrize(("system", "machine"), [("linux", "aarch64"), ("darwin", "x86_64"), ("win32", "AMD64")])
def test_the_gateway_binary_is_refused_for_an_unpinned_platform(cache, monkeypatch, system, machine):
    monkeypatch.setattr(run.sys, "platform", system)
    monkeypatch.setattr(run.platform, "machine", lambda: machine)
    with pytest.raises(RuntimeError, match="no pinned agentgateway"):
        run.gateway_binary()


def test_a_missing_gateway_binary_is_refused(cache, monkeypatch):
    monkeypatch.setattr(run.sys, "platform", "linux")
    monkeypatch.setattr(run.platform, "machine", lambda: "x86_64")
    with pytest.raises(RuntimeError, match="fetch_gateway.sh"):
        run.gateway_binary()


def test_the_cache_defaults_to_the_fetch_script_location(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_BAILIFF_CACHE", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(run.sys, "platform", "linux")
    monkeypatch.setattr(run.platform, "machine", lambda: "x86_64")
    binary = place(tmp_path / "agent-bailiff" / "agentgateway" / "v1.7.0", "linux-amd64")
    assert run.gateway_binary() == binary


def make_layout(root, files=run.WORK_FILES):
    root.mkdir(exist_ok=True)
    work, receipts = root / "work", root / "receipts"
    work.mkdir(mode=0o700)
    receipts.mkdir()
    os.chmod(receipts, 0o750)
    for name in files:
        if name == "home":
            (work / name).mkdir()
        else:
            (work / name).write_text("x")
    return work, receipts


def test_the_entrypoint_layout_is_accepted(tmp_path):
    run.require_layout(*make_layout(tmp_path), run.WORK_FILES)


def test_the_kubernetes_layout_needs_the_kubeconfig(tmp_path):
    work, receipts = make_layout(tmp_path)
    with pytest.raises(RuntimeError, match="must hold only"):
        run.require_layout(work, receipts, run.WORK_FILES | {"kubeconfig"})


@pytest.mark.parametrize(
    "change",
    [
        lambda work, receipts: (work.parent / "extra").mkdir(),
        lambda work, receipts: (receipts / "planted").write_text("x"),
        lambda work, receipts: os.chmod(receipts, 0o770),
        lambda work, receipts: (work / "claude-token").unlink(),
        lambda work, receipts: (work / "extra").write_text("x"),
    ],
    ids=["extra-entry", "receipts-not-empty", "receipts-mode", "missing-token", "extra-work-file"],
)
def test_a_layout_other_than_the_entrypoints_is_refused(tmp_path, change):
    work, receipts = make_layout(tmp_path)
    change(work, receipts)
    with pytest.raises(RuntimeError):
        run.require_layout(work, receipts, run.WORK_FILES)


def test_a_symlinked_work_dir_is_refused(tmp_path):
    work, receipts = make_layout(tmp_path / "layout")
    os.rename(work, tmp_path / "elsewhere")
    os.symlink(tmp_path / "elsewhere", work)
    with pytest.raises(RuntimeError, match="not a link"):
        run.require_layout(work, receipts, run.WORK_FILES)


def test_the_archiver_uid_must_differ_from_the_harness_uid(tmp_path):
    with pytest.raises(RuntimeError, match="harness's own uid"):
        run.Deployment(tmp_path, receipt_dir=tmp_path, archiver_uid=os.geteuid())


def test_the_archiver_uid_is_keyword_only(tmp_path):
    with pytest.raises(TypeError):
        run.Deployment(tmp_path, tmp_path, os.geteuid() + 1)


def test_the_receipt_dir_owned_by_the_archiver_is_accepted(tmp_path):
    os.chmod(tmp_path, 0o750)
    run.check_receipt_dir(tmp_path, os.geteuid(), os.lstat(tmp_path).st_gid)


@pytest.mark.parametrize(
    ("uid_offset", "gid_offset", "mode"), [(1, 0, 0o750), (0, 1, 0o750), (0, 0, 0o770)], ids=["owner", "gid", "mode"]
)
def test_a_receipt_dir_the_archiver_does_not_hold_is_refused(tmp_path, uid_offset, gid_offset, mode):
    os.chmod(tmp_path, mode)
    gid = os.lstat(tmp_path).st_gid
    with pytest.raises(RuntimeError, match="must be owned by"):
        run.check_receipt_dir(tmp_path, os.geteuid() + uid_offset, gid + gid_offset)


def test_the_result_is_one_compact_line(capsys):
    run.print_result("r1", "m", [run.Outcome("s", "p")], {"docket verifies": True})
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    assert json.loads(out)["run_id"] == "r1" and json.loads(out)["status"] == "ok"
