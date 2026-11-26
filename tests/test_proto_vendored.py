import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "adapters" / "agentgateway" / "scripts" / "generate_proto.sh"
PROTO = ROOT / "adapters" / "agentgateway" / "proto" / "ext_mcp.proto"
STUBS = ROOT / "agent_bailiff" / "adapters" / "agentgateway" / "_proto"
SCAN_IGNORES = ROOT / ".trivyignore.yaml"
IMAGE_SCAN = ROOT / ".github" / "workflows" / "image-scan.yml"
MAX_IGNORE_DAYS = 31


def pinned_sha256():
    return re.search(r"^SHA256=([0-9a-f]{64})$", SCRIPT.read_text(), re.MULTILINE).group(1)


def copy_layout(tmp_path):
    scripts = tmp_path / "adapters" / "agentgateway" / "scripts"
    proto = tmp_path / "adapters" / "agentgateway" / "proto"
    scripts.mkdir(parents=True)
    proto.mkdir(parents=True)
    shutil.copy(SCRIPT, scripts)
    shutil.copy(PROTO, proto)
    return scripts / SCRIPT.name, proto / PROTO.name


def generate(script, out):
    return subprocess.run(
        ["sh", str(script)],
        env={"PYTHON": sys.executable, "OUT": str(out), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_the_vendored_proto_matches_the_pinned_sha256():
    assert hashlib.sha256(PROTO.read_bytes()).hexdigest() == pinned_sha256()


def test_the_script_generates_the_stubs(tmp_path):
    script, _ = copy_layout(tmp_path)
    result = generate(script, tmp_path / "out")
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in (tmp_path / "out").iterdir()) == [
        "__init__.py",
        "ext_mcp_pb2.py",
        "ext_mcp_pb2.pyi",
    ]


def test_the_script_refuses_a_changed_proto(tmp_path):
    script, proto = copy_layout(tmp_path)
    proto.write_text(proto.read_text() + "\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / "kept").touch()
    result = generate(script, out)
    assert result.returncode == 1
    assert "does not match" in result.stderr
    assert (out / "kept").exists()


def test_the_committed_stubs_match_a_fresh_generation(tmp_path):
    result = generate(SCRIPT, tmp_path / "out")
    assert result.returncode == 0, result.stderr
    names = ["__init__.py", "ext_mcp_pb2.py", "ext_mcp_pb2.pyi"]
    assert sorted(path.name for path in (tmp_path / "out").iterdir()) == names
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--", str(STUBS.relative_to(ROOT))],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert sorted(Path(path).name for path in tracked) == names
    assert {name: (tmp_path / "out" / name).read_bytes() for name in names} == {
        name: (STUBS / name).read_bytes() for name in names
    }


def test_every_image_builds_from_one_digest_pinned_python_base():
    tracked = subprocess.run(
        ["git", "ls-files", "*Dockerfile*"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    images = [
        match
        for path in tracked
        for match in re.findall(r"^FROM (?:--platform=\S+ )?(\S+)", (ROOT / path).read_text(), re.MULTILINE)
    ]
    bases = {image for image in images if image.startswith("python:")}
    assert len(tracked) >= 4 and len(bases) == 1, bases
    assert re.fullmatch(r"python:3\.13\.\d+-slim@sha256:[0-9a-f]{64}", bases.pop())


def test_every_image_scan_exception_is_scoped_explained_and_expiring():
    entries = json.loads(SCAN_IGNORES.read_text())["vulnerabilities"]
    assert entries
    for entry in entries:
        assert set(entry) == {"id", "paths", "purls", "statement", "expired_at"}, entry
        assert re.fullmatch(r"CVE-\d{4}-\d+", entry["id"])
        assert entry["paths"] and all(entry["paths"]), entry
        assert entry["purls"] and all(re.fullmatch(r"pkg:\w+/\S+@\S+", purl) for purl in entry["purls"]), entry
        assert entry["statement"].strip(), entry
        expires = datetime.strptime(entry["expired_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        now = datetime.now(UTC)
        assert now < expires <= now + timedelta(days=MAX_IGNORE_DAYS), entry


def test_the_image_scan_applies_the_exceptions():
    assert "--ignorefile .trivyignore.yaml" in IMAGE_SCAN.read_text()
