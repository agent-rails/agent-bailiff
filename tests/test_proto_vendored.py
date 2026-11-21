import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "adapters" / "agentgateway" / "scripts" / "generate_proto.sh"
PROTO = ROOT / "adapters" / "agentgateway" / "proto" / "ext_mcp.proto"
PROTO_LOCK = ROOT / "examples" / "quickstart" / "proto-requirements.txt"
CI_LOCK = ROOT / "requirements-ci.txt"
DOCKERFILES = [ROOT / "examples" / "quickstart" / "Dockerfile", ROOT / "deploy" / "kubernetes" / "Dockerfile.webhook"]


def pinned_sha256():
    return re.search(r"^SHA256=([0-9a-f]{64})$", SCRIPT.read_text(), re.MULTILINE).group(1)


def pins(lock):
    return dict(re.findall(r"^([a-z0-9_.-]+)==([^ \\]+)", lock.read_text(), re.MULTILINE))


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


def test_the_image_build_uses_the_ci_protoc_toolchain():
    build = pins(PROTO_LOCK)
    assert "grpcio-tools" in build
    ci = pins(CI_LOCK)
    assert {name: ci.get(name) for name in build} == build


def test_every_image_builds_from_one_digest_pinned_python_base():
    bases = {
        match
        for dockerfile in DOCKERFILES
        for match in re.findall(r"^FROM (python:\S+)", dockerfile.read_text(), re.MULTILINE)
    }
    assert len(bases) == 1
    assert re.fullmatch(r"python:3\.13\.\d+-slim@sha256:[0-9a-f]{64}", bases.pop())
