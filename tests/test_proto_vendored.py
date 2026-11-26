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
LIBZSTD_FLOOR = "1.5.7+dfsg-1+deb13u1"
LIBZSTD_UPGRADE = (
    "RUN apt-get update \\\n"
    "    && apt-get install --yes --no-install-recommends --only-upgrade libzstd1 \\\n"
    "    && dpkg --compare-versions \"$(dpkg-query --show --showformat='${Version}' libzstd1)\" "
    f"ge {LIBZSTD_FLOOR} \\\n"
    "    && apt-get dist-clean\n"
)
PYTHON_STAGES = 4


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


def tracked_image_files():
    return subprocess.run(
        ["git", "ls-files", ":(icase)*dockerfile*", ":(icase)*containerfile*"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()


def test_every_image_builds_from_one_digest_pinned_python_base():
    tracked = tracked_image_files()
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


def test_the_image_scan_applies_and_reports_the_exceptions():
    text = IMAGE_SCAN.read_text()
    assert "--ignorefile .trivyignore.yaml --show-suppressed" in text


def test_the_image_scan_runs_on_pull_requests_that_change_an_image():
    text = IMAGE_SCAN.read_text()
    paths = re.search(r"^on:\n  pull_request:\n    paths:\n((?:      - \S+\n)+)  schedule:\n", text, re.MULTILINE)
    assert paths
    assert set(re.findall(r"- (\S+)", paths.group(1))) == {
        *tracked_image_files(),
        ".github/workflows/image-scan.yml",
        ".trivyignore.yaml",
        "deploy/kubernetes/webhook-requirements.txt",
        "examples/live-run/package-lock.json",
        "examples/live-run/package.json",
        "examples/quickstart/trace-requirements.txt",
        "requirements-ci.txt",
    }
    assert '    - cron: "23 5 * * 1"\n  workflow_dispatch:\n' in text


def test_the_image_scan_builds_and_scans_every_tracked_image_in_its_own_job():
    text = IMAGE_SCAN.read_text()
    assert set(re.findall(r"^            build: --file (\S+)", text, re.MULTILINE)) == set(tracked_image_files())
    assert "    strategy:\n      fail-fast: false\n      matrix:\n" in text
    assert "    if: always()\n    needs: scan\n" in text
    assert 'test "$RESULT" = success' in text


def test_the_image_scan_downloads_the_database_once_per_day():
    text = IMAGE_SCAN.read_text()
    assert "key=trivy-db-${TRIVY_VERSION}-$(date -u +%F)" in text
    assert "--download-db-only" in text
    assert "key: ${{ needs.db.outputs.key }}\n          fail-on-cache-miss: true\n" in text
    assert "--skip-db-update" in text


def test_the_image_scan_checks_libzstd_in_the_built_image():
    text = IMAGE_SCAN.read_text()
    assert f"LIBZSTD_FLOOR: {LIBZSTD_FLOOR}\n" in text
    assert "--entrypoint dpkg-query \"$IMAGE\" --show --showformat='${Version}' libzstd1" in text
    assert 'dpkg --compare-versions "$version" ge "$LIBZSTD_FLOOR"' in text


def test_every_python_stage_installs_the_fixed_libzstd():
    tracked = tracked_image_files()
    stages = [
        stage
        for path in tracked
        for stage in re.split(r"^(?=FROM )", (ROOT / path).read_text(), flags=re.MULTILINE)
        if re.match(r"FROM (?:--platform=\S+ )?python:", stage)
    ]
    assert len(stages) >= PYTHON_STAGES
    for stage in stages:
        assert re.search(r"^FROM \S.*\n\n" + re.escape(LIBZSTD_UPGRADE), stage, re.MULTILINE), stage
