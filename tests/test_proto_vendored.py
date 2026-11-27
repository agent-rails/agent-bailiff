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


def copied_image_inputs():
    build_args = re.findall(r"--build-arg (\w+)=(\S+)", IMAGE_SCAN.read_text())
    sources = set()
    for path in tracked_image_files():
        text = (ROOT / path).read_text().replace("\\\n", " ")
        values = [*re.findall(r"^ARG (\w+)=(\S+)", text, re.MULTILINE), *build_args]
        for instruction in re.findall(r"^(?:COPY|ADD) (.+)$", text, re.MULTILINE):
            words = instruction.split()
            if any(word.startswith("--from=") for word in words):
                continue
            for source in [word for word in words if not word.startswith("--")][:-1]:
                if "://" in source:
                    continue
                names = re.findall(r"\$\{(\w+)\}", source)
                assert len(names) <= 1, source
                if not names:
                    sources.add(source)
                    continue
                expanded = {value for name, value in values if name == names[0]}
                assert expanded, source
                sources.update(source.replace(f"${{{names[0]}}}", value) for value in expanded)
    return sources


def test_the_image_scan_runs_on_every_pull_request_and_scans_when_an_image_input_changes():
    text = IMAGE_SCAN.read_text()
    assert "on:\n  pull_request:\n  schedule:\n" in text
    assert '    - cron: "23 5 * * *"\n  workflow_dispatch:\n' in text
    diff = re.search(
        r'^          changed="\$\(git diff --name-only "origin/\$BASE_REF\.\.\.HEAD" -- \\\n'
        r'((?:            \S+(?: \\|\)")\n)+)',
        text,
        re.MULTILINE,
    )
    assert diff
    listed = re.findall(r"^            ([^\s)]+)(?: \\|\)\")$", diff.group(1), re.MULTILINE)
    assert len(listed) == len(diff.group(1).splitlines())
    assert set(listed) == {
        *copied_image_inputs(),
        *tracked_image_files(),
        ".dockerignore",
        ".github/workflows/image-scan.yml",
        ".trivyignore.yaml",
        "pyproject.toml",
    }
    included = re.findall(r"^!(\S+)$", (ROOT / ".dockerignore").read_text(), re.MULTILINE)
    assert included
    assert all(any(path == entry or path.startswith(f"{entry}/") for entry in listed) for path in included), included
    assert "          persist-credentials: false\n          fetch-depth: 0\n" in text
    assert "          EVENT: ${{ github.event_name }}\n          BASE_REF: ${{ github.base_ref }}\n" in text
    assert 'if [ "$EVENT" != pull_request ]; then\n            echo "images=true" >> "$GITHUB_OUTPUT"\n' in text
    assert "  db:\n    needs: changes\n    if: needs.changes.outputs.images == 'true'\n" in text
    assert "  scan:\n    needs: db\n" in text


def test_the_image_scan_builds_and_scans_every_tracked_image_in_its_own_job():
    text = IMAGE_SCAN.read_text()
    assert set(re.findall(r"^            build: --file (\S+)", text, re.MULTILINE)) == set(tracked_image_files())
    assert "    strategy:\n      fail-fast: false\n      matrix:\n" in text
    assert "          BUILD: ${{ matrix.build }}\n" in text
    assert 'read -ra build <<< "$BUILD"\n          docker build "${build[@]}" --tag "$IMAGE" .\n' in text
    runs = re.findall(r"^ +(?:- )?run: (?:[|>]-?\n((?:(?: {10,}.*)?\n)+)|(.*)\n)", text, re.MULTILINE)
    assert runs and not any("${{" in block + line for block, line in runs)
    assert "    if: always()\n    needs: [changes, db, scan]\n" in text
    assert (
        '      - run: test "$RESULTS" = "success true success success"'
        ' || test "$RESULTS" = "success false skipped skipped"\n'
        "        env:\n"
        "          RESULTS: ${{ needs.changes.result }} ${{ needs.changes.outputs.images }}"
        " ${{ needs.db.result }} ${{ needs.scan.result }}\n"
    ) in text


def test_the_image_scan_downloads_the_database_once_per_day():
    text = IMAGE_SCAN.read_text()
    assert "key=trivy-db-${TRIVY_VERSION}-$(date -u +%F)" in text
    assert "--download-db-only" in text
    assert "key: ${{ needs.db.outputs.key }}\n          fail-on-cache-miss: true\n" in text
    assert "--skip-db-update --skip-java-db-update\n" in text


def test_the_image_scan_refuses_a_database_older_than_two_days():
    text = IMAGE_SCAN.read_text()
    assert (
        '          metadata="$RUNNER_TEMP/trivy-cache/db/metadata.json"\n'
        '          jq . "$metadata"\n'
        '          updated="$(jq -er .UpdatedAt "$metadata")"\n'
        '          test "$(date -u -d "$updated" +%s)" -ge "$(( $(date -u +%s) - DB_MAX_AGE_SECONDS ))"\n'
        "        env:\n"
        "          DB_MAX_AGE_SECONDS: 172800\n"
        "\n"
        "  scan:\n"
    ) in text


def test_the_image_scan_checks_libzstd_in_the_built_image():
    text = IMAGE_SCAN.read_text()
    assert f"LIBZSTD_FLOOR: {LIBZSTD_FLOOR}\n" in text
    assert (
        '--entrypoint dpkg-query "$IMAGE" --show --showformat=\'${db:Status-Abbrev} ${Version}\\n\' libzstd1)"\n'
        '          echo "libzstd1 $status"\n'
        '          test "$(wc -l <<< "$status")" -eq 1\n'
        '          test "${status:0:4}" = "ii  "\n'
        '          dpkg --compare-versions "${status:4}" ge "$LIBZSTD_FLOOR"\n'
    ) in text


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
