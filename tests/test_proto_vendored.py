import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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


def test_every_trivy_run_ignores_a_trivy_config_in_the_checkout():
    runs = re.findall(r'"\$RUNNER_TEMP/trivy" image .*', IMAGE_SCAN.read_text())
    assert len(runs) == 2
    assert all("--config /dev/null" in run for run in runs), runs


def excluded_from_the_changes():
    diff = re.search(
        r"^changed=\"\$\(git diff --name-only HEAD\^1 HEAD -- \. \\\n((?:  ':\(exclude\)[^']+'(?: \\|\)\")\n)+)",
        changes_script(),
        re.MULTILINE,
    )
    assert diff
    excluded = re.findall(r"^  ':\(exclude\)([^']+)'(?: \\|\)\")$", diff.group(1), re.MULTILINE)
    assert len(excluded) == len(diff.group(1).splitlines())
    return excluded


def test_the_image_scan_runs_on_every_pull_request_and_scans_unless_it_changes_only_docs_or_tests():
    text = IMAGE_SCAN.read_text()
    assert "on:\n  pull_request:\n  schedule:\n" in text
    assert '    - cron: "23 5 * * *"\n  workflow_dispatch:\n' in text
    assert "\nconcurrency:\n  group: image-scan-${{ github.ref }}\n  cancel-in-progress: true\n\n" in text
    excluded = excluded_from_the_changes()
    assert excluded == ["docs", "tests"]
    ignored = (ROOT / ".dockerignore").read_text().splitlines()
    included = [line[1:] for line in ignored if line.startswith("!")]
    assert included
    for path in excluded:
        assert path in ignored
        assert not any(entry.split("/")[0] == path for entry in included), included
        assert not any(image.split("/")[0] == path for image in tracked_image_files())
    assert "          persist-credentials: false\n          fetch-depth: 2\n" in text
    assert "      - id: diff\n        env:\n          EVENT: ${{ github.event_name }}\n        run: |\n" in text
    assert "  db:\n    needs: changes\n    if: needs.changes.outputs.images == 'true'\n" in text
    assert "  scan:\n    needs: db\n" in text


def changes_script():
    block = re.search(
        r"^      - id: diff\n(?:        .*\n)*?        run: \|\n((?:          .*\n)+)",
        IMAGE_SCAN.read_text(),
        re.MULTILINE,
    )
    assert block
    return textwrap.dedent(block.group(1))


def git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        env={"PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"},
        capture_output=True,
        check=True,
        timeout=30,
    )


def commit_file(repo, path, message):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"{message}\n")
    git(repo, "add", path)
    git(repo, "commit", "--quiet", "--no-gpg-sign", "--message", message)


def new_repository(tmp_path, name):
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch", "main")
    commit_file(repo, "README.md", "base")
    return repo


def merged_pull_request(tmp_path, name, path, moved_from=None):
    repo = new_repository(tmp_path, name)
    if moved_from:
        commit_file(repo, moved_from, "base")
    git(repo, "switch", "--quiet", "--create", "pull")
    if moved_from:
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        git(repo, "mv", moved_from, path)
        git(repo, "commit", "--quiet", "--no-gpg-sign", "--message", "pull")
    else:
        commit_file(repo, path, "pull")
    git(repo, "switch", "--quiet", "main")
    commit_file(repo, "agent_bailiff/main_only.py", "main")
    git(repo, "switch", "--quiet", "--detach")
    git(repo, "merge", "--quiet", "--no-ff", "--no-gpg-sign", "--message", "merge", "pull")
    return repo


def run_changes(repo, event):
    output = repo.parent / f"{repo.name}-{event}.output"
    output.touch()
    result = subprocess.run(
        ["bash", "-e", "-c", changes_script()],
        cwd=repo,
        env={"PATH": os.environ["PATH"], "HOME": str(repo), "EVENT": event, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.returncode, output.read_text()


@pytest.mark.parametrize("path", ["docs/guide.md", "tests/test_policy.py"])
def test_the_changes_job_skips_the_scan_when_a_pull_request_changes_only_docs_or_tests(tmp_path, path):
    repo = merged_pull_request(tmp_path, "skipped", path)
    assert run_changes(repo, "pull_request") == (0, "images=false\n")


@pytest.mark.parametrize("path", ["trivy-secret.yaml", "scripts/build.sh", "docsite/guide.md", ".github/CODEOWNERS"])
def test_the_changes_job_scans_when_a_pull_request_changes_any_other_path(tmp_path, path):
    repo = merged_pull_request(tmp_path, "other", path)
    assert run_changes(repo, "pull_request") == (0, "images=true\n")


def test_the_changes_job_scans_when_a_pull_request_moves_an_image_input_into_docs(tmp_path):
    repo = merged_pull_request(tmp_path, "moved", "docs/rule.py", moved_from="examples/quickstart/rule.py")
    assert run_changes(repo, "pull_request") == (0, "images=true\n")


def test_the_changes_job_scans_when_a_pull_request_changes_an_image_input(tmp_path):
    repo = merged_pull_request(tmp_path, "image", "agent_bailiff/policy.py")
    assert run_changes(repo, "pull_request") == (0, "images=true\n")


def test_the_changes_job_fails_without_the_merge_parent(tmp_path):
    repo = new_repository(tmp_path, "shallow")
    returncode, output = run_changes(repo, "pull_request")
    assert returncode != 0
    assert output == ""


def test_the_changes_job_scans_on_schedule_and_dispatch(tmp_path):
    repo = new_repository(tmp_path, "scheduled")
    assert run_changes(repo, "schedule") == (0, "images=true\n")
    assert run_changes(repo, "workflow_dispatch") == (0, "images=true\n")


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
    assert "--download-db-only --cache-dir" in text
    assert "--download-java-db-only" not in text
    assert "trivy-cache/java-db" not in text
    cached = "          path: ${{ runner.temp }}/trivy-cache/db\n"
    assert text.count(cached) == 2
    assert f"{cached}          key: ${{{{ steps.key.outputs.key }}}}\n" in text
    assert f"{cached}          key: ${{{{ needs.db.outputs.key }}}}\n          fail-on-cache-miss: true\n" in text
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
