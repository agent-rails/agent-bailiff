import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements-ci.txt"
INSTALL_TIMEOUT_SECONDS = 600
RUN_TIMEOUT_SECONDS = 60
pytestmark = [
    pytest.mark.skipif(
        os.environ.get("AGENT_BAILIFF_TEST_INSTALL") != "1",
        reason="set AGENT_BAILIFF_TEST_INSTALL=1 to install the package from git",
    ),
    pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not installed"),
]


def install_command(revision):
    return ["uv", "tool", "install", "--python", "3.13", "--constraints", str(LOCK), f"git+file://{ROOT}@{revision}"]


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    home = tmp_path_factory.mktemp("uv-tool")
    env = {
        **os.environ,
        "UV_TOOL_DIR": str(home / "tools"),
        "UV_TOOL_BIN_DIR": str(home / "bin"),
        "UV_CACHE_DIR": str(home / "cache"),
    }
    revision = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    done = subprocess.run(
        install_command(revision),
        env=env,
        capture_output=True,
        text=True,
        timeout=INSTALL_TIMEOUT_SECONDS,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return home / "bin" / "agent-bailiff"


@pytest.mark.parametrize("arguments", [["--help"]])
def test_the_installed_cli_starts(installed, arguments):
    done = subprocess.run(
        [str(installed), *arguments], capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS, check=False
    )
    assert done.returncode == 0, done.stderr
    assert "usage: agent-bailiff" in done.stdout
