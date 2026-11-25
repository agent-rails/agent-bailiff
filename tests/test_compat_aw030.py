import os
import subprocess
from pathlib import Path

import pytest
from test_decide import make_v1_root
from test_task_issue import DECIDER, issued

from agent_bailiff.task.task_file import TaskFile

AW_030_VENV = os.environ.get("AW_030_VENV")
pytestmark = pytest.mark.skipif(not AW_030_VENV, reason="set AW_030_VENV to a venv with agent-warrant 0.3.0")
DECODE = """
import json
import sys
from importlib.metadata import version

from agent_warrant.task_root import TaskRoot

assert version("agent-warrant") == "0.3.0", version("agent-warrant")
with open(sys.argv[1]) as stream:
    document = json.load(stream)
try:
    TaskRoot.decode(document["task_root"])
except ValueError as exc:
    print(f"refused: {exc}")
else:
    print("decoded")
"""


def decode_with_030(tmp_path, task):
    path = tmp_path / "task.json"
    path.write_bytes(task.encode())
    python = Path(AW_030_VENV) / "bin" / "python"
    result = subprocess.run(
        [python, "-I", "-c", DECODE, path], cwd=tmp_path, capture_output=True, text=True, check=True, timeout=30
    )
    return result.stdout.strip()


def test_agent_warrant_030_refuses_a_v2_task_file(tmp_path):
    assert decode_with_030(tmp_path, issued()).startswith("refused: scope:")


def test_agent_warrant_030_decodes_a_v1_task_file(tmp_path):
    assert decode_with_030(tmp_path, TaskFile(make_v1_root(), DECIDER)) == "decoded"
