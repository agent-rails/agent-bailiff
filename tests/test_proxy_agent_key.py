import os
import stat
import subprocess
import sys

import pytest
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.cli import main
from agent_bailiff.proxy import agent_key
from agent_bailiff.proxy.agent_key import AgentKeyError, generate_agent_key, prune

SHORT_WRITE = """
import resource, signal, sys
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (16, 16))
from agent_bailiff.cli import main
sys.exit(main(["proxy", "keygen", "--key-dir", sys.argv[1]]))
"""


@pytest.fixture
def key_dir(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


def make_key(key_dir, mtime):
    subject = generate_agent_key(key_dir)
    os.utime(key_dir / f"{subject}.key", ns=(mtime, mtime))
    return subject


def test_keygen_writes_an_owner_only_key_named_by_its_public_key(key_dir):
    subject = generate_agent_key(key_dir)
    path = key_dir / f"{subject}.key"
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid()
    seed = path.read_bytes()
    assert len(seed) == 32
    assert encode_public_key(Ed25519PrivateKey.from_private_bytes(seed).public_key()) == subject
    assert os.listdir(key_dir) == [f"{subject}.key"]


def test_each_keygen_makes_a_new_key(key_dir):
    assert generate_agent_key(key_dir) != generate_agent_key(key_dir)


def test_the_cli_prints_only_the_subject(key_dir, capsys):
    assert main(["proxy", "keygen", "--key-dir", str(key_dir)]) == 0
    printed = capsys.readouterr().out
    assert printed.endswith("\n")
    assert os.listdir(key_dir) == [f"{printed.strip()}.key"]


def test_keygen_refuses_a_symlinked_key_dir(key_dir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(key_dir)
    with pytest.raises(AgentKeyError, match="cannot open the key directory"):
        generate_agent_key(link)


@pytest.mark.parametrize("mode", [0o750, 0o755, 0o777, 0o500])
def test_keygen_refuses_a_key_dir_others_can_open(key_dir, mode):
    os.chmod(key_dir, mode)
    try:
        with pytest.raises(AgentKeyError, match="mode 0o700"):
            generate_agent_key(key_dir)
    finally:
        os.chmod(key_dir, 0o700)
    assert os.listdir(key_dir) == []


def test_keygen_refuses_a_key_dir_another_uid_owns(key_dir, monkeypatch):
    monkeypatch.setattr(agent_key.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(AgentKeyError, match="must be owned by uid"):
        generate_agent_key(key_dir)
    assert os.listdir(key_dir) == []


def test_keygen_refuses_a_missing_key_dir(tmp_path):
    with pytest.raises(AgentKeyError, match="cannot open the key directory"):
        generate_agent_key(tmp_path / "missing")


def test_the_cli_refuses_without_printing_a_subject(tmp_path, capsys):
    assert main(["proxy", "keygen", "--key-dir", str(tmp_path / "missing")]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "proxy keygen refused" in captured.err


def test_a_short_write_leaves_no_key_and_prints_no_subject(key_dir):
    completed = subprocess.run(
        [sys.executable, "-c", SHORT_WRITE, str(key_dir)], capture_output=True, text=True, timeout=30
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "wrote 16 of 32 bytes" in completed.stderr
    assert os.listdir(key_dir) == []


def test_a_staged_leftover_does_not_block_keygen_and_prune_removes_it(key_dir):
    leftover = key_dir / f".{encode_public_key(Ed25519PrivateKey.generate().public_key())}.key.new"
    leftover.write_bytes(b"partial")
    subject = generate_agent_key(key_dir)
    assert prune(key_dir, subject) == []
    assert os.listdir(key_dir) == [f"{subject}.key"]


def test_prune_keeps_the_loaded_key_and_the_newest(key_dir):
    oldest = make_key(key_dir, 1_000_000_000)
    loaded = make_key(key_dir, 2_000_000_000)
    stale = make_key(key_dir, 3_000_000_000)
    pending = make_key(key_dir, 4_000_000_000)
    assert prune(key_dir, loaded) == sorted([oldest, stale])
    assert sorted(os.listdir(key_dir)) == sorted([f"{loaded}.key", f"{pending}.key"])


def test_prune_keeps_one_key_when_the_loaded_key_is_newest(key_dir):
    older = make_key(key_dir, 1_000_000_000)
    loaded = make_key(key_dir, 2_000_000_000)
    assert prune(key_dir, loaded) == [older]
    assert os.listdir(key_dir) == [f"{loaded}.key"]


def test_prune_leaves_files_that_are_not_agent_keys(key_dir, tmp_path):
    loaded = generate_agent_key(key_dir)
    (key_dir / "notes.txt").write_text("x")
    (key_dir / "not-a-key.key").write_text("x")
    target = tmp_path / "target.key"
    target.write_text("x")
    other = encode_public_key(Ed25519PrivateKey.generate().public_key())
    (key_dir / f"{other}.key").symlink_to(target)
    assert prune(key_dir, loaded) == []
    assert sorted(os.listdir(key_dir)) == sorted([f"{loaded}.key", "notes.txt", "not-a-key.key", f"{other}.key"])
