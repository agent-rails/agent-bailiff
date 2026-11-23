"""The agent's per-task signing keys, kept in a key directory only the agent's uid can open."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from agent_warrant.identity import encode_public_key, is_valid_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.custodian.files import OwnedFileError, replace_at

KEY_DIR_MODE = 0o700
KEY_MODE = 0o600
KEY_SUFFIX = ".key"
STAGED_SUFFIX = ".new"


class AgentKeyError(Exception):
    pass


def generate_agent_key(key_dir: Path) -> str:
    dir_fd = open_key_dir(key_dir)
    try:
        private_key = Ed25519PrivateKey.generate()
        subject: str = encode_public_key(private_key.public_key())
        replace_at(dir_fd, subject + KEY_SUFFIX, "agent key", private_key.private_bytes_raw(), KEY_MODE)
    except OwnedFileError as exc:
        raise AgentKeyError(str(exc)) from None
    finally:
        os.close(dir_fd)
    return subject


def prune(key_dir: Path, keep: str) -> list[str]:
    dir_fd = open_key_dir(key_dir)
    try:
        subjects = _key_subjects(dir_fd)
        newest = max(subjects, key=lambda subject: (subjects[subject], subject), default=None)
        removed = sorted(subject for subject in subjects if subject not in (keep, newest))
        names = [subject + KEY_SUFFIX for subject in removed] + _staged_names(dir_fd)
        for name in names:
            os.unlink(name, dir_fd=dir_fd)
        if names:
            os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return removed


def open_key_dir(key_dir: Path) -> int:
    try:
        dir_fd = os.open(key_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise AgentKeyError(f"cannot open the key directory {key_dir}: {exc.strerror}") from None
    info = os.fstat(dir_fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != KEY_DIR_MODE:
        os.close(dir_fd)
        raise AgentKeyError(
            f"the key directory {key_dir} must be owned by uid {os.geteuid()} with mode {oct(KEY_DIR_MODE)}"
        )
    return dir_fd


def _key_subjects(dir_fd: int) -> dict[str, int]:
    subjects: dict[str, int] = {}
    for name in os.listdir(dir_fd):
        subject = name.removesuffix(KEY_SUFFIX)
        if subject == name or not is_valid_public_key(subject):
            continue
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            subjects[subject] = info.st_mtime_ns
    return subjects


def _staged_names(dir_fd: int) -> list[str]:
    return sorted(
        name for name in os.listdir(dir_fd) if name.startswith(".") and name.endswith(KEY_SUFFIX + STAGED_SUFFIX)
    )
