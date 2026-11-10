from __future__ import annotations

import os
from pathlib import Path

FORBIDDEN_MODE_BITS = 0o022


def open_private_dir(directory: Path) -> int:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & FORBIDDEN_MODE_BITS:
        os.close(fd)
        raise PermissionError(f"{directory} must be owned by uid {os.geteuid()} and not writable by group or others")
    return fd
