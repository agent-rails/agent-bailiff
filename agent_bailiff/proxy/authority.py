"""The two-user precondition: the proxy refuses to start when its OS user can reach the Docker daemon."""

from __future__ import annotations

import errno
import os
import pwd
import socket
import stat
from collections.abc import Mapping
from pathlib import Path

SYSTEM_SOCKET = "/var/run/docker.sock"
HOME_SOCKETS = (".docker/run/docker.sock", ".orbstack/run/docker.sock", ".colima/default/docker.sock")
RUNTIME_SOCKET = "docker.sock"
USER_RUNTIME_DIR = "/run/user/{uid}"
UNIX_SCHEME = "unix://"
CONNECT_TIMEOUT_SECONDS = 0.5
ABSENT = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ENOTSOCK})
ADOPT_SECTION = "docs/ADOPT.md, Two users"


class SharedAuthority(Exception):
    pass


def reachable_endpoints(environ: Mapping[str, str]) -> list[str]:
    found: list[str] = []
    docker_host = environ.get("DOCKER_HOST", "")
    if docker_host and not docker_host.startswith(UNIX_SCHEME):
        found.append(f"DOCKER_HOST={docker_host} (not a local unix socket; not tested, counted as reachable)")
    for path in _candidate_sockets(environ):
        if _can_connect(path):
            found.append(f"the Docker daemon socket {path}")
    return found


def check_two_user(environ: Mapping[str, str], *, allow_shared_user: bool) -> str | None:
    found = reachable_endpoints(environ)
    if not found:
        return None
    listed = "; ".join(found)
    if allow_shared_user:
        return (
            f"--allow-shared-user: this user can reach {listed}; an agent running as this user can mint its own "
            f"tasks and read the service credential ({ADOPT_SECTION})"
        )
    raise SharedAuthority(
        f"this user can reach {listed}; anyone who reaches the Docker daemon can mint tasks and read the service "
        f"credential. Run the proxy as a user that cannot ({ADOPT_SECTION}), or pass --allow-shared-user for "
        "single-user development only"
    )


def _candidate_sockets(environ: Mapping[str, str]) -> list[Path]:
    paths = [Path(SYSTEM_SOCKET)]
    docker_host = environ.get("DOCKER_HOST", "")
    if docker_host.startswith(UNIX_SCHEME):
        paths.append(Path(docker_host.removeprefix(UNIX_SCHEME)))
    for home in (Path.home(), Path(pwd.getpwuid(os.getuid()).pw_dir)):
        paths.extend(home / relative for relative in HOME_SOCKETS)
    runtime_dir = environ.get("XDG_RUNTIME_DIR", "")
    if runtime_dir:
        paths.append(Path(runtime_dir) / RUNTIME_SOCKET)
    paths.append(Path(USER_RUNTIME_DIR.format(uid=os.getuid())) / RUNTIME_SOCKET)
    return list(dict.fromkeys(paths))


def _can_connect(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            probe.connect(str(path))
        except (TimeoutError, BlockingIOError):
            return True
        except OSError as exc:
            return _unconnectable_means_reachable(path, exc.errno)
    return True


def _unconnectable_means_reachable(path: Path, error: int | None) -> bool:
    if error in ABSENT:
        return False
    if error == errno.EACCES:
        return os.access(path, os.W_OK)
    if error == errno.ECONNREFUSED:
        return _is_socket_or_unknown(path)
    return True


def _is_socket_or_unknown(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return True
