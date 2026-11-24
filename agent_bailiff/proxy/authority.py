"""The two-user precondition: the proxy refuses to start when its OS user can reach the Docker daemon."""

from __future__ import annotations

import errno
import socket
from collections.abc import Mapping
from pathlib import Path

SYSTEM_SOCKET = "/var/run/docker.sock"
HOME_SOCKETS = (".docker/run/docker.sock", ".orbstack/run/docker.sock", ".colima/default/docker.sock")
RUNTIME_SOCKET = "docker.sock"
UNIX_SCHEME = "unix://"
CONNECT_TIMEOUT_SECONDS = 0.5
UNREACHABLE = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.EPERM, errno.ECONNREFUSED, errno.ENOTSOCK})
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
    home = Path.home()
    paths.extend(home / relative for relative in HOME_SOCKETS)
    runtime_dir = environ.get("XDG_RUNTIME_DIR", "")
    if runtime_dir:
        paths.append(Path(runtime_dir) / RUNTIME_SOCKET)
    return list(dict.fromkeys(paths))


def _can_connect(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            probe.connect(str(path))
        except (TimeoutError, BlockingIOError):
            return True
        except OSError as exc:
            return exc.errno is not None and exc.errno not in UNREACHABLE
    return True
