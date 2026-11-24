import errno
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agent_bailiff.proxy import authority
from agent_bailiff.proxy.authority import SharedAuthority, check_two_user, reachable_endpoints

ROUTES = {"routes": [{"service": "demo", "name": "get", "tool": "demo.get", "resource": "demo/{id}",
                      "schema": [{"name": "id", "kind": "identifier"}]}]}  # fmt: skip
TCP_HOST = "tcp://127.0.0.1:2375"


@pytest.fixture
def sockets():
    directory = Path(tempfile.mkdtemp(prefix="bw-", dir="/tmp"))
    servers = []

    def bind(name, *, listening):
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        if listening:
            server.listen(8)
            servers.append(server)
        else:
            server.close()
        return path

    bind.directory = directory
    yield bind
    for server in servers:
        server.close()
    shutil.rmtree(directory)


@pytest.fixture
def isolated(sockets, monkeypatch):
    home = sockets.directory / "home"
    home.mkdir()
    monkeypatch.setattr(authority, "SYSTEM_SOCKET", str(sockets.directory / "absent.sock"))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(authority, "USER_RUNTIME_DIR", str(sockets.directory / "run-user-{uid}"))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: pwd.struct_passwd(("u", "x", uid, 0, "", str(home), "sh")))
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)


def named(path):
    return [f"the Docker daemon socket {path}"]


def test_a_listening_system_socket_is_reachable(sockets, isolated, monkeypatch):
    path = sockets("system.sock", listening=True)
    monkeypatch.setattr(authority, "SYSTEM_SOCKET", str(path))
    assert reachable_endpoints(os.environ) == named(path)


@pytest.mark.parametrize(
    "relative", ["home/.docker/run/docker.sock", "home/.orbstack/run/docker.sock", "home/.colima/default/docker.sock"]
)
def test_a_listening_home_socket_is_reachable(sockets, isolated, relative):
    path = sockets(relative, listening=True)
    assert reachable_endpoints(os.environ) == named(path)


def test_a_listening_runtime_dir_socket_is_reachable(sockets, isolated, monkeypatch):
    path = sockets("run/docker.sock", listening=True)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(path.parent))
    assert reachable_endpoints(os.environ) == named(path)


def test_a_unix_docker_host_is_reachable_when_listening(sockets, isolated, monkeypatch):
    path = sockets("custom.sock", listening=True)
    monkeypatch.setenv("DOCKER_HOST", f"unix://{path}")
    assert reachable_endpoints(os.environ) == named(path)


def test_no_socket_means_nothing_is_reachable(isolated):
    assert reachable_endpoints(os.environ) == []


def test_a_socket_file_with_no_listener_is_reachable_because_a_daemon_can_start_later(sockets, isolated):
    path = sockets("home/.docker/run/docker.sock", listening=False)
    assert reachable_endpoints(os.environ) == named(path)


def test_the_passwd_home_is_probed_when_home_points_elsewhere(sockets, isolated, monkeypatch):
    path = sockets("passwd-home/.docker/run/docker.sock", listening=True)
    passwd_home = str(sockets.directory / "passwd-home")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: pwd.struct_passwd(("u", "x", uid, 0, "", passwd_home, "sh")))
    assert reachable_endpoints(os.environ) == named(path)


def test_the_uid_runtime_dir_is_probed_when_xdg_runtime_dir_is_unset(sockets, isolated):
    path = sockets(f"run-user-{os.getuid()}/docker.sock", listening=True)
    assert reachable_endpoints(os.environ) == named(path)


def test_the_uid_runtime_dir_is_probed_when_xdg_runtime_dir_points_elsewhere(sockets, isolated, monkeypatch):
    path = sockets(f"run-user-{os.getuid()}/docker.sock", listening=True)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(sockets.directory / "elsewhere"))
    assert reachable_endpoints(os.environ) == named(path)


def refuse_connect(monkeypatch, path, code):
    real_connect = socket.socket.connect

    def refuse(self, address):
        if address == str(path):
            raise OSError(code, os.strerror(code)) if code is not None else OSError("no errno")
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.mark.parametrize("code", [errno.ENOENT, errno.ENOTDIR, errno.ENOTSOCK])
def test_an_absent_path_is_not_reachable(sockets, isolated, monkeypatch, code):
    path = sockets("home/.docker/run/docker.sock", listening=True)
    refuse_connect(monkeypatch, path, code)
    assert reachable_endpoints(os.environ) == []


def test_a_permission_error_on_an_unwritable_socket_is_not_reachable(sockets, isolated, monkeypatch):
    path = sockets("home/.docker/run/docker.sock", listening=True)
    refuse_connect(monkeypatch, path, errno.EACCES)
    monkeypatch.setattr(os, "access", lambda target, mode: False)
    assert reachable_endpoints(os.environ) == []


def test_a_permission_error_on_a_writable_socket_is_reachable(sockets, isolated, monkeypatch):
    path = sockets("home/.docker/run/docker.sock", listening=True)
    refuse_connect(monkeypatch, path, errno.EACCES)
    monkeypatch.setattr(os, "access", lambda target, mode: True)
    assert reachable_endpoints(os.environ) == named(path)


@pytest.mark.parametrize("code", [errno.EPERM, errno.EAGAIN, errno.ECONNREFUSED, errno.EINVAL, None])
def test_any_other_connect_error_on_a_socket_is_reachable(sockets, isolated, monkeypatch, code):
    path = sockets("home/.docker/run/docker.sock", listening=True)
    refuse_connect(monkeypatch, path, code)
    assert reachable_endpoints(os.environ) == named(path)


def test_a_regular_file_at_a_candidate_path_is_not_reachable(sockets, isolated):
    path = sockets.directory / "home" / ".docker" / "run" / "docker.sock"
    path.parent.mkdir(parents=True)
    path.write_text("")
    assert reachable_endpoints(os.environ) == []


def test_a_tcp_docker_host_is_reachable_without_being_tested(isolated, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", TCP_HOST)
    found = reachable_endpoints(os.environ)
    assert len(found) == 1
    assert TCP_HOST in found[0]
    assert "not tested" in found[0]


def test_a_connect_that_times_out_is_reachable(sockets, isolated, monkeypatch):
    path = sockets("custom.sock", listening=True)
    monkeypatch.setenv("DOCKER_HOST", f"unix://{path}")

    real_connect = socket.socket.connect

    def stall(self, address):
        if address == str(path):
            raise TimeoutError
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", stall)
    assert reachable_endpoints(os.environ) == named(path)


def test_a_path_too_long_for_a_socket_is_reachable(isolated, monkeypatch):
    long_path = "/x" * 200
    monkeypatch.setenv("DOCKER_HOST", f"unix://{long_path}")
    assert reachable_endpoints(os.environ) == named(long_path)


def test_one_socket_named_twice_is_reported_once(sockets, isolated, monkeypatch):
    path = sockets("system.sock", listening=True)
    monkeypatch.setattr(authority, "SYSTEM_SOCKET", str(path))
    monkeypatch.setenv("DOCKER_HOST", f"unix://{path}")
    assert reachable_endpoints(os.environ) == named(path)


def test_a_reachable_daemon_is_refused_and_the_message_names_it(sockets, isolated, monkeypatch):
    path = sockets("system.sock", listening=True)
    monkeypatch.setattr(authority, "SYSTEM_SOCKET", str(path))
    with pytest.raises(SharedAuthority) as caught:
        check_two_user(os.environ, allow_shared_user=False)
    assert str(path) in str(caught.value)
    assert "ADOPT.md" in str(caught.value)
    assert "--allow-shared-user" in str(caught.value)


def test_a_tcp_docker_host_is_refused_and_the_message_says_so(isolated, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.5:2376")
    with pytest.raises(SharedAuthority, match="tcp://10.0.0.5:2376"):
        check_two_user(os.environ, allow_shared_user=False)


def test_nothing_reachable_passes_without_a_warning(isolated):
    assert check_two_user(os.environ, allow_shared_user=False) is None
    assert check_two_user(os.environ, allow_shared_user=True) is None


def test_the_flag_turns_the_refusal_into_a_warning_naming_the_endpoint(sockets, isolated, monkeypatch):
    path = sockets("system.sock", listening=True)
    monkeypatch.setattr(authority, "SYSTEM_SOCKET", str(path))
    warning = check_two_user(os.environ, allow_shared_user=True)
    assert warning is not None
    assert str(path) in warning
    assert "\n" not in warning


def run_proxy(tmp_path, *extra):
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps(ROUTES))
    return subprocess.run(
        [
            sys.executable, "-m", "agent_bailiff.cli", "proxy", "run",
            "--task-file", str(tmp_path / "task.json"), "--key-dir", str(tmp_path),
            "--gateway-url", "http://127.0.0.1:1/mcp", "--routes", str(routes), *extra,
        ],
        input=b"",
        capture_output=True,
        env={**os.environ, "DOCKER_HOST": TCP_HOST},
        timeout=30,
        check=False,
    )  # fmt: skip


def test_the_proxy_refuses_to_start_with_a_reachable_daemon(tmp_path):
    done = run_proxy(tmp_path)
    assert done.returncode == 1, done.stderr
    assert b"proxy run refused" in done.stderr
    assert TCP_HOST.encode() in done.stderr
    assert b"proxy routes sha256" not in done.stderr


def test_the_flag_starts_the_proxy_with_one_warning(tmp_path):
    done = run_proxy(tmp_path, "--allow-shared-user")
    assert done.returncode == 0, done.stderr
    assert done.stderr.count(b"--allow-shared-user") == 1
    assert TCP_HOST.encode() in done.stderr
    assert b"proxy routes sha256" in done.stderr
