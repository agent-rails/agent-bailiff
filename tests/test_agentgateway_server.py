import os
import shutil
import stat
import tempfile
from pathlib import Path

import grpc
import pytest

from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.adapters.agentgateway.processors import passed, refuse
from agent_bailiff.adapters.agentgateway.server import ProcessorLocked, ProcessorServer

UID = os.geteuid()
GID = os.getegid()
CHECK_REQUEST = "/agentgateway.dev.ext_mcp.ExtMcp/CheckRequest"
CHECK_RESPONSE = "/agentgateway.dev.ext_mcp.ExtMcp/CheckResponse"


class RecordingProcessor:
    def __init__(self):
        self.messages = []

    def check_request(self, message):
        self.messages.append(message)
        return refuse("out_of_scope") if message.method == "tools/call" else passed()


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bg-", dir="/tmp"))
    os.chmod(path, 0o700)
    yield path
    shutil.rmtree(path)


@pytest.fixture
def private_dir(workdir):
    directory = workdir / "p"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


@pytest.fixture
def running(workdir, private_dir):
    servers = []

    def start(processor, *, gateway_uid=UID, socket_path=None, private=None):
        server = ProcessorServer(
            processor,
            socket_path or workdir / "s" / "decide.sock",
            private or private_dir,
            gateway_uid=gateway_uid,
            socket_gid=GID,
        )
        server.start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def call(socket_path, method=CHECK_REQUEST, message=None, response=ext_mcp_pb2.McpRequestResult):
    with grpc.insecure_channel(f"unix:{socket_path}") as channel:
        stub = channel.unary_unary(
            method,
            request_serializer=type(message or ext_mcp_pb2.McpRequest()).SerializeToString,
            response_deserializer=response.FromString,
        )
        return stub(message or ext_mcp_pb2.McpRequest(method="tools/call"), timeout=5)


def test_a_gateway_uid_peer_reaches_the_processor(running, workdir):
    processor = RecordingProcessor()
    running(processor)
    result = call(workdir / "s" / "decide.sock")
    assert (result.WhichOneof("result"), result.error.reason) == ("error", "out_of_scope")
    assert [message.method for message in processor.messages] == ["tools/call"]


def test_a_peer_with_another_uid_is_refused_before_the_processor(running, workdir):
    processor = RecordingProcessor()
    running(processor, gateway_uid=UID + 1)
    with pytest.raises(grpc.RpcError) as caught:
        call(workdir / "s" / "decide.sock")
    assert caught.value.code() == grpc.StatusCode.UNAVAILABLE
    assert processor.messages == []


def test_check_response_is_not_served(running, workdir):
    running(RecordingProcessor())
    with pytest.raises(grpc.RpcError) as caught:
        call(
            workdir / "s" / "decide.sock",
            method=CHECK_RESPONSE,
            message=ext_mcp_pb2.McpResponse(method="tools/call"),
            response=ext_mcp_pb2.McpResponseResult,
        )
    assert caught.value.code() == grpc.StatusCode.UNIMPLEMENTED


def test_the_socket_is_group_only_in_a_0750_directory(running, workdir):
    running(RecordingProcessor())
    directory = os.lstat(workdir / "s")
    socket_info = os.lstat(workdir / "s" / "decide.sock")
    assert (stat.S_IMODE(directory.st_mode), directory.st_gid) == (0o750, GID)
    assert stat.S_ISSOCK(socket_info.st_mode)
    assert (stat.S_IMODE(socket_info.st_mode), socket_info.st_gid) == (0o660, GID)


@pytest.mark.parametrize("mode", [0o750, 0o701, 0o710])
def test_a_private_directory_open_to_others_is_refused(running, workdir, mode):
    directory = workdir / "open"
    directory.mkdir()
    os.chmod(directory, mode)
    with pytest.raises(PermissionError):
        running(RecordingProcessor(), private=directory)
    assert not (workdir / "s" / "decide.sock").exists()


def test_a_private_path_that_is_a_file_is_refused(running, workdir):
    path = workdir / "file"
    path.write_bytes(b"")
    os.chmod(path, 0o700)
    with pytest.raises(PermissionError):
        running(RecordingProcessor(), private=path)


def test_a_symlinked_private_directory_is_refused(running, workdir, private_dir):
    link = workdir / "link"
    link.symlink_to(private_dir)
    with pytest.raises(PermissionError):
        running(RecordingProcessor(), private=link)


def test_a_second_processor_on_the_same_socket_is_refused(running, workdir):
    running(RecordingProcessor())
    other = workdir / "q"
    other.mkdir(mode=0o700)
    with pytest.raises(ProcessorLocked):
        running(RecordingProcessor(), private=other)
    assert call(workdir / "s" / "decide.sock").error.reason == "out_of_scope"


def test_close_removes_the_socket_and_refuses_new_calls(running, workdir):
    server = running(RecordingProcessor())
    server.close()
    assert not (workdir / "s" / "decide.sock").exists()
    with pytest.raises(grpc.RpcError) as caught:
        call(workdir / "s" / "decide.sock")
    assert caught.value.code() == grpc.StatusCode.UNAVAILABLE


def test_a_directory_with_the_wrong_group_is_refused(workdir, private_dir):
    directory = workdir / "s"
    directory.mkdir(mode=0o750)
    os.chmod(directory, 0o750)
    server = ProcessorServer(
        RecordingProcessor(), directory / "decide.sock", private_dir, gateway_uid=UID, socket_gid=GID + 1
    )
    with pytest.raises(PermissionError):
        server.start()
