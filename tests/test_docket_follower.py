import threading

import pytest
from test_docket import make_entry
from test_docket_report import WRITERS, Docket

from agent_bailiff.docket.follower import DocketFollower, load_checkpoint
from agent_bailiff.docket.sink import build_kid_index

INDEX = build_kid_index(WRITERS)


class HandlerFailed(Exception):
    pass


@pytest.fixture
def docket(tmp_path):
    path = tmp_path / "docket.log"
    path.touch(mode=0o600)
    return Docket(path)


@pytest.fixture
def checkpoint(tmp_path):
    directory = tmp_path / "follower"
    directory.mkdir(mode=0o700)
    return directory / "checkpoint.json"


def follow(docket, checkpoint, handle, **options):
    return DocketFollower(docket.path, INDEX, checkpoint, handle, **options).run(threading.Event(), follow=False)


def test_handler_sees_each_verified_record_once_across_runs(docket, checkpoint):
    seen = []
    for number in range(1, 4):
        docket.append("decide", make_entry(number))
    assert follow(docket, checkpoint, lambda batch, stop: seen.extend(line.line for line in batch), batch_size=2) == 3
    docket.append("decide", make_entry(4))
    assert follow(docket, checkpoint, lambda batch, stop: seen.extend(line.line for line in batch)) == 1
    assert seen == [1, 2, 3, 4]
    assert load_checkpoint(checkpoint).entries == 4


def test_a_failing_handler_leaves_the_checkpoint_at_the_last_handled_batch(docket, checkpoint):
    for number in range(1, 5):
        docket.append("decide", make_entry(number))
    batches = []

    def handle(batch, stop):
        if batches:
            raise HandlerFailed
        batches.append([line.line for line in batch])

    with pytest.raises(HandlerFailed):
        follow(docket, checkpoint, handle, batch_size=2)
    assert batches == [[1, 2]]
    assert load_checkpoint(checkpoint).entries == 2


def test_batch_size_must_be_positive(docket, checkpoint):
    with pytest.raises(ValueError, match="batch size"):
        DocketFollower(docket.path, INDEX, checkpoint, lambda batch, stop: None, batch_size=0)
