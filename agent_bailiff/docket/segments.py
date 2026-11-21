from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from agent_bailiff.docket.manifest import SegmentEntry, read_docket_manifest, segment_path

MAX_OPEN_ATTEMPTS = 3


class SegmentRemoved(Exception):
    pass


class SegmentMismatch(Exception):
    pass


@dataclass
class OpenedSegment:
    stream: BinaryIO
    path: Path
    end: int
    sealed: SegmentEntry | None


class BoundedReader:
    def __init__(self, stream: BinaryIO, end: int) -> None:
        self._stream = stream
        self._end = end

    def readline(self, size: int = -1, /) -> bytes:
        return self._stream.readline(self._remaining(size))

    def read(self, size: int = -1, /) -> bytes:
        return self._stream.read(self._remaining(size))

    def _remaining(self, size: int) -> int:
        left = max(self._end - self._stream.tell(), 0)
        return left if size < 0 else min(size, left)


def open_segment(docket_path: Path, segment: int) -> OpenedSegment | None:
    for _ in range(MAX_OPEN_ATTEMPTS):
        manifest = read_docket_manifest(docket_path)
        if segment < manifest.first_segment:
            raise SegmentRemoved(f"segment {segment} of {docket_path} was removed; see docs/DOCKET.md")
        if segment > manifest.active_segment:
            raise SegmentMismatch(f"segment {segment} is after the active segment {manifest.active_segment}")
        sealed = manifest.sealed_entry(segment)
        path = docket_path if sealed is None else segment_path(docket_path, segment)
        try:
            stream = open(path, "rb")
        except FileNotFoundError:
            return None
        if read_docket_manifest(docket_path).generation != manifest.generation:
            stream.close()
            continue
        size = os.fstat(stream.fileno()).st_size
        if sealed is not None and size != sealed.size:
            stream.close()
            raise SegmentMismatch(f"{path} is {size} bytes, not the {sealed.size} its manifest entry says")
        return OpenedSegment(stream, path, size, sealed)
    return None
