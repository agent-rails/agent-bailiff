from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, quote_plus

from agent_bailiff.strict_json import parse_strict_json

MIN_NEEDLE_LENGTH = 12
MARKER = "[redacted by agent-bailiff]"
MAX_RESULT_BYTES = 4 * 1024 * 1024
BASE64_ENCODERS = (base64.b64encode, base64.urlsafe_b64encode)
PREFIX_CHARACTERS = (0, 2, 3)
PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}")


class UnreadableResult(Exception):
    pass


class Oversize(Exception):
    pass


@dataclass(frozen=True)
class Redaction:
    result: bytes
    hits: int


def needles(header_value: str) -> tuple[str, ...]:
    if not header_value:
        raise ValueError("header value must be non-empty")
    found: set[str] = set()
    for form in _forms(header_value):
        upper = quote(form, safe="")
        found.update((form, upper, PERCENT_ESCAPE.sub(_lower_escape, upper), quote_plus(form)))
        found.update(_base64_needles(form.encode("utf-8")))
    kept = (needle for needle in found if len(needle) >= MIN_NEEDLE_LENGTH)
    return tuple(sorted(kept, key=lambda needle: (-len(needle), needle)))


def redact(result: bytes, needles: Sequence[str]) -> Redaction | None:
    if len(result) > MAX_RESULT_BYTES:
        raise UnreadableResult("result exceeds the size cap")
    document = _parse(result)
    hits = _scrub_document(document, needles)
    if hits == 0:
        return None
    mutated = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(mutated) > MAX_RESULT_BYTES:
        raise Oversize("redacted result exceeds the size cap")
    return Redaction(mutated, hits)


def _forms(header_value: str) -> list[str]:
    forms = [header_value]
    parts = header_value.split(None, 1)
    if len(parts) != 2:
        return forms
    scheme, token = parts
    forms.append(token)
    if scheme.lower() == "basic":
        forms.extend(_basic_forms(token))
    return forms


def _basic_forms(token: str) -> list[str]:
    try:
        pair = base64.b64decode(token, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return []
    _user, separator, password = pair.partition(":")
    return [pair, password] if separator else [pair]


def _lower_escape(match: re.Match[str]) -> str:
    return match.group(0).lower()


def _base64_needles(form: bytes) -> Iterator[str]:
    for encode in BASE64_ENCODERS:
        for offset, prefix_characters in enumerate(PREFIX_CHARACTERS):
            encoded = encode(b"\0" * offset + form).decode("ascii")
            end = len(encoded) if (offset + len(form)) % 3 == 0 else len(encoded) - 4
            yield encoded[prefix_characters:end]


def _parse(result: bytes) -> dict[str, Any]:
    try:
        document = parse_strict_json(result)
    except (ValueError, RecursionError) as error:
        raise UnreadableResult("result is not strict JSON") from error
    if not isinstance(document, dict):
        raise UnreadableResult("result is not a JSON object")
    return document


def _scrub_document(document: dict[str, Any], needles: Sequence[str]) -> int:
    hits = 0
    pending: list[dict[str, Any] | list[Any]] = [document]
    while pending:
        container = pending.pop()
        if isinstance(container, list):
            for index, item in enumerate(container):
                container[index], found = _scrub_value(item, needles, pending)
                hits += found
            continue
        items: list[tuple[str, Any]] = []
        for key, item in container.items():
            scrubbed_key, key_hits = _scrub_text(key, needles)
            scrubbed_item, item_hits = _scrub_value(item, needles, pending)
            hits += key_hits + item_hits
            items.append((scrubbed_key, scrubbed_item))
        if len({key for key, _item in items}) != len(items):
            raise UnreadableResult("redacted keys collide")
        container.clear()
        container.update(items)
    return hits


def _scrub_value(value: Any, needles: Sequence[str], pending: list[dict[str, Any] | list[Any]]) -> tuple[Any, int]:
    if isinstance(value, str):
        return _scrub_text(value, needles)
    if isinstance(value, dict | list):
        pending.append(value)
    elif isinstance(value, float) and math.isinf(value):
        raise UnreadableResult("result has an infinite number")
    return value, 0


def _scrub_text(text: str, needles: Sequence[str]) -> tuple[str, int]:
    intervals = sorted(_occurrences(text, needles))
    if not intervals:
        return text, 0
    merged = [intervals[0]]
    for start, end in intervals[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.append(text[cursor:start])
        parts.append(MARKER)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts), len(merged)


def _occurrences(text: str, needles: Sequence[str]) -> Iterator[tuple[int, int]]:
    for needle in needles:
        index = text.find(needle)
        while index != -1:
            yield index, index + len(needle)
            index = text.find(needle, index + 1)
