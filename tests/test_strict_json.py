import os

import pytest

from agent_bailiff.custodian.bindings import BindingTable, BindingTableError
from agent_bailiff.strict_json import parse_strict_json


def test_a_plain_document_parses():
    assert parse_strict_json(b'{"a": [1, 2.5, "x", null, true]}') == {"a": [1, 2.5, "x", None, True]}


@pytest.mark.parametrize("raw", [b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}'])
def test_duplicate_keys_and_non_finite_numbers_are_refused(raw):
    with pytest.raises(ValueError):
        parse_strict_json(raw)


def test_the_binding_table_refuses_a_duplicate_key(tmp_path):
    path = tmp_path / "bindings.json"
    path.write_text('{"bindings": [], "bindings": []}')
    os.chmod(path, 0o600)
    with pytest.raises(BindingTableError, match="not valid JSON"):
        BindingTable.load(path)
