import pytest
from test_quickstart_stack import b


def test_a_probe_that_returns_ok_is_allowed():
    assert b.probe_outcome("read issues", 200) == "allowed"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_probe_that_is_denied_is_refused_with_its_status(status):
    assert b.probe_outcome("create a repository", status) == f"refused ({status})"


@pytest.mark.parametrize("status", [201, 400, 422, 500])
def test_a_probe_that_is_neither_allowed_nor_refused_fails_bootstrap(status):
    with pytest.raises(b.BootstrapError, match=f"'create a repository' returned {status}"):
        b.probe_outcome("create a repository", status)
