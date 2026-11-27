from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / "docs"


def read(name):
    return (DOCS / name).read_text()


@pytest.mark.parametrize(
    ("name", "needle"),
    [
        ("DECISIONS.md", "## D25. Provider privilege check before a credential is stored"),
        ("THREAT_MODEL.md", "**The provider privilege check is point-in-time and provider-reported.**"),
        ("THREAT_MODEL.md", "**The provider check sends the token to the provider.**"),
        ("UPGRADE.md", "### Provider privilege check"),
        ("UPGRADE.md", "Neither can decrypt a credential stored with a `broader` exception"),
        ("ADOPT.md", "`credential-check` covers Gitea only"),
    ],
)
def test_the_docs_record_the_provider_privilege_check(name, needle):
    assert needle in read(name)


def test_adopt_checks_the_token_before_it_stores_it():
    adopt = read("ADOPT.md")
    check = adopt.index("$ agent-bailiff credential-check --provider gitea")
    store = adopt.index("Store the credential. The custodian reads it from stdin.")
    assert check < store
    assert "--expect-fingerprint" in adopt[check:store]
