from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TRANSPORT_DOCS = [
    "README.md",
    "docs/ADOPT.md",
    "docs/AGENTGATEWAY.md",
    "docs/ARCHITECTURE.md",
    "docs/CLIENT.md",
    "docs/THREAT_MODEL.md",
    "examples/quickstart/README.md",
    "examples/quickstart/upstreams/schema.md",
]


def read(name):
    return (ROOT / name).read_text()


@pytest.mark.parametrize("name", TRANSPORT_DOCS)
def test_no_doc_trusts_a_service_name_over_plain_http(name):
    text = read(name)
    assert "single-label service name" not in text
    assert "tracked in #86" not in text
    assert "http://127.0.0.1:18090" not in text


def test_the_threat_model_states_the_channel_auth_non_goals():
    text = read("docs/THREAT_MODEL.md")
    assert "**TLS adds no defence against prompt injection.**" in text
    assert "**Public `https` upstreams keep the system roots.**" in text
    assert "**The OTLP hop to Jaeger is plaintext.**" in text
    assert "**Channel authentication covers one host.**" in text
    assert "`certs issue --reissue`" in text


def test_d24_records_channel_auth():
    text = read("docs/DECISIONS.md")
    assert "## D24. Channel authentication on the single host" in text
    assert text.index("## D24.") < text.index("## Deferred")


def test_the_upgrade_guide_covers_channel_auth():
    text = read("docs/UPGRADE.md")
    assert "- [Channel authentication](#channel-authentication)" in text
    assert "## Channel authentication" in text
    assert '"ca_file": "install"' in text
    assert "--gateway-ca ./ca.pem" in text
    assert "http only on 127.0.0.1, localhost or [::1]" in text


def test_the_adopt_guide_passes_the_gateway_ca_to_every_proxy_command():
    text = read("docs/ADOPT.md")
    assert text.count("https://127.0.0.1:18090/mcp") == 2
    assert text.count("--gateway-ca") == 2
    assert "docker compose cp cert-watch:/var/lib/bailiff/certs/public/current/ca.pem" in text
