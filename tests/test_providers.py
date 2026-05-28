# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from recce.config import Settings
from recce.core.result import Report, Status
from recce.providers import (
    append_registry_gate_hits,
    provider_status_rows,
    query_registered_providers,
)


def _settings(**overrides) -> Settings:  # type: ignore[no-untyped-def]
    data = {
        "hibp_api_key": None,
        "hunter_api_key": None,
        "numverify_api_key": None,
        "emailrep_api_key": None,
        "leakcheck_api_key": None,
        "companies_house_key": None,
        "shodan_api_key": None,
        "virustotal_api_key": None,
        "securitytrails_api_key": None,
        "censys_api_id": None,
        "censys_api_secret": None,
        "user_agent": "recce-test",
        "timeout": 3.0,
        "max_concurrency": 2,
        "provider_integrations_enabled": True,
    }
    data.update(overrides)
    return Settings(**data)


def test_provider_statuses_include_optional_key_and_not_configured(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    rows = {row["id"]: row for row in provider_status_rows(_settings())}

    assert rows["emailrep"]["status"] == "active"
    assert rows["hibp"]["status"] == "not_configured"
    assert rows["shodan"]["status"] == "not_configured"


def test_pro_provider_is_gated_without_entitlement(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    rows = {row["id"]: row for row in provider_status_rows(_settings(shodan_api_key="key"))}

    assert rows["shodan"]["status"] == "inactive_pro"


def test_append_registry_gate_hits_adds_pro_skip(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)
    report = Report(query="example.com", query_type="domain")

    append_registry_gate_hits(report, _settings(shodan_api_key="key"))

    assert len(report.hits) == 1
    assert report.hits[0].source == "Shodan"
    assert report.hits[0].status is Status.SKIPPED


def test_no_providers_disables_registry_status(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    rows = provider_status_rows(_settings(provider_integrations_enabled=False))

    assert {row["status"] for row in rows} == {"disabled"}


class DummyResponse:
    def __init__(self, status_code: int, payload=None) -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload

    def json(self):  # type: ignore[no-untyped-def]
        return self._payload


class DummyClient:
    def __init__(self, response: DummyResponse | None) -> None:
        self.response = response
        self.requests: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append((url, kwargs))
        return self.response


@pytest.mark.asyncio
async def test_hibp_provider_returns_not_configured_skip() -> None:
    hits = await query_registered_providers(
        "person@example.com",
        "email",
        DummyClient(None),  # type: ignore[arg-type]
        _settings(),
    )

    hibp_hits = [hit for hit in hits if hit.source == "Have I Been Pwned"]
    assert len(hibp_hits) == 1
    assert hibp_hits[0].status is Status.SKIPPED
    assert "HIBP_API_KEY" in (hibp_hits[0].summary or "")


@pytest.mark.asyncio
async def test_hibp_provider_queries_api_when_configured() -> None:
    payload = [
        {"Name": "ExampleBreach", "Title": "Example Breach"},
        {"Name": "OtherBreach", "Title": "Other Breach"},
    ]
    client = DummyClient(DummyResponse(200, payload))

    hits = await query_registered_providers(
        "person@example.com",
        "email",
        client,  # type: ignore[arg-type]
        _settings(hibp_api_key="test-key"),
    )

    hibp_hits = [hit for hit in hits if hit.source == "Have I Been Pwned"]
    assert len(hibp_hits) == 1
    assert hibp_hits[0].status is Status.FOUND
    assert "2 breach(es)" in (hibp_hits[0].summary or "")
    assert client.requests[0][1]["headers"]["hibp-api-key"] == "test-key"


@pytest.mark.asyncio
async def test_hibp_provider_can_be_skipped() -> None:
    client = DummyClient(DummyResponse(200, []))

    hits = await query_registered_providers(
        "person@example.com",
        "email",
        client,  # type: ignore[arg-type]
        _settings(hibp_api_key="test-key"),
        skip_provider_ids={"hibp"},
    )

    assert all(hit.source != "Have I Been Pwned" for hit in hits)
    assert client.requests == []
