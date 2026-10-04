# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

import recce.licensing as _licensing
from recce.config import Settings
from recce.core.result import Hit, Report, Status
from recce.providers import (
    append_registry_gate_hits,
    provider_status_rows,
    query_registered_providers,
)


@pytest.fixture(autouse=True)
def _isolate_pro_entitlement(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Pro entitlement defaults to INACTIVE in tests, regardless of the dev's
    ~/.config/recce/pro_licence.txt. Tests that want it active set
    RECCE_PRO_LICENCE themselves."""
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)
    monkeypatch.setattr(_licensing, "pro_licence_path", lambda: tmp_path / "pro_licence.txt")
    yield


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
        skip_provider_ids={"hunter", "emailrep"},
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
        skip_provider_ids={"hunter", "emailrep"},
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
        skip_provider_ids={"hibp", "hunter", "emailrep"},
    )

    assert all(hit.source != "Have I Been Pwned" for hit in hits)
    assert client.requests == []


@pytest.mark.asyncio
async def test_emailrep_provider_queries_without_key() -> None:
    payload = {
        "reputation": "high",
        "suspicious": False,
        "details": {
            "first_seen": "2020-01-01",
            "profiles": ["twitter"],
            "data_breach": False,
            "malicious_activity": False,
        },
    }
    client = DummyClient(DummyResponse(200, payload))

    hits = await query_registered_providers(
        "person@example.com",
        "email",
        client,  # type: ignore[arg-type]
        _settings(),
        skip_provider_ids={"hibp", "hunter"},
    )

    assert len(hits) == 1
    assert hits[0].source == "EmailRep"
    assert hits[0].status is Status.FOUND
    assert "reputation: high" in (hits[0].summary or "")
    assert client.requests[0][0] == "https://emailrep.io/person@example.com"
    assert "Key" not in client.requests[0][1]["headers"]


@pytest.mark.asyncio
async def test_emailrep_provider_sends_key_when_configured() -> None:
    client = DummyClient(DummyResponse(429, {}))

    await query_registered_providers(
        "person@example.com",
        "email",
        client,  # type: ignore[arg-type]
        _settings(emailrep_api_key="rep-key"),
        skip_provider_ids={"hibp", "hunter"},
    )

    assert client.requests[0][1]["headers"]["Key"] == "rep-key"


@pytest.mark.asyncio
async def test_hunter_provider_returns_not_configured_skip() -> None:
    hits = await query_registered_providers(
        "person@example.com",
        "email",
        DummyClient(None),  # type: ignore[arg-type]
        _settings(),
        skip_provider_ids={"hibp", "emailrep"},
    )

    assert len(hits) == 1
    assert hits[0].source == "Hunter.io"
    assert hits[0].status is Status.SKIPPED
    assert "HUNTER_API_KEY" in (hits[0].summary or "")


@pytest.mark.asyncio
async def test_hunter_provider_queries_api_when_configured() -> None:
    payload = {
        "data": {
            "status": "valid",
            "score": 97,
            "disposable": False,
            "webmail": True,
            "accept_all": False,
            "sources": [{"domain": "example.com"}],
        }
    }
    client = DummyClient(DummyResponse(200, payload))

    hits = await query_registered_providers(
        "person@example.com",
        "email",
        client,  # type: ignore[arg-type]
        _settings(hunter_api_key="hunter-key"),
        skip_provider_ids={"hibp", "emailrep"},
    )

    assert len(hits) == 1
    assert hits[0].source == "Hunter.io"
    assert hits[0].status is Status.FOUND
    assert "score: 97" in (hits[0].summary or "")
    assert client.requests[0][0] == "https://api.hunter.io/v2/email-verifier"
    assert client.requests[0][1]["params"] == {
        "email": "person@example.com",
        "api_key": "hunter-key",
    }


@pytest.mark.asyncio
async def test_hunter_domain_pivots_remain_non_queryable_until_implemented() -> None:
    client = DummyClient(DummyResponse(200, {}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(hunter_api_key="hunter-key"),
        skip_provider_ids={"shodan"},
    )

    assert hits == []
    assert client.requests == []


@pytest.mark.asyncio
async def test_numverify_provider_returns_not_configured_skip() -> None:
    hits = await query_registered_providers(
        "+447826916903",
        "phone",
        DummyClient(None),  # type: ignore[arg-type]
        _settings(),
    )

    nv = [h for h in hits if h.source == "NumVerify"]
    assert len(nv) == 1
    assert nv[0].status is Status.SKIPPED
    assert "NUMVERIFY_API_KEY" in (nv[0].summary or "")


@pytest.mark.asyncio
async def test_numverify_provider_queries_api_when_configured() -> None:
    payload = {
        "valid": True,
        "country_name": "United Kingdom",
        "location": "London",
        "carrier": "Example Mobile",
        "line_type": "mobile",
    }
    client = DummyClient(DummyResponse(200, payload))

    hits = await query_registered_providers(
        "+447826916903",
        "phone",
        client,  # type: ignore[arg-type]
        _settings(numverify_api_key="num-key"),
    )

    nv = [h for h in hits if h.source == "NumVerify"]
    assert len(nv) == 1
    assert nv[0].status is Status.FOUND
    assert "Example Mobile" in (nv[0].summary or "")
    assert client.requests[0][0] == "https://apilayer.net/api/validate"
    assert client.requests[0][1]["params"] == {
        "access_key": "num-key",
        "number": "447826916903",
        "format": 1,
    }


_VONAGE_OK = {
    "status": 0,
    "status_message": "Success",
    "lookup_outcome": 0,
    "valid_number": "valid",
    "reachable": "reachable",
    "ported": "ported",
    "current_carrier": {"name": "EE", "network_type": "mobile", "network_code": "23430"},
    "original_carrier": {"name": "Vodafone UK", "network_type": "mobile"},
    "roaming": "not_roaming",
    "country_name": "United Kingdom",
}


@pytest.mark.asyncio
async def test_vonage_provider_returns_not_configured_skip() -> None:
    hits = await query_registered_providers(
        "+447826916903", "phone", DummyClient(None), _settings(),  # type: ignore[arg-type]
    )
    vonage = [h for h in hits if h.source == "Vonage Number Insight"]
    assert len(vonage) == 1
    assert vonage[0].status is Status.SKIPPED
    assert "VONAGE_API_KEY" in (vonage[0].summary or "")


@pytest.mark.asyncio
async def test_vonage_provider_is_pro_gated_without_entitlement() -> None:
    client = DummyClient(DummyResponse(200, _VONAGE_OK))
    hits = await query_registered_providers(
        "+447826916903", "phone", client,  # type: ignore[arg-type]
        _settings(vonage_api_key="k", vonage_api_secret="s"),
    )
    vonage = [h for h in hits if h.source == "Vonage Number Insight"]
    assert len(vonage) == 1
    assert vonage[0].status is Status.SKIPPED
    assert "Pro" in (vonage[0].summary or "")
    assert client.requests == []  # gated before any network call


@pytest.mark.asyncio
async def test_vonage_provider_queries_when_entitled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-entitlement")
    client = DummyClient(DummyResponse(200, _VONAGE_OK))
    hits = await query_registered_providers(
        "+447826916903", "phone", client,  # type: ignore[arg-type]
        _settings(vonage_api_key="k", vonage_api_secret="s"),
    )
    vonage = [h for h in hits if h.source == "Vonage Number Insight"]
    assert len(vonage) == 1
    assert vonage[0].status is Status.FOUND
    summary = vonage[0].summary or ""
    assert "carrier: EE" in summary
    assert "ported: ported" in summary
    assert "originally: Vodafone UK" in summary
    assert "reachable: reachable" in summary
    assert client.requests[0][0] == "https://api.nexmo.com/ni/advanced/json"
    assert client.requests[0][1]["params"]["number"] == "447826916903"


@pytest.mark.asyncio
async def test_vonage_provider_reports_api_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-entitlement")
    client = DummyClient(DummyResponse(200, {"status": 4, "status_message": "invalid credentials"}))
    hits = await query_registered_providers(
        "+447826916903", "phone", client,  # type: ignore[arg-type]
        _settings(vonage_api_key="k", vonage_api_secret="s"),
    )
    vonage = [h for h in hits if h.source == "Vonage Number Insight"]
    assert len(vonage) == 1
    assert vonage[0].status is Status.ERROR
    assert "invalid credentials" in (vonage[0].error or "")


class SequenceClient:
    """Returns queued responses in order; records the URLs requested."""

    def __init__(self, responses: list) -> None:  # type: ignore[no-untyped-def]
        self.responses = list(responses)
        self.requests: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append((url, kwargs))
        return self.responses.pop(0) if self.responses else None


@pytest.mark.asyncio
async def test_numverify_falls_back_to_http_on_https_restriction() -> None:
    restricted = DummyResponse(200, {"error": {"code": 105, "type": "https_access_restricted"}})
    ok = DummyResponse(200, {"valid": True, "carrier": "Example Mobile", "line_type": "mobile"})
    client = SequenceClient([restricted, ok])

    hits = await query_registered_providers(
        "+447826916903",
        "phone",
        client,  # type: ignore[arg-type]
        _settings(numverify_api_key="num-key"),
    )

    nv = [h for h in hits if h.source == "NumVerify"]
    assert len(nv) == 1
    assert nv[0].status is Status.FOUND
    assert "Example Mobile" in (nv[0].summary or "")
    # First attempt HTTPS, then transparently retried over HTTP.
    assert client.requests[0][0] == "https://apilayer.net/api/validate"
    assert client.requests[1][0] == "http://apilayer.net/api/validate"


@pytest.mark.asyncio
async def test_numverify_provider_can_be_skipped() -> None:
    client = DummyClient(DummyResponse(200, {"valid": True}))

    hits = await query_registered_providers(
        "+447826916903",
        "phone",
        client,  # type: ignore[arg-type]
        _settings(numverify_api_key="num-key"),
        skip_provider_ids={"numverify", "vonage"},
    )

    assert hits == []
    assert client.requests == []


@pytest.mark.asyncio
async def test_shodan_provider_returns_not_configured_skip(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    hits = await query_registered_providers(
        "example.com",
        "domain",
        DummyClient(None),  # type: ignore[arg-type]
        _settings(),
    )

    shodan_hits = [hit for hit in hits if hit.source == "Shodan"]
    assert len(shodan_hits) == 1
    assert shodan_hits[0].status is Status.SKIPPED
    assert "SHODAN_API_KEY" in (shodan_hits[0].summary or "")


@pytest.mark.asyncio
async def test_shodan_provider_is_pro_gated_before_query(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)
    client = DummyClient(DummyResponse(200, {}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(shodan_api_key="shodan-key"),
    )

    shodan_hits = [hit for hit in hits if hit.source == "Shodan"]
    assert len(shodan_hits) == 1
    assert shodan_hits[0].status is Status.SKIPPED
    assert "Recce Pro entitlement required" in (shodan_hits[0].summary or "")
    assert client.requests == []


@pytest.mark.asyncio
async def test_shodan_provider_queries_api_when_pro_active(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    payload = {
        "domain": "example.com",
        "tags": ["ipv6"],
        "subdomains": ["www", "mail"],
        "more": False,
        "data": [
            {"subdomain": "www", "type": "A", "value": "93.184.216.34"},
            {"subdomain": "mail", "type": "MX", "value": "mail.example.com"},
        ],
    }
    client = DummyClient(DummyResponse(200, payload))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(shodan_api_key="shodan-key"),
    )

    shodan_hits = [hit for hit in hits if hit.source == "Shodan"]
    assert len(shodan_hits) == 1
    assert shodan_hits[0].status is Status.FOUND
    assert "2 subdomain(s)" in (shodan_hits[0].summary or "")
    assert shodan_hits[0].extra["provider_id"] == "shodan"
    assert client.requests[0][0] == "https://api.shodan.io/dns/domain/example.com"
    assert client.requests[0][1]["params"] == {"key": "shodan-key"}


@pytest.mark.asyncio
async def test_shodan_provider_can_be_skipped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    client = DummyClient(DummyResponse(200, {}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(shodan_api_key="shodan-key"),
        skip_provider_ids={"shodan"},
    )

    assert all(hit.source != "Shodan" for hit in hits)
    assert client.requests == []


def test_append_registry_gate_hits_does_not_duplicate_provider_gate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)
    report = Report(query="example.com", query_type="domain")
    report.add(
        Hit(
            source="Shodan",
            category="provider",
            status=Status.SKIPPED,
            summary="Recce Pro entitlement required for this provider",
            extra={"provider_id": "shodan"},
        )
    )

    append_registry_gate_hits(report, _settings(shodan_api_key="key"))

    shodan_hits = [hit for hit in report.hits if hit.source == "Shodan"]
    assert len(shodan_hits) == 1
