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


# Keyless email providers; tests targeting one specific provider skip these.
OTHER_FREE_EMAIL = {"xposedornot", "leakcheck", "proton", "github-commits"}


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
        skip_provider_ids={"hunter", "emailrep", *OTHER_FREE_EMAIL},
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
        skip_provider_ids={"hunter", "emailrep", *OTHER_FREE_EMAIL},
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
        skip_provider_ids={"hibp", "hunter", "emailrep", *OTHER_FREE_EMAIL},
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
        skip_provider_ids={"hibp", "hunter", *OTHER_FREE_EMAIL},
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
        skip_provider_ids={"hibp", "hunter", *OTHER_FREE_EMAIL},
    )

    assert client.requests[0][1]["headers"]["Key"] == "rep-key"


@pytest.mark.asyncio
async def test_hunter_provider_returns_not_configured_skip() -> None:
    hits = await query_registered_providers(
        "person@example.com",
        "email",
        DummyClient(None),  # type: ignore[arg-type]
        _settings(),
        skip_provider_ids={"hibp", "emailrep", *OTHER_FREE_EMAIL},
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
        skip_provider_ids={"hibp", "emailrep", *OTHER_FREE_EMAIL},
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
        skip_provider_ids={"shodan", "censys"},
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


@pytest.mark.asyncio
async def test_shodan_free_plan_403_reports_plan_not_bad_key(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.domain_sources.common as common

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    monkeypatch.setattr(common, "dns_lookup", _fake_dns({}))
    client = DummyClient(DummyResponse(403, {"error": "Requires membership or higher to access"}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(shodan_api_key="shodan-key"),
        skip_provider_ids={"censys"},
    )

    shodan_hits = [hit for hit in hits if hit.source == "Shodan"]
    assert len(shodan_hits) == 1
    assert shodan_hits[0].status is Status.SKIPPED
    assert "key is valid" in (shodan_hits[0].summary or "")
    assert "Membership" in (shodan_hits[0].summary or "")
    assert "fallback" not in (shodan_hits[0].summary or "")  # no IPs resolved, nothing to fall back to


@pytest.mark.asyncio
async def test_shodan_free_plan_falls_back_to_host_lookups(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.domain_sources.common as common
    import recce.providers.shodan as shodan

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    monkeypatch.setattr(shodan, "REQUEST_SPACING", 0)
    monkeypatch.setattr(
        common, "dns_lookup", _fake_dns({"A": ["140.82.112.3", "185.70.42.37", "10.0.0.5"]})
    )
    membership = DummyResponse(403, {"error": "Requires membership or higher to access"})
    host = {
        "ip_str": "140.82.112.3",
        "org": "GitHub, Inc.",
        "asn": "AS36459",
        "country_code": "US",
        "ports": [443, 22, 80],
        "vulns": ["CVE-2023-48795"],
        "hostnames": ["lb-140-82-112-3-iad.github.com"],
        "tags": [],
    }
    client = RoutingClient(
        {
            "/dns/domain/example.com": membership,
            "/shodan/host/140.82.112.3": DummyResponse(200, host),
            "/shodan/host/185.70.42.37": membership,
        }
    )

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(shodan_api_key="shodan-key"),
        skip_provider_ids={"censys"},
    )

    shodan_hits = [hit for hit in hits if hit.source == "Shodan"]
    assert [hit.status for hit in shodan_hits] == [Status.SKIPPED, Status.FOUND]
    note, host_hit = shodan_hits
    assert "1/2 IP(s) available" in (note.summary or "")
    assert "restricted: 185.70.42.37" in (note.summary or "")
    assert "AS36459 GitHub, Inc." in (host_hit.summary or "")
    assert "ports: 22, 80, 443" in (host_hit.summary or "")
    assert "1 CVE(s): CVE-2023-48795" in (host_hit.summary or "")
    assert host_hit.url == "https://www.shodan.io/host/140.82.112.3"
    # private IPs are never sent to Shodan
    assert not any("10.0.0.5" in url for url, _ in client.requests)
    assert all(kwargs["params"] == {"key": "shodan-key"} for _, kwargs in client.requests)


@pytest.mark.asyncio
async def test_shodan_401_reports_invalid_key(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    client = DummyClient(DummyResponse(401, {"error": "Invalid API key"}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(shodan_api_key="shodan-key"),
    )

    shodan_hits = [hit for hit in hits if hit.source == "Shodan"]
    assert shodan_hits[0].status is Status.ERROR
    assert shodan_hits[0].error == "invalid API key"


class RoutingClient:
    def __init__(self, routes: dict[str, DummyResponse]) -> None:
        self.routes = routes
        self.requests: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append((url, kwargs))
        for suffix, response in self.routes.items():
            if url.endswith(suffix):
                return response
        return DummyResponse(404, {})


def _fake_dns(records: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    async def lookup(name: str, rtype: str) -> tuple[list[str], str | None]:
        del name
        return records.get(rtype, []), None

    return lookup


@pytest.mark.asyncio
async def test_censys_provider_reports_hosts_and_cert(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.domain_sources.common as common

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    monkeypatch.setattr(common, "dns_lookup", _fake_dns({"A": ["93.184.216.34", "10.0.0.5"]}))
    host = {
        "result": {
            "resource": {
                "ip": "93.184.216.34",
                "autonomous_system": {"asn": 15133, "name": "EDGECAST"},
                "location": {"country_code": "US"},
                "services": [
                    {"port": 443, "protocol": "HTTP", "transport_protocol": "tcp"},
                    {"port": 443, "protocol": "UNKNOWN", "transport_protocol": "quic"},
                ],
            }
        }
    }
    web = {
        "result": {
            "resource": {
                "cert": {
                    "fingerprint_sha256": "abc",
                    "names": ["example.com", "www.example.com"],
                    "parsed": {
                        "subject_dn": "C=US, O=Example, CN=www.example.com",
                        "issuer_dn": "C=US, O=DigiCert Inc, CN=DigiCert TLS",
                        "validity_period": {"not_after": "2027-01-15T23:59:59Z"},
                    },
                }
            }
        }
    }
    client = RoutingClient(
        {"/host/93.184.216.34": DummyResponse(200, host), "/webproperty/example.com:443": DummyResponse(200, web)}
    )

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(censys_api_token="censys_tok"),
        skip_provider_ids={"shodan"},
    )

    censys_hits = [hit for hit in hits if hit.source == "Censys"]
    assert [hit.status for hit in censys_hits] == [Status.FOUND, Status.FOUND]
    host_hit, cert_hit = censys_hits
    assert "AS15133 EDGECAST" in (host_hit.summary or "")
    assert "443/HTTP" in (host_hit.summary or "")
    assert "443/UNKNOWN (quic)" in (host_hit.summary or "")
    assert "issuer: DigiCert Inc" in (cert_hit.summary or "")
    assert "expires 2027-01-15" in (cert_hit.summary or "")
    # private IPs are never sent to Censys; token goes in a bearer header, no org ID by default
    urls = [url for url, _ in client.requests]
    assert not any("10.0.0.5" in url for url in urls)
    headers = client.requests[0][1]["headers"]
    assert headers["Authorization"] == "Bearer censys_tok"
    assert "X-Organization-ID" not in headers


@pytest.mark.asyncio
async def test_censys_provider_reports_inactive_token(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.domain_sources.common as common

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    monkeypatch.setattr(common, "dns_lookup", _fake_dns({"A": ["93.184.216.34"]}))
    client = DummyClient(DummyResponse(401, {"error": {"code": 401, "reason": "Access token is not active"}}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(censys_api_token="censys_bad", censys_org_id="org-uuid"),
        skip_provider_ids={"shodan"},
    )

    censys_hits = [hit for hit in hits if hit.source == "Censys"]
    assert censys_hits and all(hit.status is Status.ERROR for hit in censys_hits)
    assert censys_hits[0].error == "invalid or inactive API token"
    assert client.requests[0][1]["headers"]["X-Organization-ID"] == "org-uuid"


def test_censys_provider_needs_token_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")

    rows = {row["id"]: row for row in provider_status_rows(_settings(censys_api_token="censys_tok"))}

    assert rows["censys"]["status"] == "active"


@pytest.mark.asyncio
async def test_censys_provider_retries_once_on_rate_limit(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.domain_sources.common as common
    import recce.providers.censys as censys

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    monkeypatch.setattr(common, "dns_lookup", _fake_dns({}))
    monkeypatch.setattr(censys, "RATE_LIMIT_RETRY_DELAY", 0)
    client = DummyClient(DummyResponse(429, {}))

    hits = await query_registered_providers(
        "example.com",
        "domain",
        client,  # type: ignore[arg-type]
        _settings(censys_api_token="censys_tok"),
        skip_provider_ids={"shodan"},
    )

    censys_hits = [hit for hit in hits if hit.source == "Censys"]
    assert censys_hits[0].status is Status.NOT_FOUND  # no public IPs resolved
    assert censys_hits[1].status is Status.ERROR
    assert "rate-limited" in (censys_hits[1].error or "")
    assert len(client.requests) == 2  # webproperty lookup + one retry
