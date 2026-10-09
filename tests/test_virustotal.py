# SPDX-License-Identifier: AGPL-3.0-or-later
import time

import pytest

import recce.licensing as _licensing
from recce.config import Settings
from recce.core.result import Report, Status
from recce.modules.domain_summary import build_domain_summary
from recce.providers import query_registered_providers
from recce.providers.base import ProviderContext
from recce.providers.virustotal import RATE_LIMIT_MESSAGE, VirusTotalProvider

NOW = int(time.time())


@pytest.fixture(autouse=True)
def _pro_active(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(_licensing, "pro_licence_path", lambda: tmp_path / "pro_licence.txt")
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")


class Response:
    def __init__(self, status_code: int, payload=None) -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload

    def json(self):  # type: ignore[no-untyped-def]
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class Client:
    """Routes GETs by URL suffix; records every call."""

    def __init__(self, routes: dict[str, Response]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append((url, kwargs))
        for suffix, response in self.routes.items():
            if url.endswith(suffix):
                return response
        return Response(404, {"error": {"code": "NotFoundError", "message": "not found"}})


def _settings(**keys: str) -> Settings:
    base = dict.fromkeys(
        (
            "hibp_api_key", "hunter_api_key", "numverify_api_key", "emailrep_api_key",
            "leakcheck_api_key", "companies_house_key", "shodan_api_key",
            "virustotal_api_key", "securitytrails_api_key",
        )
    )
    base.update(keys)
    return Settings(**base, user_agent="recce-test", timeout=3.0, max_concurrency=2)  # type: ignore[arg-type]


def _ctx(client: Client) -> ProviderContext:
    return ProviderContext(settings=_settings(virustotal_api_key="vt-secret"), client=client)  # type: ignore[arg-type]


DOMAIN_REPORT = {
    "data": {
        "id": "evil.example",
        "type": "domain",
        "attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 30, "harmless": 60, "timeout": 0},
            "last_analysis_results": {
                "Fortinet": {"category": "malicious", "result": "phishing", "engine_name": "Fortinet"},
                "Kaspersky": {"category": "malicious", "result": "malware", "engine_name": "Kaspersky"},
                "Sophos": {"category": "malicious", "result": "malicious", "engine_name": "Sophos"},
                "Quttera": {"category": "suspicious", "result": "suspicious", "engine_name": "Quttera"},
                "Google": {"category": "harmless", "result": "clean", "engine_name": "Google"},
            },
            "reputation": -12,
            "total_votes": {"harmless": 1, "malicious": 7},
            "categories": {"Forcepoint ThreatSeeker": "phishing", "Sophos": "phishing and fraud"},
            "registrar": "NameCheap, Inc.",
            "creation_date": 1700000000,
            "last_analysis_date": 1790000000,
            "popularity_ranks": {
                "Alexa": {"rank": 50, "timestamp": 1684083481},
                "Cisco Umbrella": {"rank": 900000, "timestamp": NOW - 3600},
                "Majestic": {"rank": 700000, "timestamp": NOW - 3600},
            },
            "last_dns_records": [{"type": "A", "ttl": 300, "value": "203.0.113.7"}],
            "tags": ["dga"],
        },
    }
}

SUBDOMAINS = {
    "data": [
        {"type": "domain", "id": "login.evil.example"},
        {"type": "domain", "id": "evil.example"},
        {"type": "domain", "id": "cdn.evil.example"},
    ],
    "meta": {"count": 58, "cursor": "abc"},
}


@pytest.mark.asyncio
async def test_domain_reports_detections_and_subdomains() -> None:
    client = Client(
        {
            "/domains/evil.example": Response(200, DOMAIN_REPORT),
            "/domains/evil.example/relationships/subdomains": Response(200, SUBDOMAINS),
        }
    )

    report_hit, subs_hit = await VirusTotalProvider().query("Evil.Example", "domain", _ctx(client))

    assert report_hit.status is Status.FOUND
    assert report_hit.category == "reputation"
    assert report_hit.url == "https://www.virustotal.com/gui/domain/evil.example"
    summary = report_hit.summary or ""
    assert "3/94 engines malicious, 1 suspicious" in summary
    assert "Fortinet (phishing)" in summary and "Quttera (suspicious)" in summary
    assert "reputation -12" in summary
    assert "community votes 1 harmless / 7 malicious" in summary
    assert "categories: phishing, phishing and fraud" in summary
    assert "registrar: NameCheap, Inc." in summary
    assert "created 2023-11-14" in summary
    # Ranks best-first; Alexa's frozen 2023 list is dropped.
    assert "ranks: Majestic #700000, Cisco Umbrella #900000" in summary
    assert "Alexa" not in summary
    assert report_hit.extra["verdict"] == "malicious"
    assert report_hit.extra["last_dns_records"][0]["value"] == "203.0.113.7"
    assert report_hit.extra["provider_id"] == "virustotal"

    assert subs_hit.status is Status.FOUND
    assert subs_hit.category == "subs"
    # The apex VirusTotal lists as its own subdomain is dropped from list and count.
    assert subs_hit.extra["subdomains"] == ["login.evil.example", "cdn.evil.example"]
    assert subs_hit.extra["total"] == 57
    assert "57 known subdomain(s) · showing the 2 most recent" in (subs_hit.summary or "")

    # Two calls, key sent as a header only, subdomain page capped.
    assert [url for url, _ in client.calls] == [
        "https://www.virustotal.com/api/v3/domains/evil.example",
        "https://www.virustotal.com/api/v3/domains/evil.example/relationships/subdomains",
    ]
    assert client.calls[0][1]["headers"]["x-apikey"] == "vt-secret"
    assert client.calls[1][1]["params"] == {"limit": 40}


@pytest.mark.asyncio
async def test_secret_never_appears_in_hits() -> None:
    client = Client({"/domains/evil.example": Response(200, DOMAIN_REPORT)})

    hits = await VirusTotalProvider().query("evil.example", "domain", _ctx(client))

    assert all("vt-secret" not in hit.model_dump_json() for hit in hits)


@pytest.mark.asyncio
async def test_clean_domain_verdict() -> None:
    payload = {"data": {"attributes": {"last_analysis_stats": {"harmless": 61, "undetected": 31}, "reputation": 28}}}
    client = Client({"/domains/example.com": Response(200, payload)})

    hits = await VirusTotalProvider().query("example.com", "domain", _ctx(client))

    assert hits[0].extra["verdict"] == "clean"
    assert (hits[0].summary or "").startswith("0/92 engines malicious · reputation 28")
    assert hits[1].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_rate_limit_is_reported_and_stops_further_calls() -> None:
    client = Client(
        {"/domains/example.com": Response(429, {"error": {"code": "QuotaExceededError", "message": "Quota exceeded"}})}
    )

    hits = await VirusTotalProvider().query("example.com", "domain", _ctx(client))

    assert len(hits) == 1
    assert hits[0].status is Status.ERROR
    assert hits[0].error == RATE_LIMIT_MESSAGE
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_rate_limit_on_subdomains_keeps_the_report() -> None:
    client = Client(
        {
            "/domains/example.com": Response(200, DOMAIN_REPORT),
            "/relationships/subdomains": Response(429, {"error": {"code": "QuotaExceededError"}}),
        }
    )

    report_hit, subs_hit = await VirusTotalProvider().query("example.com", "domain", _ctx(client))

    assert report_hit.status is Status.FOUND
    assert subs_hit.status is Status.ERROR
    assert "4 requests/min" in (subs_hit.error or "")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "payload", "expected_status", "expected"),
    [
        (401, {"error": {"code": "WrongCredentialsError"}}, Status.ERROR, "invalid API key"),
        (403, {"error": {"code": "ForbiddenError", "message": "no access"}}, Status.ERROR, "ForbiddenError: no access"),
        (404, {"error": {"code": "NotFoundError"}}, Status.NOT_FOUND, "not in the VirusTotal dataset"),
        (503, None, Status.UNKNOWN, "HTTP 503"),
    ],
)
async def test_error_statuses(status_code, payload, expected_status, expected) -> None:  # type: ignore[no-untyped-def]
    client = Client({"/domains/example.com": Response(status_code, payload)})

    hits = await VirusTotalProvider().query("example.com", "domain", _ctx(client))

    assert len(hits) == 1
    assert hits[0].status is expected_status
    assert expected in (hits[0].error or hits[0].summary or "")


@pytest.mark.asyncio
async def test_network_failure() -> None:
    class NoNetwork(Client):
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            self.calls.append((url, kwargs))
            return None

    hits = await VirusTotalProvider().query("example.com", "domain", _ctx(NoNetwork({})))

    assert hits[0].status is Status.ERROR
    assert hits[0].error == "network"


@pytest.mark.asyncio
async def test_email_looks_up_the_mail_domain_once() -> None:
    client = Client({"/domains/evil.example": Response(200, DOMAIN_REPORT)})

    hits = await VirusTotalProvider().query("ceo@Evil.Example", "email", _ctx(client))

    assert len(hits) == 1
    assert hits[0].status is Status.FOUND
    assert (hits[0].summary or "").startswith("domain evil.example · 3/94 engines malicious")
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_email_on_webmail_domain_makes_no_call() -> None:
    client = Client({})

    hits = await VirusTotalProvider().query("someone@gmail.com", "email", _ctx(client))

    assert hits[0].status is Status.SKIPPED
    assert "consumer webmail" in (hits[0].summary or "")
    assert client.calls == []


@pytest.mark.asyncio
async def test_registry_gates_and_runs_virustotal(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    others = {"hudsonrock", "hunter", "shodan", "censys", "companies-house", "securitytrails"}
    client = Client({"/domains/example.com": Response(200, DOMAIN_REPORT)})

    not_configured = await query_registered_providers(
        "example.com", "domain", client, _settings(), skip_provider_ids=others  # type: ignore[arg-type]
    )
    assert [hit.status for hit in not_configured] == [Status.SKIPPED]
    assert "VIRUSTOTAL_API_KEY" in (not_configured[0].summary or "")

    monkeypatch.delenv("RECCE_PRO_LICENCE")
    gated = await query_registered_providers(
        "example.com", "domain", client, _settings(virustotal_api_key="k"), skip_provider_ids=others  # type: ignore[arg-type]
    )
    assert "Recce Pro entitlement required" in (gated[0].summary or "")
    assert client.calls == []

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    hits = await query_registered_providers(
        "example.com", "domain", client, _settings(virustotal_api_key="k"), skip_provider_ids=others  # type: ignore[arg-type]
    )
    assert [hit.source for hit in hits] == ["VirusTotal", "VirusTotal"]
    assert hits[0].status is Status.FOUND


@pytest.mark.asyncio
async def test_domain_summary_shows_reputation_row() -> None:
    client = Client({"/domains/evil.example": Response(200, DOMAIN_REPORT)})
    report = Report(query="evil.example", query_type="domain")
    for hit in await VirusTotalProvider().query("evil.example", "domain", _ctx(client)):
        report.add(hit)

    rows = {row.label: row.value for row in build_domain_summary(report)}

    assert rows["Reputation"] == "VirusTotal: 3/94 malicious, 1 suspicious (reputation -12)"
    assert "Reputation" not in {row.label for row in build_domain_summary(Report(query="x.com", query_type="domain"))}
