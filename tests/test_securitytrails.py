# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

import recce.licensing as _licensing
from recce.config import Settings
from recce.core.result import Status
from recce.providers import query_registered_providers
from recce.providers.base import ProviderContext
from recce.providers.securitytrails import RATE_LIMIT_MESSAGE, SecurityTrailsProvider


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
        return Response(404, {"message": "not found"})


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
    return ProviderContext(settings=_settings(securitytrails_api_key="st-secret"), client=client)  # type: ignore[arg-type]


SUBDOMAINS = {
    "endpoint": "/v1/domain/example.com/subdomains",
    "meta": {"limit_reached": True},
    "subdomain_count": 312,
    "subdomains": ["www", "mail", "vpn", "WWW"],
}

A_HISTORY = {
    "endpoint": "/v1/history/example.com/dns/a",
    "pages": 2,
    "type": "a/ipv4",
    "records": [
        {
            "first_seen": "2021-03-01",
            "last_seen": "2026-10-08",
            "organizations": ["Cloudflare, Inc."],
            "type": "a",
            "values": [{"ip": "104.16.1.1", "ip_count": 40}, {"ip": "104.16.2.2", "ip_count": 40}],
        },
        {
            "first_seen": "2016-05-10",
            "last_seen": "2021-02-28",
            "organizations": ["DigitalOcean, LLC"],
            "type": "a",
            "values": [{"ip": "198.51.100.7", "ip_count": 1}],
        },
        {"first_seen": "2015-01-01", "last_seen": "2016-05-09", "organizations": [], "type": "a", "values": []},
    ],
}


@pytest.mark.asyncio
async def test_domain_reports_subdomains_and_a_history() -> None:
    client = Client(
        {
            "/domain/example.com/subdomains": Response(200, SUBDOMAINS),
            "/history/example.com/dns/a": Response(200, A_HISTORY),
        }
    )

    subs, history = await SecurityTrailsProvider().query("Example.com", "domain", _ctx(client))

    assert subs.status is Status.FOUND and subs.category == "subs"
    assert subs.extra["subdomains"] == ["mail.example.com", "vpn.example.com", "www.example.com"]
    assert subs.extra["total"] == 312 and subs.extra["limit_reached"] is True
    assert (subs.summary or "").startswith("312 subdomain(s) incl. inactive · plan shows 3 · sample: mail.example.com")
    assert subs.extra["provider_id"] == "securitytrails"

    assert history.status is Status.FOUND and history.category == "network"
    summary = history.summary or ""
    assert "2 A record period(s) · 3 IP(s) · since 2016-05-10" in summary
    assert "hosts: Cloudflare, Inc., DigitalOcean, LLC" in summary
    # The pre-CDN origin is what this lookup is for; it leads the "earliest" list.
    assert "earliest: 198.51.100.7 (2016-05-10–2021-02-28); 104.16.1.1, 104.16.2.2 (2021-03-01–2026-10-08)" in summary
    assert "first of 2 pages" in summary
    assert history.extra["ips"] == ["104.16.1.1", "104.16.2.2", "198.51.100.7"]
    assert history.url == "https://securitytrails.com/domain/example.com/history/a"

    assert [url for url, _ in client.calls] == [
        "https://api.securitytrails.com/v1/domain/example.com/subdomains",
        "https://api.securitytrails.com/v1/history/example.com/dns/a",
    ]
    assert client.calls[0][1]["headers"]["APIKEY"] == "st-secret"
    assert client.calls[0][1]["params"] == {"children_only": "false", "include_inactive": "true"}
    assert all("st-secret" not in hit.model_dump_json() for hit in (subs, history))


@pytest.mark.asyncio
async def test_quota_exhausted_stops_after_first_call() -> None:
    client = Client({"/subdomains": Response(429, {"message": "You've exceeded the usage limits for your account."})})

    hits = await SecurityTrailsProvider().query("example.com", "domain", _ctx(client))

    assert len(hits) == 1
    assert hits[0].status is Status.ERROR
    assert hits[0].error == RATE_LIMIT_MESSAGE
    assert len(client.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "payload", "expected"),
    [
        (403, {"message": "Invalid authentication credentials"}, "Invalid authentication credentials"),
        (401, None, "invalid key or endpoint not in plan (HTTP 401)"),
    ],
)
async def test_auth_errors_stop_after_first_call(status_code, payload, expected) -> None:  # type: ignore[no-untyped-def]
    client = Client({"/subdomains": Response(status_code, payload)})

    hits = await SecurityTrailsProvider().query("example.com", "domain", _ctx(client))

    assert [hit.status for hit in hits] == [Status.ERROR]
    assert hits[0].error == expected
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_empty_results_are_not_found() -> None:
    client = Client(
        {
            "/subdomains": Response(200, {"subdomains": [], "subdomain_count": 0}),
            "/dns/a": Response(200, {"records": [], "pages": 1}),
        }
    )

    subs, history = await SecurityTrailsProvider().query("example.com", "domain", _ctx(client))

    assert subs.status is Status.NOT_FOUND
    assert history.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_history_failure_keeps_subdomains() -> None:
    client = Client(
        {"/subdomains": Response(200, SUBDOMAINS), "/dns/a": Response(429, {"message": "limit"})}
    )

    subs, history = await SecurityTrailsProvider().query("example.com", "domain", _ctx(client))

    assert subs.status is Status.FOUND
    assert history.status is Status.ERROR and history.error == RATE_LIMIT_MESSAGE


@pytest.mark.asyncio
async def test_server_error_and_bad_json_are_unknown() -> None:
    client = Client({"/subdomains": Response(500, {"message": "upstream"}), "/dns/a": Response(200, None)})

    subs, history = await SecurityTrailsProvider().query("example.com", "domain", _ctx(client))

    assert subs.status is Status.UNKNOWN and subs.summary == "upstream"
    assert history.status is Status.UNKNOWN and history.summary == "bad json"


@pytest.mark.asyncio
async def test_registry_gates_and_runs_securitytrails(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    others = {"hudsonrock", "hunter", "shodan", "censys", "companies-house", "virustotal"}
    client = Client({"/subdomains": Response(200, SUBDOMAINS), "/dns/a": Response(200, A_HISTORY)})

    not_configured = await query_registered_providers(
        "example.com", "domain", client, _settings(), skip_provider_ids=others  # type: ignore[arg-type]
    )
    assert [hit.status for hit in not_configured] == [Status.SKIPPED]
    assert "SECURITYTRAILS_API_KEY" in (not_configured[0].summary or "")

    monkeypatch.delenv("RECCE_PRO_LICENCE")
    gated = await query_registered_providers(
        "example.com", "domain", client, _settings(securitytrails_api_key="k"), skip_provider_ids=others  # type: ignore[arg-type]
    )
    assert "Recce Pro entitlement required" in (gated[0].summary or "")
    assert client.calls == []

    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-pro")
    hits = await query_registered_providers(
        "example.com", "domain", client, _settings(securitytrails_api_key="k"), skip_provider_ids=others  # type: ignore[arg-type]
    )
    assert [hit.status for hit in hits] == [Status.FOUND, Status.FOUND]


@pytest.mark.asyncio
async def test_email_and_other_types_are_ignored() -> None:
    client = Client({})

    assert await SecurityTrailsProvider().query("a@example.com", "email", _ctx(client)) == []
    assert client.calls == []
