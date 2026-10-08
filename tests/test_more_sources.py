# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest

from recce.config import Settings
from recce.core.result import Hit, Report, Status
from recce.modules.domain_sources import reverse_ip, wayback
from recce.modules.domain_sources.registry import SourceContext
from recce.providers import query_registered_providers
from recce.providers.base import ProviderContext
from recce.providers.wayback_profiles import PROFILE_URLS, WaybackProfilesProvider, mark_deleted


class Response:
    def __init__(self, status_code: int, payload=None, text: str | None = None) -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else ("" if payload is None else "json")

    def json(self):  # type: ignore[no-untyped-def]
        return self._payload


class Client:
    """Routes GET (url, params) through a handler; records every call."""

    def __init__(self, handler) -> None:  # type: ignore[no-untyped-def]
        self.handler = handler
        self.calls: list[tuple[str, dict]] = []

    async def get(self, url: str, params=None, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append((url, dict(params or {})))
        return self.handler(url, dict(params or {}))


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


def _cdx(rows: list[list[str]]) -> Response:
    return Response(200, [["timestamp", "original"], *rows])


# --- Hudson Rock by domain ------------------------------------------------------


@pytest.mark.asyncio
async def test_hudsonrock_domain_reports_counts_and_drops_password_stats() -> None:
    payload = {
        "total": 1200, "employees": 12, "users": 1180, "third_parties": 8,
        "last_employee_compromised": "2026-09-01T00:00:00.000Z",
        "stealerFamilies": {"RedLine": 700, "Lumma": 300, "total": 1200},
        "employeePasswords": {"totalPass": 12, "too_weak": {"qty": 3}},
        "userPasswords": {"totalPass": 1180},
        "thirdPartyDomains": [{"domain": f"d{i}.example.test"} for i in range(40)],
        "data": {
            "employees_urls": [
                {"occurrence": 3, "type": "Employee", "url": "https://vpn.example.test/login?token=abc"},
                {"occurrence": 9, "type": "Employee", "url": "https://sso.example.test/"},
            ]
        },
    }
    client = Client(lambda url, params: Response(200, payload))

    hits = await query_registered_providers(
        "example.test", "domain", client, _settings(),  # type: ignore[arg-type]
        skip_provider_ids={"hunter", "shodan", "censys", "companies-house", "virustotal", "securitytrails"},
    )

    [hit] = [h for h in hits if h.source == "Hudson Rock (infostealers)"]
    assert hit.status is Status.FOUND
    assert "12 employee(s), 1,180 user(s), 8 third-party" in hit.summary
    assert "RedLine (700), Lumma (300)" in hit.summary
    assert hit.extra["employee_urls"][0] == {"url": "https://sso.example.test/", "occurrence": 9}
    assert hit.extra["employee_urls"][1]["url"] == "https://vpn.example.test/login"  # token stripped
    assert "employeePasswords" not in hit.extra and "userPasswords" not in hit.extra
    assert len(hit.extra["thirdPartyDomains"]) == 20
    assert client.calls[0][1] == {"domain": "example.test"}


@pytest.mark.asyncio
async def test_hudsonrock_domain_without_infections_is_not_found() -> None:
    client = Client(lambda url, params: Response(200, {"employees": 0, "users": 0, "third_parties": 0}))
    hits = await query_registered_providers(
        "example.test", "domain", client, _settings(),  # type: ignore[arg-type]
        skip_provider_ids={"hunter", "shodan", "censys", "companies-house", "virustotal", "securitytrails"},
    )
    assert [h.status for h in hits if h.source.startswith("Hudson")] == [Status.NOT_FOUND]


# --- Hunter domain search --------------------------------------------------------


@pytest.mark.asyncio
async def test_hunter_domain_search_reports_format_with_one_credit() -> None:
    payload = {
        "data": {"pattern": "{first}.{last}", "organization": "Example Ltd", "accept_all": True,
                 "emails": [{"value": "someone@example.test"}]},
        "meta": {"results": 42},
    }
    client = Client(lambda url, params: Response(200, payload))

    hits = await query_registered_providers(
        "example.test", "domain", client, _settings(hunter_api_key="k"),  # type: ignore[arg-type]
        skip_provider_ids={"hudsonrock", "shodan", "censys"},
    )

    [hit] = [h for h in hits if h.source == "Hunter.io"]
    assert hit.status is Status.FOUND
    assert hit.summary == (
        "email format: {first}.{last}@example.test · organisation: Example Ltd · "
        "42 address(es) found on the web · accept-all mail server"
    )
    assert "someone@example.test" not in str(hit.extra)
    url, params = client.calls[0]
    assert url.endswith("/domain-search") and params["limit"] == 1


# --- reverse IP -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reverse_ip_lists_other_domains(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def fake_dns(name, rtype):  # type: ignore[no-untyped-def]
        return ["192.0.2.10"], None

    monkeypatch.setattr(reverse_ip, "dns_lookup", fake_dns)
    text = "example.test\nwww.example.test\nother.test\nthird.test\n"
    client = Client(lambda url, params: Response(200, text=text))

    [hit] = await reverse_ip.query("example.test", SourceContext(client=client, settings=_settings()))  # type: ignore[arg-type]

    assert hit.status is Status.FOUND
    assert hit.summary == "192.0.2.10 also hosts 2 other domain(s): other.test, third.test"
    assert hit.extra["shared"] is False
    assert client.calls == [("https://api.hackertarget.com/reverseiplookup/", {"q": "192.0.2.10"})]


@pytest.mark.asyncio
async def test_reverse_ip_flags_shared_hosting_and_quota(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def fake_dns(name, rtype):  # type: ignore[no-untyped-def]
        return ["192.0.2.10"], None

    monkeypatch.setattr(reverse_ip, "dns_lookup", fake_dns)
    many = "\n".join(f"site{i}.test" for i in range(60))
    ctx = SourceContext(client=Client(lambda u, p: Response(200, text=many)), settings=_settings())  # type: ignore[arg-type]
    [shared] = await reverse_ip.query("example.test", ctx)
    assert "shared hosting/CDN" in shared.summary and shared.confidence == 0.4

    ctx = SourceContext(client=Client(lambda u, p: Response(200, text="API count exceeded")), settings=_settings())  # type: ignore[arg-type]
    [quota] = await reverse_ip.query("example.test", ctx)
    assert quota.status is Status.SKIPPED


# --- Wayback ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wayback_domain_first_seen_and_key_pages() -> None:
    def handler(url, params):  # type: ignore[no-untyped-def]
        target = params["url"]
        if target == "example.test":
            return _cdx([["20020120142510", "http://example.test:80/"]])
        if target == "example.test/about":
            assert params["fastLatest"] == "true" and params["limit"] == "-1"
            return _cdx([["20260101000000", "https://example.test/about"]])
        return Response(200, text="")  # never archived

    hits = await wayback.query("example.test", SourceContext(client=Client(handler), settings=_settings()))  # type: ignore[arg-type]

    by_source = {h.source: h for h in hits}
    assert by_source["Wayback first seen"].summary == "2002-01-20"
    about = by_source["Wayback /about"]
    assert about.status is Status.FOUND
    assert about.url == "https://web.archive.org/web/20260101000000/https://example.test/about"
    assert by_source["Wayback /contact"].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_wayback_stops_on_rate_limit() -> None:
    def handler(url, params):  # type: ignore[no-untyped-def]
        if params["url"] == "example.test":
            return _cdx([["20020120142510", "http://example.test/"]])
        return Response(429, text="Too Many Requests")

    hits = await wayback.query("example.test", SourceContext(client=Client(handler), settings=_settings()))  # type: ignore[arg-type]

    assert hits[-1].status is Status.SKIPPED
    assert "rate limit" in hits[-1].summary


@pytest.mark.asyncio
async def test_wayback_profiles_finds_archived_and_flags_deleted() -> None:
    archived = {"github.com/sample": "20150101000000", "twitter.com/sample": "20120101000000"}

    def handler(url, params):  # type: ignore[no-untyped-def]
        if params["url"] == "reddit.com/user/sample":
            return Response(503, text="busy")
        ts = archived.get(params["url"])
        return _cdx([[ts, f"https://{params['url']}"]]) if ts else Response(200, text="")

    ctx = ProviderContext(settings=_settings(), client=Client(handler))  # type: ignore[arg-type]
    hits = await WaybackProfilesProvider().query("sample", "username", ctx)

    found = {h.source: h for h in hits if h.status is Status.FOUND}
    assert set(found) == {"Wayback: GitHub", "Wayback: Twitter"}
    assert found["Wayback: GitHub"].summary == "archived profile, first captured 2015-01-01"
    assert "weaker evidence" in found["Wayback: Twitter"].summary
    assert found["Wayback: GitHub"].confidence > found["Wayback: Twitter"].confidence
    [failed] = [h for h in hits if h.status is Status.UNKNOWN]
    assert failed.extra["failed_sites"] == ["Reddit"]
    assert len(ctx.client.calls) == len(PROFILE_URLS)

    report = Report(query="sample", query_type="username")
    report.add(Hit(source="GitHub", status=Status.NOT_FOUND, url="https://github.com/sample"))
    report.add(Hit(source="X", status=Status.FOUND, url="https://x.com/sample"))
    for hit in hits:
        report.add(hit)
    mark_deleted(report)
    assert "deleted or renamed?" in found["Wayback: GitHub"].summary
    assert found["Wayback: GitHub"].extra["live_status"] == "not_found"
    assert "deleted" not in found["Wayback: Twitter"].summary


@pytest.mark.asyncio
async def test_wayback_profiles_none_archived_is_one_not_found_hit() -> None:
    ctx = ProviderContext(settings=_settings(), client=Client(lambda u, p: Response(200, text="")))  # type: ignore[arg-type]
    hits = await WaybackProfilesProvider().query("sample", "username", ctx)
    assert [h.status for h in hits] == [Status.NOT_FOUND]
