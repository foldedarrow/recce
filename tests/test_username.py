# SPDX-License-Identifier: AGPL-3.0-or-later
import httpx
import pytest

from recce.core.result import Status
from recce.modules import username as username_mod
from recce.modules.username import PerDomainThrottle, _check_site, _classify, _throttle_key


def test_present_probe_guarded_status_is_unknown() -> None:
    site = {"method": "present", "marker": "\"username\":\"{u}\""}

    status, note = _classify(site, 403, "blocked", "alice")

    assert status is Status.UNKNOWN
    assert note == "HTTP 403"


def test_present_probe_404_is_not_found() -> None:
    site = {"method": "present", "marker": "\"username\":\"{u}\""}

    status, note = _classify(site, 404, "missing", "alice")

    assert status is Status.NOT_FOUND
    assert note is None


def test_post_json_rate_limit_is_unknown() -> None:
    site = {"method": "post_json", "marker": "\"matchedUser\":{\"username\""}

    status, note = _classify(site, 429, "slow down", "alice")

    assert status is Status.UNKNOWN
    assert note == "HTTP 429"


def test_wmn_guarded_status_is_unknown() -> None:
    site = {
        "method": "wmn",
        "e_code": 200,
        "e_string": "exists",
        "m_code": 404,
        "m_string": "missing",
    }

    status, note = _classify(site, 403, "blocked", "alice")

    assert status is Status.UNKNOWN
    assert note == "HTTP 403 (blocked/rate-limited)"


@pytest.mark.asyncio
async def test_check_site_records_probe_evidence() -> None:
    class FakeClient:
        async def get(self, url: str, **kwargs):
            request = httpx.Request("GET", url)
            return httpx.Response(200, text="hello alice", request=request)

    site = {
        "name": "Example",
        "category": "dev",
        "url": "https://example.test/{u}",
        "probe": "https://example.test/api/{u}",
        "method": "present",
        "marker": "hello {u}",
    }

    hit = await _check_site(FakeClient(), site, "alice")

    assert hit.status is Status.FOUND
    assert hit.extra["method"] == "present"
    assert hit.extra["probe_url"] == "https://example.test/api/alice"
    assert hit.extra["status_code"] == 200
    assert hit.extra["final_url"] == "https://example.test/api/alice"


@pytest.mark.asyncio
async def test_per_domain_throttle_spaces_same_host_requests() -> None:
    now = 100.0
    sleeps: list[float] = []

    def monotonic() -> float:
        return now

    async def sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    throttle = PerDomainThrottle(
        rate_per_second=2.0,
        jitter_seconds=0.0,
        sleep=sleep,
        monotonic=monotonic,
    )

    await throttle.wait("https://www.example.test/a")
    await throttle.wait("https://example.test/b")
    await throttle.wait("https://other.test/a")

    assert sleeps == [0.5]


@pytest.mark.asyncio
async def test_per_domain_throttle_applies_guarded_backoff() -> None:
    now = 10.0
    sleeps: list[float] = []

    def monotonic() -> float:
        return now

    async def sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    throttle = PerDomainThrottle(
        rate_per_second=10.0,
        guarded_backoff_seconds=3.0,
        jitter_seconds=0.0,
        sleep=sleep,
        monotonic=monotonic,
    )

    await throttle.wait("https://example.test/a")
    throttle.backoff("https://example.test/a")
    await throttle.wait("https://example.test/b")

    assert sleeps == [3.0]


@pytest.mark.asyncio
async def test_check_site_extends_throttle_on_guarded_status() -> None:
    now = 10.0
    sleeps: list[float] = []

    def monotonic() -> float:
        return now

    async def sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    class FakeClient:
        async def get(self, url: str, **kwargs):
            request = httpx.Request("GET", url)
            return httpx.Response(429, text="slow down", request=request)

    throttle = PerDomainThrottle(
        rate_per_second=10.0,
        guarded_backoff_seconds=3.0,
        jitter_seconds=0.0,
        sleep=sleep,
        monotonic=monotonic,
    )
    site = {
        "name": "Example",
        "category": "dev",
        "url": "https://example.test/{u}",
        "probe": "https://example.test/api/{u}",
        "method": "present",
        "marker": "hello {u}",
    }

    hit = await _check_site(FakeClient(), site, "alice", throttle=throttle)
    await throttle.wait("https://example.test/next")

    assert hit.status is Status.UNKNOWN
    assert hit.summary == "HTTP 429"
    assert sleeps == [3.0]


def test_throttle_key_normalizes_www_hostname() -> None:
    assert _throttle_key("https://www.Example.test/user/alice") == "example.test"


def test_corrupt_wmn_cache_falls_back_to_bundled_snapshot(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "wmn-data.json"
    cache.write_text("{not json")
    monkeypatch.setattr(username_mod, "CACHED_WMN", cache)

    sites = username_mod._load_wmn_sites()

    assert len(sites) > 100


@pytest.mark.asyncio
async def test_canary_downgrades_site_that_finds_every_username(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce.core.result import Hit
    from recce.modules.username import _verify_found

    class FakeClient:
        async def get(self, url: str, **kwargs):
            request = httpx.Request("GET", url)
            # "Always200" answers 200 for anything; "Strict" only knows alice.
            ok = "always" in url or url.endswith("/alice")
            return httpx.Response(200 if ok else 404, text="", request=request)

    sites = {
        name: {"name": name, "category": "dev", "url": f"https://{host}/{{u}}", "method": "status", "found": [200], "missing": [404]}
        for name, host in (("Always200", "always.test"), ("Strict", "strict.test"))
    }
    hits = [
        Hit(source="Always200", status=Status.FOUND, url="https://always.test/alice", confidence=0.85),
        Hit(source="Strict", status=Status.FOUND, url="https://strict.test/alice", confidence=0.85),
    ]

    await _verify_found(FakeClient(), sites, hits, throttle=None)  # type: ignore[arg-type]

    always, strict = hits
    assert always.status is Status.UNKNOWN
    assert "made-up username" in (always.summary or "")
    assert always.extra["canary"]["status"] == "found"
    assert strict.status is Status.FOUND
    assert strict.extra["canary"]["status"] == "not_found"


def test_dedupe_by_profile_keeps_most_decisive_hit() -> None:
    from recce.core.result import Hit
    from recce.modules.username import _dedupe_by_profile

    hits = [
        Hit(source="GitHub", status=Status.UNKNOWN, url="https://github.com/alice"),
        Hit(source="GitHub (User)", status=Status.FOUND, url="https://www.github.com/alice/"),
        Hit(source="GitLab", status=Status.NOT_FOUND, url="https://gitlab.com/alice"),
    ]

    out = _dedupe_by_profile(hits)

    assert [hit.source for hit in out] == ["GitHub (User)", "GitLab"]
    assert out[0].extra["also_checked_as"] == ["GitHub"]


def test_custom_sites_override_exact_names_and_yield_on_case_only_duplicates(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.username as username

    monkeypatch.setattr(
        username,
        "_load_wmn_sites",
        lambda: [
            {"name": "tumblr", "category": "images", "url": "u", "method": "wmn"},
            {"name": "GitLab", "category": "coding", "url": "u", "method": "wmn"},
        ],
    )
    monkeypatch.setattr(
        username,
        "_load_custom_sites",
        lambda: [
            {"name": "Tumblr", "category": "social", "url": "u", "method": "status"},
            {"name": "GitLab", "category": "dev", "url": "u", "method": "status"},
        ],
    )

    sites = {site["name"]: site["method"] for site in username._load_sites()}

    # Case-only duplicate: WMN's maintained entry wins, ours is dropped.
    assert sites["tumblr"] == "wmn" and "Tumblr" not in sites
    # Exact name: the custom entry is a deliberate override.
    assert sites["GitLab"] == "status"


@pytest.mark.asyncio
async def test_check_site_reports_transport_error_reason() -> None:
    class FakeClient:
        async def request_detailed(self, method: str, url: str, **kwargs):
            return None, "DNS lookup failed (blocked by local resolver, or domain gone)"

    site = {"name": "Example", "category": "dev", "url": "https://example.test/{u}", "method": "status"}

    hit = await _check_site(FakeClient(), site, "alice")  # type: ignore[arg-type]

    assert hit.status is Status.ERROR
    assert hit.error is not None and hit.error.startswith("DNS lookup failed")


@pytest.mark.asyncio
async def test_search_username_uses_impersonating_client_when_available(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import recce.modules.username as username

    used: list[str] = []

    class FakeBrowser:
        closed = False

        @classmethod
        def from_client(cls, client):  # type: ignore[no-untyped-def]
            return cls()

        async def aclose(self) -> None:
            FakeBrowser.closed = True

    async def fake_search(name, client, **kwargs):  # type: ignore[no-untyped-def]
        used.append(type(client).__name__)
        return username.Report(query=name, query_type="username")

    monkeypatch.setattr(username, "ImpersonatingClient", FakeBrowser)
    monkeypatch.setattr(username, "_search_username", fake_search)
    monkeypatch.setattr(username, "impersonation_available", lambda: True)

    await username.search_username("alice", object(), show_progress=False)  # type: ignore[arg-type]
    await username.search_username("alice", object(), show_progress=False, impersonate=False)  # type: ignore[arg-type]

    assert used == ["FakeBrowser", "object"]
    assert FakeBrowser.closed


def test_describe_transport_error_handles_curl_messages() -> None:
    from recce.core.http import describe_transport_error

    class DNSError(Exception):
        pass

    class ReadTimeout(Exception):  # noqa: N818 - mirrors curl_cffi's exception name
        pass

    assert describe_transport_error(DNSError("Failed to perform, curl: (6) Could not resolve host: x.test")).startswith(
        "DNS lookup failed"
    )
    assert describe_transport_error(ReadTimeout("curl: (28) Operation timed out after 12001 ms")) == "timeout"
