import httpx
import pytest

from recce.core.result import Status
from recce.modules import username as username_mod
from recce.modules.username import _check_site, _classify


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


def test_corrupt_wmn_cache_falls_back_to_bundled_snapshot(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "wmn-data.json"
    cache.write_text("{not json")
    monkeypatch.setattr(username_mod, "CACHED_WMN", cache)

    sites = username_mod._load_wmn_sites()

    assert len(sites) > 100
