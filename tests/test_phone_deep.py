# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from recce.core.result import Status
from recce.modules.phone import number_format_variants
from recce.modules.phone_deep import _parse_ddg, _real_url, deep_phone_probes

SAMPLE_HTML = """
<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fabout&amp;rut=x">Example &amp; About</a>
<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fforum.test%2Fthread">Forum Thread</a>
<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fcontact">Example Contact</a>
"""

NUM = ("+447826916903", "+44 7826 916903", "07826 916903")


def test_number_format_variants_shapes_and_dedup() -> None:
    v = number_format_variants(*NUM)
    assert "+447826916903" in v          # E.164
    assert "447826916903" in v           # E.164 without +
    assert "00447826916903" in v         # 00-prefixed
    assert "07826 916903" in v           # national spaced
    assert "07826916903" in v            # national digits only
    assert len(v) == len(set(v))         # de-duplicated


def test_real_url_unwraps_ddg_redirect() -> None:
    wrapped = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fx&rut=abc"
    assert _real_url(wrapped) == "https://example.com/x"
    assert _real_url("https://plain.example/y") == "https://plain.example/y"


def test_parse_ddg_extracts_urls_and_titles() -> None:
    res = _parse_ddg(SAMPLE_HTML)
    urls = [u for u, _ in res]
    assert "https://example.com/about" in urls
    assert "https://forum.test/thread" in urls
    assert ("https://example.com/about", "Example & About") in res


class _FakeResp:
    def __init__(self, text: str, status: int = 200) -> None:
        self.status_code = status
        self.text = text


class _FakeClient:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status = status
        self.calls: list[tuple[str, dict]] = []

    async def get(self, url: str, **kw):  # type: ignore[no-untyped-def]
        self.calls.append((url, kw))
        return _FakeResp(self.text, self.status)


@pytest.mark.asyncio
async def test_deep_phone_probes_dorks_and_live_results() -> None:
    client = _FakeClient(SAMPLE_HTML)
    hits = await deep_phone_probes(*NUM, client=client, max_concurrency=3, request_interval=0.0)  # type: ignore[arg-type]

    # Clickable platform dorks are always present, as Google site: searches.
    platform = [h for h in hits if h.category == "deep/platform"]
    assert len(platform) >= 5
    assert all(h.status is Status.FOUND for h in platform)
    assert all("google.com/search" in (h.url or "") and "site" in (h.url or "") for h in platform)

    # Category dorks.
    dork_sources = {h.source for h in hits if h.category == "deep/dork"}
    assert {"Documents", "Paste sites", "Spam / reputation"} <= dork_sources

    # Live web results parsed from the single DDG query.
    web = next(h for h in hits if h.source == "DuckDuckGo web")
    assert web.status is Status.FOUND
    assert "2 site(s)" in (web.summary or "")

    # Exactly one network call (the live query); dorks are offline.
    assert len(client.calls) == 1
    assert "duckduckgo.com/html" in client.calls[0][0]


@pytest.mark.asyncio
async def test_deep_phone_probes_live_challenge_degrades_gracefully() -> None:
    client = _FakeClient("anti-bot challenge", status=202)
    hits = await deep_phone_probes(*NUM, client=client, request_interval=0.0)  # type: ignore[arg-type]

    web = next(h for h in hits if h.source == "DuckDuckGo web")
    assert web.status is Status.UNKNOWN            # degraded, not crashed
    assert "dork links" in (web.summary or "")
    # The reliable dork backbone is still delivered.
    assert any(h.category == "deep/platform" and h.status is Status.FOUND for h in hits)


def test_bing_pivot_uses_unquoted_spaced_formats() -> None:
    from urllib.parse import parse_qs, urlparse

    from recce.modules.phone import _pivot_hits

    hits = {hit.source: hit for hit in _pivot_hits("+442087438000", "+44 20 8743 8000", "020 8743 8000", "GB")}

    bing_query = parse_qs(urlparse(hits["Bing web"].url or "").query)["q"][0]
    assert bing_query == "020 8743 8000 OR 02087438000 OR +44 20 8743 8000"
    assert '"' not in bing_query
    # Google and DuckDuckGo handle quoted phrases, so they keep every format.
    google_query = parse_qs(urlparse(hits["Google web"].url or "").query)["q"][0]
    assert '"+442087438000"' in google_query and '"00442087438000"' in google_query
