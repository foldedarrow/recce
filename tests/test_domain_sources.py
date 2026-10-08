# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio

import pytest

from recce.modules.domain_sources import certspotter, subdomains, urlscan
from recce.modules.domain_sources.registry import SourceContext
from recce.modules.domain_sources.web import _detect_technologies


class Response:
    def __init__(self, status_code: int, payload) -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload

    def json(self):  # type: ignore[no-untyped-def]
        return self._payload


class Client:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append((url, kwargs))
        return self.responses.pop(0) if self.responses else Response(200, [])


def _ctx(client) -> SourceContext:  # type: ignore[no-untyped-def]
    return SourceContext(client=client, settings=None, validate_subdomains=True)  # type: ignore[arg-type]


def test_tech_detection_ignores_ordinary_words() -> None:
    prose = "<p>Our reaction to the revue on the avenue was positive. Value!</p>"
    assert _detect_technologies(prose, {}, {}) == []


def test_tech_detection_finds_framework_markers() -> None:
    html = '<div data-reactroot=""></div><script id="__NEXT_DATA__"></script><span data-v-7ba5bd90></span>'
    found = _detect_technologies(html.lower(), {}, {})
    assert {"React", "Next.js", "Vue"} <= set(found)


@pytest.mark.asyncio
async def test_certspotter_paginates_and_normalises() -> None:
    client = Client(
        [
            Response(200, [{"id": "1", "dns_names": ["*.example.com", "www.example.com", "other.org"]}]),
            Response(200, [{"id": "2", "dns_names": ["api.example.com"]}]),
            Response(200, []),
        ]
    )

    name, subs, error = await certspotter.query("example.com", _ctx(client))

    assert (name, error) == ("Cert Spotter", None)
    assert subs == {"www.example.com", "api.example.com"}
    assert client.requests[1][1]["params"]["after"] == "1"


@pytest.mark.asyncio
async def test_certspotter_keeps_partial_results_on_later_error() -> None:
    client = Client([Response(200, [{"id": "1", "dns_names": ["a.example.com"]}]), Response(429, {})])

    _, subs, error = await certspotter.query("example.com", _ctx(client))

    assert subs == {"a.example.com"} and error is None


@pytest.mark.asyncio
async def test_urlscan_collects_page_and_task_domains() -> None:
    payload = {"results": [{"page": {"domain": "shop.example.com"}, "task": {"domain": "www.example.com"}}]}

    _, subs, error = await urlscan.query("example.com", _ctx(Client([Response(200, payload)])))

    assert subs == {"shop.example.com", "www.example.com"} and error is None


@pytest.mark.asyncio
async def test_subdomain_validation_runs_concurrently(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    names = {f"h{i}.example.com" for i in range(40)}
    in_flight = 0
    peak = 0

    async def fake_source(domain, ctx):  # type: ignore[no-untyped-def]
        return "fake", names, None

    async def fake_dns(name: str, rtype: str):  # type: ignore[no-untyped-def]
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return (["192.0.2.1"] if rtype == "A" and name.startswith("h1") else []), None

    for module in ("crtsh", "certspotter", "urlscan", "hackertarget", "otx", "wayback_subdomains"):
        monkeypatch.setattr(getattr(subdomains, module), "query", fake_source)
    monkeypatch.setattr(subdomains, "dns_lookup", fake_dns)

    [hit] = await subdomains.query("example.com", _ctx(Client([])))

    resolving = {row["host"] for row in hit.extra["subdomains"] if row["resolves"]}
    assert resolving == {name for name in names if name.startswith("h1")}
    assert peak > 1
