# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep phone footprint — PhoneInfoga-style passive search-engine footprinting.

For a validated number we:

1. Generate a comprehensive set of **clickable search dorks** — per-platform
   ``site:`` dorks (socials, classifieds, paste sites) and category dorks
   (documents, paste sites, spam/reputation) — each spanning every common
   textual format of the number. These always work: the operator clicks them
   and the search runs in their own browser.
2. Make **one** best-effort live DuckDuckGo query for the number and, when it
   isn't challenged, list the public pages it surfaces.

Everything is *passive*: we only read public search results and never contact
the number, its owner, or any account. Free search endpoints aggressively
challenge quoted/operator queries from server IPs, so the live step is strictly
best-effort — the dork links are the reliable backbone. A keyed search provider
(SerpAPI / Brave / Google CSE) is the path to reliable automated results and can
slot in here later as a Pro-gated source.
"""

from __future__ import annotations

import asyncio
import re
import time
from html import unescape
from urllib.parse import parse_qs, quote, unquote, urlparse

from ..core.http import HttpClient
from ..core.result import Hit, Status
from .phone import number_format_variants

_DDG_HTML = "https://html.duckduckgo.com/html/"
_GOOGLE = "https://www.google.com/search?q="
# A real browser UA — DuckDuckGo serves an anti-bot challenge to honest UAs.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

# (label, domain) — platforms where phone numbers commonly appear publicly.
_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("Facebook", "facebook.com"),
    ("Instagram", "instagram.com"),
    ("X / Twitter", "twitter.com"),
    ("LinkedIn", "linkedin.com"),
    ("Telegram", "t.me"),
    ("Reddit", "reddit.com"),
    ("Gumtree", "gumtree.com"),
    ("Craigslist", "craigslist.org"),
    ("eBay UK", "ebay.co.uk"),
    ("Yell (UK)", "yell.com"),
)

_RESULT_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_MAX_WEB_RESULTS = 10


def _real_url(href: str) -> str:
    """DuckDuckGo wraps outbound links in a /l/?uddg=<url> redirect; unwrap it."""
    href = unescape(href).strip()
    if href.startswith("//"):
        href = "https:" + href
    if "duckduckgo.com/l/" in href:
        qs = parse_qs(urlparse(href).query)
        if qs.get("uddg"):
            return unquote(qs["uddg"][0])
    return href


def _parse_ddg(html: str) -> list[tuple[str, str]]:
    """Extract (url, title) pairs from a DuckDuckGo HTML results page."""
    out: list[tuple[str, str]] = []
    for href, title in _RESULT_RE.findall(html):
        url = _real_url(href)
        text = unescape(_TAG_RE.sub("", title)).strip()
        if url.startswith("http"):
            out.append((url, text))
    return out


def _dork_hits(combined: str) -> list[Hit]:
    """Clickable Google dorks — the reliable backbone of deep mode."""
    hits: list[Hit] = []
    for label, domain in _PLATFORMS:
        hits.append(
            Hit(
                source=label,
                category="deep/platform",
                status=Status.FOUND,
                url=_GOOGLE + quote(f"site:{domain} ({combined})"),
                summary=f"site: dork — search {domain} for every number format",
                confidence=0.4,
            )
        )
    category_dorks = [
        ("Documents", f"({combined}) (filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:docx)"),
        ("Paste sites", f"({combined}) (site:pastebin.com OR site:ghostbin.com OR site:paste.ee OR site:throwbin.io)"),
        ("Spam / reputation", f"({combined}) (site:tellows.co.uk OR site:who-called.co.uk OR site:whocalledme.com OR site:shouldianswer.com)"),
    ]
    for label, query in category_dorks:
        hits.append(
            Hit(
                source=label,
                category="deep/dork",
                status=Status.FOUND,
                url=_GOOGLE + quote(query),
                summary="category dork — click to run the search",
                confidence=0.4,
            )
        )
    return hits


async def _live_ddg(client: HttpClient, combined: str, retries: int = 1) -> list[tuple[str, str]] | None:
    """One best-effort DuckDuckGo query. None => challenged/unreachable."""
    headers = {"User-Agent": _BROWSER_UA, "Referer": "https://duckduckgo.com/"}
    for attempt in range(retries + 1):
        resp = await client.get(_DDG_HTML, params={"q": combined}, headers=headers)
        # DDG serves its anti-bot challenge as HTTP 202; only 200 carries results.
        if resp is not None and resp.status_code == 200:
            return _parse_ddg(resp.text)
        if attempt < retries:
            await asyncio.sleep(1.5 * (attempt + 1))
    return None


async def deep_phone_probes(
    e164: str,
    intl: str,
    national: str,
    *,
    client: HttpClient,
    max_concurrency: int = 4,  # retained for signature stability; deep mode now issues one live query
    request_interval: float = 0.8,
) -> list[Hit]:
    variants = number_format_variants(e164, intl, national)
    combined = " OR ".join(f'"{v}"' for v in variants)

    # 1. Reliable dork backbone (no network).
    hits: list[Hit] = _dork_hits(combined)

    # 2. Best-effort live web footprint (one query).
    started = time.perf_counter()
    web = await _live_ddg(client, combined)
    elapsed = int((time.perf_counter() - started) * 1000)
    if web is None:
        hits.append(
            Hit(
                source="DuckDuckGo web",
                category="deep/web",
                status=Status.UNKNOWN,
                summary="live search was rate-limited/challenged — use the dork links above, "
                        "or configure a search-API key for automated results",
                elapsed_ms=elapsed,
            )
        )
    elif not web:
        hits.append(
            Hit(
                source="DuckDuckGo web",
                category="deep/web",
                status=Status.NOT_FOUND,
                summary="no public web results for any number format",
                elapsed_ms=elapsed,
            )
        )
    else:
        seen: set[str] = set()
        uniq: list[tuple[str, str, str]] = []
        for url, title in web:
            net = urlparse(url).netloc.lower().removeprefix("www.")
            if net and net not in seen:
                seen.add(net)
                uniq.append((url, title, net))
        hits.append(
            Hit(
                source="DuckDuckGo web",
                category="deep/web",
                status=Status.FOUND,
                summary=f"{len(web)} result(s) across {len(uniq)} site(s)",
                extra={"results": [{"url": u, "title": t} for u, t, _ in uniq[:_MAX_WEB_RESULTS]]},
                confidence=0.6,
                elapsed_ms=elapsed,
            )
        )
        for url, title, net in uniq[:_MAX_WEB_RESULTS]:
            hits.append(
                Hit(
                    source=net,
                    category="deep/web",
                    status=Status.FOUND,
                    url=url,
                    summary=(title or "")[:120],
                    confidence=0.5,
                )
            )
    return hits
