# SPDX-License-Identifier: AGPL-3.0-or-later
"""Web surface, TLS, robots, and sitemap domain source."""

from __future__ import annotations

import asyncio
import re
import time
from html.parser import HTMLParser
from typing import Any

from recce.core.result import Hit, Status

from . import tls
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    hits: list[Hit] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        started = time.perf_counter()
        resp = await ctx.client.get(url)
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            hits.append(Hit(source=f"{scheme.upper()} probe", category="web", status=Status.ERROR, url=url, error="network", elapsed_ms=elapsed))
            continue
        title, meta, canonical, socials, technologies = _parse_html(resp.text, resp.headers)
        parts = [f"HTTP {resp.status_code}", f"final: {resp.url}"]
        if title:
            parts.append(f"title: {title}")
        if technologies:
            parts.append("tech: " + ", ".join(technologies[:6]))
        hits.append(
            Hit(
                source=f"{scheme.upper()} probe",
                category="web",
                status=Status.FOUND if resp.status_code < 500 else Status.UNKNOWN,
                url=str(resp.url),
                summary=" · ".join(parts),
                extra={
                    "status_code": resp.status_code,
                    "server": resp.headers.get("server"),
                    "title": title,
                    "meta_description": meta,
                    "canonical": canonical,
                    "technologies": technologies,
                    "socials": socials,
                },
                confidence=0.85,
                elapsed_ms=elapsed,
            )
        )
        if socials:
            hits.append(
                Hit(
                    source="Linked socials",
                    category="web",
                    status=Status.FOUND,
                    summary=", ".join(socials[:8]),
                    extra={"links": socials},
                    confidence=0.7,
                )
            )
    cert_hit = await asyncio.to_thread(tls.hit, domain)
    if cert_hit:
        hits.append(cert_hit)
    for path in ("robots.txt", "sitemap.xml"):
        url = f"https://{domain}/{path}"
        resp = await ctx.client.get(url)
        if resp is not None and resp.status_code == 200:
            summary = _summarise_declared_file(path, resp.text)
            hits.append(
                Hit(
                    source=path,
                    category="web",
                    status=Status.FOUND,
                    url=url,
                    summary=summary,
                    extra={"sample": resp.text[:3000]},
                    confidence=0.7,
                )
            )
        else:
            code = "network" if resp is None else f"HTTP {resp.status_code}"
            hits.append(Hit(source=path, category="web", status=Status.NOT_FOUND, url=url, summary=code))
    return hits


def _parse_html(html: str, headers: Any) -> tuple[str | None, str | None, str | None, list[str], list[str]]:
    parser = _HomepageParser()
    try:
        parser.feed(html[:500_000])
    except Exception:
        pass
    technologies = _detect_technologies(html, headers, parser.meta)
    return parser.title, parser.meta.get("description"), parser.canonical, sorted(parser.socials), technologies


class _HomepageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title: str | None = None
        self.meta: dict[str, str] = {}
        self.canonical: str | None = None
        self.socials: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            name = (attr.get("name") or attr.get("property") or "").lower()
            content = attr.get("content") or ""
            if name and content:
                self.meta[name] = content[:300]
        if tag == "link" and attr.get("rel", "").lower() == "canonical":
            self.canonical = attr.get("href") or None
        if tag == "a" and attr.get("href"):
            link = attr["href"]
            if re.search(
                r"(linkedin\.com/(company|in)/|twitter\.com/|//(www\.)?x\.com/|facebook\.com/|instagram\.com/|"
                r"youtube\.com/|github\.com/|tiktok\.com/@|threads\.net/@|bsky\.app/profile/|mastodon\.)",
                link,
                re.I,
            ):
                self.socials.add(link.split("?", 1)[0].rstrip("/"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            self.title = " ".join(data.split())[:160]


def _detect_technologies(html: str, headers: Any, meta: dict[str, str]) -> list[str]:
    text = html[:200_000].lower()
    header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    generator = (meta.get("generator") or "").lower()
    checks = [
        ("WordPress", "wp-content" in text or "wordpress" in generator),
        ("Drupal", "drupal" in generator or "/sites/default/" in text),
        ("Shopify", "cdn.shopify.com" in text or "shopify" in header_text),
        ("Wix", "wixstatic.com" in text),
        ("Squarespace", "static1.squarespace.com" in text or "squarespace" in generator),
        ("Webflow", "assets.website-files.com" in text or "data-wf-site" in text or "webflow" in generator),
        ("HubSpot", "hs-scripts.com" in text or "js.hs-analytics.net" in text or "hubspot" in header_text),
        ("Cloudflare", "cloudflare" in header_text),
        ("AWS CloudFront", "cloudfront" in header_text),
        ("Fastly", "fastly" in header_text),
        ("Google Analytics", "google-analytics.com" in text or "gtag/js" in text),
        ("Google Tag Manager", "googletagmanager.com" in text),
        # Framework checks need markers the framework itself emits: plain
        # substrings like "react"/"vue" matched ordinary words ("reaction",
        # "revue") and flagged most sites.
        ("React", bool(re.search(r"data-reactroot|react-dom(\.production)?(\.min)?\.js|__react|_reactlistening", text))),
        ("Next.js", "__next_data__" in text or "/_next/static/" in text),
        ("Nuxt", "__nuxt" in text or "/_nuxt/" in text),
        ("Vue", bool(re.search(r"\bdata-v-[0-9a-f]{6,8}\b|vue(\.runtime)?(\.global)?(\.prod)?(\.min)?\.js|__vue_app__", text))),
        ("Angular", bool(re.search(r"\bng-version=|\b_ngcontent-", text))),
        ("Svelte", bool(re.search(r"\bsvelte-[a-z0-9]{5,8}\b|/_app/immutable/", text))),
    ]
    return [name for name, ok in checks if ok]


def _summarise_declared_file(path: str, text: str) -> str:
    if path == "robots.txt":
        disallow = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.lower().startswith("disallow:")]
        return f"{len(disallow)} disallow rule(s)" + (f" · {', '.join(disallow[:5])}" if disallow else "")
    urls = re.findall(r"<loc>(.*?)</loc>", text, flags=re.I)
    return f"{len(urls)} sitemap URL(s)" + (f" · {', '.join(urls[:3])}" if urls else "")

