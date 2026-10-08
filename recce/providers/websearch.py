# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keyed web search for phone numbers (Brave Search API or SerpAPI).

`--deep` ships clickable dorks and one best-effort DuckDuckGo query that server
IPs are usually challenged on. This provider runs the same searches through a
search API, so the pages that mention a number come back as hits without
clicking anything.

Three queries per number, each spanning every common textual format of it:
the number on its own, the number on social/classified sites, and the number on
spam-reputation sites. A result counts as a confirmed mention when the number's
digits appear in its title or snippet; otherwise it is a weak hit, because
search engines match numbers loosely.

Backend: `BRAVE_API_KEY` (preferred) or `SERPAPI_API_KEY`. The number is sent
to that vendor as a search query, which is the one thing this provider does
that the offline sources do not. Nothing is sent to the number or its owner.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from recce.config import Settings
from recce.core.result import Hit, Status

from .base import Provider, ProviderContext, ProviderStatus

_BRAVE = "https://api.search.brave.com/res/v1/web/search"
_SERPAPI = "https://serpapi.com/search.json"
MAX_RESULTS = 10

_SOCIAL_SITES = (
    "facebook.com", "instagram.com", "x.com", "linkedin.com", "t.me", "reddit.com",
    "gumtree.com", "craigslist.org", "ebay.co.uk", "yell.com",
)
_REPUTATION_SITES = (
    "tellows.co.uk", "who-called.co.uk", "whocalledme.com", "shouldianswer.com",
)
_TAG_RE = re.compile(r"<[^>]+>")


def _group(sites: tuple[str, ...]) -> str:
    return "(" + " OR ".join(f"site:{s}" for s in sites) + ")"


def queries_for(variants: list[str]) -> list[tuple[str, str]]:
    """(kind, query) for a number's textual variants."""
    combined = "(" + " OR ".join(f'"{v}"' for v in variants) + ")"
    return [
        ("web", combined),
        ("social", f"{combined} {_group(_SOCIAL_SITES)}"),
        ("reputation", f"{combined} {_group(_REPUTATION_SITES)}"),
    ]


class WebSearchProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="websearch",
            name="Web search",
            tier="pro",
            enriches=("phone",),
            config_keys=("BRAVE_API_KEY", "SERPAPI_API_KEY"),
            setting_attrs=("brave_api_key", "serpapi_api_key"),
            homepage="https://brave.com/search/api/",
            notes="pages that mention the number (Brave or SerpAPI; the number is sent to that vendor)",
        )

    def is_configured(self, settings: Settings) -> bool:
        return any(getattr(settings, attr, None) for attr in self.setting_attrs)

    def status(self, settings: Settings) -> ProviderStatus:
        status = super().status(settings)
        if status.state == "active":
            return ProviderStatus("active", f"{self.notes} via {_backend(settings)}")
        return status

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "phone":
            return []
        import phonenumbers

        from recce.modules.phone import number_format_variants

        try:
            parsed = phonenumbers.parse(target)
        except phonenumbers.NumberParseException:
            return []
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        variants = number_format_variants(target, intl, national)
        digit_forms = {re.sub(r"\D", "", v) for v in variants}
        digit_forms |= {d.lstrip("0") for d in digit_forms if len(d) > 7}
        backend = _backend(ctx.settings)

        started = time.perf_counter()
        searches = queries_for(variants)
        outcomes = await asyncio.gather(
            *(self._search(ctx, backend, query) for _, query in searches)
        )
        elapsed = int((time.perf_counter() - started) * 1000)

        hits: list[Hit] = []
        seen: set[str] = set()
        errors: list[str] = []
        for (kind, _), (results, error) in zip(searches, outcomes, strict=True):
            if error:
                errors.append(f"{kind}: {error}")
            for title, url, snippet in results[:MAX_RESULTS]:
                if url in seen:
                    continue
                seen.add(url)
                mentioned = _mentions(f"{title} {snippet}", digit_forms)
                hits.append(
                    self.make_hit(
                        "websearch",
                        Status.FOUND,
                        url=url,
                        summary=(title or url)[:140] + ("" if mentioned else " (number not in snippet)"),
                        confidence=0.7 if mentioned else 0.3,
                        elapsed_ms=elapsed,
                        extra={"query_kind": kind, "snippet": snippet[:300], "mentions_number": mentioned,
                               "backend": backend},
                    )
                )
        if errors and not hits:
            return [self.make_hit("websearch", Status.ERROR, error="; ".join(errors)[:160],
                                  confidence=0.0, extra={"backend": backend})]
        if not hits:
            return [self.make_hit("websearch", Status.NOT_FOUND,
                                  summary=f"no pages found for the number via {backend}",
                                  confidence=0.5, elapsed_ms=elapsed, extra={"backend": backend})]
        hits.sort(key=lambda h: -h.confidence)
        return hits

    async def _search(
        self, ctx: ProviderContext, backend: str, query: str
    ) -> tuple[list[tuple[str, str, str]], str | None]:
        """(results as (title, url, snippet), error)."""
        if backend == "brave":
            resp = await ctx.client.get(
                _BRAVE,
                params={"q": query, "count": MAX_RESULTS},
                headers={"X-Subscription-Token": ctx.settings.brave_api_key or "", "Accept": "application/json"},
            )
        else:
            resp = await ctx.client.get(
                _SERPAPI,
                params={"engine": "google", "q": query, "num": MAX_RESULTS,
                        "api_key": ctx.settings.serpapi_api_key or ""},
            )
        if resp is None:
            return [], "no response"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"
        try:
            data = resp.json()
        except Exception:
            return [], "bad json"
        return _parse(backend, data)


def _backend(settings: Settings) -> str:
    return "brave" if settings.brave_api_key else "serpapi"


def _parse(backend: str, data: dict[str, Any]) -> tuple[list[tuple[str, str, str]], str | None]:
    if backend == "brave":
        rows = ((data.get("web") or {}).get("results")) or []
        fields = ("title", "url", "description")
        error = None
    else:
        rows = data.get("organic_results") or []
        fields = ("title", "link", "snippet")
        error = data.get("error") if not rows else None
        if error and "hasn't returned any results" in str(error):
            error = None  # SerpAPI's wording for an empty result set
    out = []
    for row in rows:
        url = row.get(fields[1])
        if isinstance(url, str) and url.startswith("http"):
            out.append((_clean(row.get(fields[0])), url, _clean(row.get(fields[2]))))
    return out, (str(error)[:100] if error else None)


def _clean(value: Any) -> str:
    return _TAG_RE.sub("", str(value or "")).replace("&amp;", "&").strip()


def _mentions(text: str, digit_forms: set[str]) -> bool:
    """True when the text contains the number in any of its digit forms,
    ignoring spaces, dashes and brackets between the digits."""
    digits = re.sub(r"[\s\-().]", "", text)
    return any(form and form in digits for form in digit_forms)
