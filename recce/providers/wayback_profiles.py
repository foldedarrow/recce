# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wayback Machine profiles — was this username's profile ever archived?

Checks the profile URL on a short list of major sites for an HTTP-200
capture. An archived profile shows the account existed at that date, even
if it has since been deleted, suspended or renamed; `mark_deleted` flags the
ones whose live probe in the same report came back "not found".

Single-page-app sites (X/Twitter since ~2020, Instagram) can serve 200 for
any path, so a capture there is weaker evidence than on GitHub or Reddit.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

from recce.core.result import Hit, Report, Status
from recce.modules.archive import ArchiveRateLimitError, calendar_url, capture

from .base import Provider, ProviderContext

# site name → profile URL ({u} = username). Kept short: archive.org rate-limits.
PROFILE_URLS: dict[str, str] = {
    "Twitter": "twitter.com/{u}",
    "Instagram": "instagram.com/{u}/",
    "Facebook": "facebook.com/{u}",
    "Reddit": "reddit.com/user/{u}",
    "GitHub": "github.com/{u}",
    "YouTube": "youtube.com/@{u}",
    "TikTok": "tiktok.com/@{u}",
    "Medium": "medium.com/@{u}",
    "Pinterest": "pinterest.com/{u}/",
    "Tumblr": "{u}.tumblr.com/",
    "SoundCloud": "soundcloud.com/{u}",
    "Twitch": "twitch.tv/{u}",
    "Flickr": "flickr.com/people/{u}/",
    "DeviantArt": "deviantart.com/{u}",
    "Keybase": "keybase.io/{u}",
    "Myspace": "myspace.com/{u}",
}
SPA_SITES = {"Twitter", "Instagram", "TikTok"}
CONCURRENCY = 3
_HOST_ALIASES = {"x.com": "twitter.com"}


class WaybackProfilesProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="wayback-profiles",
            name="Wayback profiles",
            tier="free",
            enriches=("username",),
            config_keys=(),
            setting_attrs=(),
            homepage="https://archive.org/help/wayback_api.php",
            notes=f"archived profile pages on {len(PROFILE_URLS)} major sites (finds deleted accounts); no key",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "username":
            return []
        sem = asyncio.Semaphore(CONCURRENCY)
        limited = asyncio.Event()
        failed: list[str] = []
        started = time.perf_counter()

        async def check(site: str, pattern: str) -> Hit | None:
            url = pattern.format(u=target)
            async with sem:
                if limited.is_set():
                    return None
                try:
                    found = await capture(ctx.client, url)
                except ArchiveRateLimitError:
                    limited.set()
                    return None
                except RuntimeError:
                    failed.append(site)
                    return None
            if found is None:
                return None
            spa = site in SPA_SITES
            summary = f"archived profile, first captured {found.date}"
            if spa:
                summary += " (site serves 200 for any path: weaker evidence)"
            return Hit(
                source=f"Wayback: {site}",
                category="archive",
                status=Status.FOUND,
                url=found.url,
                summary=summary,
                confidence=0.5 if spa else 0.75,
                extra={
                    "provider_id": self.id,
                    "site": site,
                    "host": _host(url),
                    "original": found.original,
                    "first_capture": found.timestamp,
                    "calendar": calendar_url(url),
                },
            )

        results = await asyncio.gather(*(check(site, p) for site, p in PROFILE_URLS.items()))
        hits = [h for h in results if h is not None]
        elapsed = int((time.perf_counter() - started) * 1000)
        if limited.is_set():
            hits.append(
                self.make_hit("archive", Status.SKIPPED, elapsed_ms=elapsed,
                              summary="archive.org rate limit (429): some sites not checked")
            )
        if failed:
            hits.append(
                self.make_hit("archive", Status.UNKNOWN, elapsed_ms=elapsed,
                              summary=f"archive.org lookup failed for {', '.join(sorted(failed))}",
                              extra={"failed_sites": sorted(failed)})
            )
        if not hits:
            hits.append(
                self.make_hit("archive", Status.NOT_FOUND, elapsed_ms=elapsed,
                              summary=f"no archived profile on {len(PROFILE_URLS)} major sites")
            )
        return hits


def mark_deleted(report: Report) -> None:
    """Flag archived profiles whose live probe in `report` says "not found"."""
    missing_hosts = {
        _host(h.url) for h in report.hits if h.status is Status.NOT_FOUND and h.url
    }
    for hit in report.hits:
        if hit.extra.get("provider_id") != "wayback-profiles" or hit.status is not Status.FOUND:
            continue
        if hit.extra.get("host") in missing_hosts:
            hit.extra["live_status"] = "not_found"
            hit.summary = f"{hit.summary} · live profile now missing: deleted or renamed?"


def _host(url: str | None) -> str:
    raw = url or ""
    host = (urlparse(raw if "://" in raw else f"https://{raw}").hostname or "").lower()
    for prefix in ("www.", "m.", "old.", "mobile."):
        host = host.removeprefix(prefix)
    return _HOST_ALIASES.get(host, host)
