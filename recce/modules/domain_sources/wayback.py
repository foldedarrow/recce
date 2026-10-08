# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wayback Machine: when the domain was first archived, and the latest
archived copy of its key pages (about, contact, team, privacy)."""

from __future__ import annotations

import asyncio

from recce.core.result import Hit, Status
from recce.modules.archive import ArchiveRateLimitError, calendar_url, capture

from .registry import SourceContext

KEY_PAGES = ("about", "contact", "team", "privacy")
CONCURRENCY = 2


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    try:
        first = await capture(ctx.client, domain)
    except ArchiveRateLimitError:
        return [_skipped("Wayback first seen")]
    except RuntimeError as e:
        status = Status.ERROR if str(e) == "network" else Status.UNKNOWN
        return [Hit(source="Wayback first seen", category="wayback", status=status, summary=str(e))]
    if first is None:
        return [
            Hit(source="Wayback first seen", category="wayback", status=Status.NOT_FOUND,
                summary="No archived snapshot")
        ]
    hits = [
        Hit(
            source="Wayback first seen",
            category="wayback",
            status=Status.FOUND,
            url=first.url,
            summary=first.date,
            extra={"timestamp": first.timestamp, "original": first.original},
            confidence=0.7,
        )
    ]
    return hits + await _key_pages(domain, ctx)


async def _key_pages(domain: str, ctx: SourceContext) -> list[Hit]:
    sem = asyncio.Semaphore(CONCURRENCY)
    limited = asyncio.Event()

    async def page(path: str) -> Hit | None:
        source = f"Wayback /{path}"
        async with sem:
            if limited.is_set():
                return None
            try:
                latest = await capture(ctx.client, f"{domain}/{path}", latest=True)
            except ArchiveRateLimitError:
                limited.set()
                return None
            except RuntimeError as e:
                return Hit(source=source, category="wayback", status=Status.UNKNOWN, summary=str(e))
        if latest is None:
            return Hit(source=source, category="wayback", status=Status.NOT_FOUND, summary="never archived")
        return Hit(
            source=source,
            category="wayback",
            status=Status.FOUND,
            url=latest.url,
            summary=f"latest archived copy {latest.date}",
            extra={"timestamp": latest.timestamp, "original": latest.original,
                   "calendar": calendar_url(f"{domain}/{path}")},
            confidence=0.7,
        )

    results = [h for h in await asyncio.gather(*(page(p) for p in KEY_PAGES)) if h]
    if limited.is_set():
        results.append(_skipped("Wayback key pages"))
    return results


def _skipped(source: str) -> Hit:
    return Hit(source=source, category="wayback", status=Status.SKIPPED,
               summary="archive.org rate limit (429); try again later")
