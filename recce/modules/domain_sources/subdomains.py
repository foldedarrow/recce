# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passive subdomain discovery domain source."""

from __future__ import annotations

import asyncio

from recce.core.result import Hit, Status

from . import certspotter, crtsh, hackertarget, otx, urlscan, wayback_subdomains
from .common import dns_lookup
from .registry import SourceContext

DNS_CONCURRENCY = 50


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    sources = await asyncio.gather(
        crtsh.query(domain, ctx),
        certspotter.query(domain, ctx),
        urlscan.query(domain, ctx),
        hackertarget.query(domain, ctx),
        otx.query(domain, ctx),
        wayback_subdomains.query(domain, ctx),
    )
    found: dict[str, set[str]] = {}
    source_errors: list[str] = []
    for source_name, subs, error in sources:
        if error:
            source_errors.append(f"{source_name}: {error}")
        for sub in subs:
            found.setdefault(sub, set()).add(source_name)
    live: list[str] = []
    unresolved: list[str] = []
    if ctx.validate_subdomains:
        # Resolve concurrently: big domains return thousands of names, and a
        # sequential A+AAAA loop (up to 5s per lookup) could take hours.
        sem = asyncio.Semaphore(DNS_CONCURRENCY)

        async def resolves(host: str) -> bool:
            async with sem:
                records, _ = await dns_lookup(host, "A")
                if records:
                    return True
                records6, _ = await dns_lookup(host, "AAAA")
                return bool(records6)

        names = sorted(found)
        for host, ok in zip(names, await asyncio.gather(*(resolves(host) for host in names)), strict=True):
            (live if ok else unresolved).append(host)
    else:
        live = sorted(found)
    summary = f"{len(found)} passive subdomain(s)"
    if ctx.validate_subdomains:
        summary += f" · {len(live)} resolving · {len(unresolved)} historical/unresolved"
    if source_errors:
        summary += f" · source issues: {len(source_errors)}"
    return [
        Hit(
            source="Passive subdomains",
            category="subs",
            status=Status.FOUND if found else Status.NOT_FOUND,
            summary=summary,
            extra={
                "subdomains": [
                    {"host": sub, "sources": sorted(found[sub]), "resolves": sub in live}
                    for sub in sorted(found)
                ],
                "source_errors": source_errors,
            },
            confidence=0.8,
        )
    ]
