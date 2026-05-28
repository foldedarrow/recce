# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wayback CDX passive subdomain source."""

from __future__ import annotations

from urllib.parse import urlparse

from .common import normalise_subdomain, safe_json
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> tuple[str, set[str], str | None]:
    resp = await ctx.client.get(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": f"*.{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey"},
    )
    if resp is None:
        return "Wayback CDX", set(), "network"
    if resp.status_code != 200:
        return "Wayback CDX", set(), f"HTTP {resp.status_code}"
    data = safe_json(resp, default=[])
    subs = set()
    for row in data[1:] if isinstance(data, list) else []:
        value = row[0] if isinstance(row, list) and row else ""
        host = normalise_subdomain(urlparse(value).hostname or value, domain)
        if host:
            subs.add(host)
    return "Wayback CDX", subs, None
