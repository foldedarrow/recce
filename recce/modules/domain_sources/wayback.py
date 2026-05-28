# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wayback first-seen domain source."""

from __future__ import annotations

from recce.core.result import Hit, Status

from .common import safe_json
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    url = "https://web.archive.org/cdx/search/cdx"
    resp = await ctx.client.get(url, params={"url": domain, "output": "json", "limit": "1", "fl": "timestamp,original"})
    if resp is None:
        return [Hit(source="Wayback first seen", category="wayback", status=Status.ERROR, error="network")]
    if resp.status_code != 200:
        return [Hit(source="Wayback first seen", category="wayback", status=Status.UNKNOWN, summary=f"HTTP {resp.status_code}")]
    data = safe_json(resp, default=[])
    if len(data) < 2:
        return [Hit(source="Wayback first seen", category="wayback", status=Status.NOT_FOUND, summary="No archived snapshot")]
    ts = data[1][0]
    date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    original = data[1][1] if len(data[1]) > 1 else domain
    return [
        Hit(
            source="Wayback first seen",
            category="wayback",
            status=Status.FOUND,
            url=f"https://web.archive.org/web/{ts}/{original}",
            summary=date,
            extra={"timestamp": ts, "original": original},
            confidence=0.7,
        )
    ]
