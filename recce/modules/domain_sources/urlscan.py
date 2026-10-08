# SPDX-License-Identifier: AGPL-3.0-or-later
"""urlscan.io passive subdomain source (public scan index; keyless)."""

from __future__ import annotations

from .common import normalise_subdomain, safe_json
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> tuple[str, set[str], str | None]:
    resp = await ctx.client.get(
        "https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 1000}
    )
    if resp is None:
        return "urlscan.io", set(), "network"
    if resp.status_code != 200:
        return "urlscan.io", set(), f"HTTP {resp.status_code}"
    data = safe_json(resp)
    subs: set[str] = set()
    for result in data.get("results") or [] if isinstance(data, dict) else []:
        for section in ("page", "task"):
            host = normalise_subdomain(str((result.get(section) or {}).get("domain") or ""), domain)
            if host:
                subs.add(host)
    return "urlscan.io", subs, None
