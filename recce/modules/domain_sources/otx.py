# SPDX-License-Identifier: AGPL-3.0-or-later
"""AlienVault OTX passive DNS subdomain source."""

from __future__ import annotations

from .common import normalise_subdomain, safe_json
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> tuple[str, set[str], str | None]:
    resp = await ctx.client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if resp is None:
        return "AlienVault OTX", set(), "network"
    if resp.status_code != 200:
        return "AlienVault OTX", set(), f"HTTP {resp.status_code}"
    data = safe_json(resp)
    subs = set()
    for item in data.get("passive_dns") or []:
        host = normalise_subdomain(item.get("hostname", ""), domain)
        if host:
            subs.add(host)
    return "AlienVault OTX", subs, None
