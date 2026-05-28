# SPDX-License-Identifier: AGPL-3.0-or-later
"""HackerTarget hostsearch passive subdomain source."""

from __future__ import annotations

import csv

from .common import normalise_subdomain
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> tuple[str, set[str], str | None]:
    resp = await ctx.client.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    if resp is None:
        return "HackerTarget", set(), "network"
    if resp.status_code != 200:
        return "HackerTarget", set(), f"HTTP {resp.status_code}"
    subs = set()
    for row in csv.reader(resp.text.splitlines()):
        if row:
            host = normalise_subdomain(row[0], domain)
            if host:
                subs.add(host)
    return "HackerTarget", subs, None
