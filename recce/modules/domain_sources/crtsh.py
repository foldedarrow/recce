# SPDX-License-Identifier: AGPL-3.0-or-later
"""crt.sh passive subdomain source."""

from __future__ import annotations

from .common import normalise_subdomain, safe_json
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> tuple[str, set[str], str | None]:
    resp = await ctx.client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if resp is None:
        return "crt.sh", set(), "network"
    if resp.status_code != 200:
        return "crt.sh", set(), f"HTTP {resp.status_code}"
    data = safe_json(resp, default=[])
    subs: set[str] = set()
    if isinstance(data, list):
        for item in data:
            for key in ("common_name", "name_value"):
                for raw in str(item.get(key, "")).splitlines():
                    host = normalise_subdomain(raw, domain)
                    if host:
                        subs.add(host)
    return "crt.sh", subs, None
