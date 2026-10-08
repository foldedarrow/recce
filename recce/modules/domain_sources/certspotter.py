# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSLMate Cert Spotter passive subdomain source (CT logs; keyless tier).

A second certificate-transparency source, because crt.sh frequently times
out or returns 502 for busy domains.
"""

from __future__ import annotations

from .common import normalise_subdomain, safe_json
from .registry import SourceContext

MAX_PAGES = 5


async def query(domain: str, ctx: SourceContext) -> tuple[str, set[str], str | None]:
    subs: set[str] = set()
    after: str | None = None
    for _ in range(MAX_PAGES):
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            params["after"] = after
        resp = await ctx.client.get("https://api.certspotter.com/v1/issuances", params=params)
        if resp is None:
            return "Cert Spotter", subs, None if subs else "network"
        if resp.status_code != 200:
            # Keep what earlier pages found; only report an error if nothing did.
            return "Cert Spotter", subs, None if subs else f"HTTP {resp.status_code}"
        page = safe_json(resp, default=[])
        if not isinstance(page, list) or not page:
            break
        for issuance in page:
            for name in issuance.get("dns_names") or []:
                host = normalise_subdomain(str(name), domain)
                if host:
                    subs.add(host)
        after = str(page[-1].get("id") or "")
        if not after:
            break
    return "Cert Spotter", subs, None
