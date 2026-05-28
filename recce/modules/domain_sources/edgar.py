# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEC EDGAR company pivot source."""

from __future__ import annotations

from recce.core.result import Hit, Status

from .registry import SourceContext


async def query(org_guess: str, ctx: SourceContext) -> Hit:
    resp = await ctx.client.get(
        "https://www.sec.gov/cgi-bin/browse-edgar",
        params={"action": "getcompany", "company": org_guess, "owner": "include", "count": "10"},
        headers={"User-Agent": ctx.settings.user_agent},
    )
    if resp is not None and resp.status_code == 200 and "CIK" in resp.text:
        return Hit(
            source="SEC EDGAR",
            category="companies",
            status=Status.FOUND,
            url=str(resp.url),
            summary=f"Possible EDGAR match for '{org_guess}'",
            confidence=0.45,
        )
    return Hit(source="SEC EDGAR", category="companies", status=Status.NOT_FOUND, summary=f"No obvious match for '{org_guess}'")
