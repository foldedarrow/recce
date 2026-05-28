# SPDX-License-Identifier: AGPL-3.0-or-later
"""Companies House source."""

from __future__ import annotations

import base64

from recce.core.result import Hit, Status

from .common import safe_json
from .registry import SourceContext


async def query(org_guess: str, ctx: SourceContext) -> Hit:
    if not ctx.settings.provider_integrations_enabled:
        return Hit(
            source="Companies House",
            category="companies",
            status=Status.SKIPPED,
            summary="provider integrations disabled",
        )
    if not ctx.settings.companies_house_key:
        return Hit(
            source="Companies House",
            category="companies",
            status=Status.SKIPPED,
            summary="set COMPANIES_HOUSE_KEY to enable UK company lookup",
        )

    auth = base64.b64encode(f"{ctx.settings.companies_house_key}:".encode()).decode()
    resp = await ctx.client.get(
        "https://api.company-information.service.gov.uk/search/companies",
        params={"q": org_guess, "items_per_page": 5},
        headers={"Authorization": f"Basic {auth}"},
    )
    if resp is not None and resp.status_code == 200:
        data = safe_json(resp)
        items = data.get("items") or []
        if items:
            top = items[0]
            return Hit(
                source="Companies House",
                category="companies",
                status=Status.FOUND,
                url=top.get("links", {}).get("self"),
                summary=f"{top.get('title')} · {top.get('company_status')} · {top.get('company_number')}",
                extra={"query": org_guess, "items": items[:5]},
                confidence=0.55,
            )
        return Hit(
            source="Companies House",
            category="companies",
            status=Status.NOT_FOUND,
            summary=f"No obvious match for '{org_guess}'",
        )
    code = "network" if resp is None else f"HTTP {resp.status_code}"
    return Hit(source="Companies House", category="companies", status=Status.UNKNOWN, summary=code)
