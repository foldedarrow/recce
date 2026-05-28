# SPDX-License-Identifier: AGPL-3.0-or-later
"""Company-register source adapter."""

from __future__ import annotations

import tldextract

from recce.core.result import Hit

from . import companies_house, edgar, rdap
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    org_guess = await _company_query_guess(domain, ctx)
    return [await companies_house.query(org_guess, ctx), await edgar.query(org_guess, ctx)]


async def _company_query_guess(domain: str, ctx: SourceContext) -> str:
    rdap_hit = await rdap.query(domain, ctx)
    org = rdap_hit.extra.get("org") if rdap_hit.extra else None
    if isinstance(org, str) and org.strip():
        return org.strip()
    extracted = tldextract.extract(domain)
    label = extracted.domain or domain.rsplit(".", 1)[0]
    return label.replace("-", " ")
