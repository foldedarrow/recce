# SPDX-License-Identifier: AGPL-3.0-or-later
"""Company-register source adapter."""

from __future__ import annotations

from recce.core.result import Hit

from . import companies_house, edgar
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    org_guess = domain.rsplit(".", 1)[0].replace("-", " ")
    return [await companies_house.query(org_guess, ctx), await edgar.query(org_guess, ctx)]
