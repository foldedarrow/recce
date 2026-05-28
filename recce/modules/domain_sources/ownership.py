# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ownership source adapter."""

from __future__ import annotations

import asyncio

from recce.core.result import Hit

from . import rdap, whois
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    return [await rdap.query(domain, ctx), await asyncio.to_thread(whois.query, domain)]
