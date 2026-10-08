# SPDX-License-Identifier: AGPL-3.0-or-later
"""XposedOrNot provider — free breach analytics, no key needed."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class XposedOrNotProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="xposedornot",
            name="XposedOrNot",
            tier="free",
            enriches=("email",),
            config_keys=(),
            setting_attrs=(),
            homepage="https://xposedornot.com/api_doc",
            notes="free breach analytics; no key needed",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "email":
            return []
        started = time.perf_counter()
        resp = await ctx.client.get(
            "https://api.xposedornot.com/v1/breach-analytics", params={"email": target}
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("breach", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code == 429:
            return [self.make_hit("breach", Status.SKIPPED, summary="rate-limited", elapsed_ms=elapsed)]
        if resp.status_code == 404:
            return [self.make_hit("breach", Status.NOT_FOUND, summary="no breaches", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("breach", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            data: dict[str, Any] = resp.json() or {}
        except Exception:
            return [self.make_hit("breach", Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)]

        details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
        if not details:
            return [self.make_hit("breach", Status.NOT_FOUND, summary="no breaches", elapsed_ms=elapsed)]
        breaches = [
            {
                "name": item.get("breach"),
                "year": item.get("xposed_date"),
                "domain": item.get("domain") or None,
                "data": [part.strip() for part in str(item.get("xposed_data") or "").split(";") if part.strip()],
                "password_risk": item.get("password_risk"),
            }
            for item in details
        ]
        names = [f"{b['name']} ({b['year']})" if b["year"] else str(b["name"]) for b in breaches]
        data_types = sorted({kind for b in breaches for kind in b["data"]})
        parts = [f"{len(breaches)} breach(es): " + ", ".join(names[:8])]
        if len(names) > 8:
            parts.append(f"+{len(names) - 8} more")
        if data_types:
            parts.append("exposed: " + ", ".join(data_types[:8]))
        if any(b["password_risk"] == "plaintext" for b in breaches):
            parts.append("includes plaintext-password breach")
        pastes = (data.get("PastesSummary") or {}).get("cnt")
        if pastes:
            parts.append(f"{pastes} paste(s)")
        return [
            self.make_hit(
                "breach",
                Status.FOUND,
                url="https://xposedornot.com/",
                summary=" · ".join(parts),
                confidence=0.85,
                elapsed_ms=elapsed,
                extra={"breaches": breaches, "data_types": data_types},
            )
        ]
