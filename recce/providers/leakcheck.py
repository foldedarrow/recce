# SPDX-License-Identifier: AGPL-3.0-or-later
"""LeakCheck public API provider — breach sources for an email, no key needed.

The public endpoint returns breach *source names* and the *kinds* of data
exposed, never the leaked values themselves; recce only reports those.
"""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class LeakCheckProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="leakcheck",
            name="LeakCheck",
            tier="free",
            enriches=("email",),
            config_keys=(),
            setting_attrs=(),
            homepage="https://wiki.leakcheck.io/en/api/public",
            notes="free public API; breach sources incl. stealer logs; no key needed",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "email":
            return []
        started = time.perf_counter()
        resp = await ctx.client.get("https://leakcheck.io/api/public", params={"check": target})
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("breach", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code == 429:
            return [self.make_hit("breach", Status.SKIPPED, summary="rate-limited", elapsed_ms=elapsed)]
        try:
            data: dict[str, Any] = resp.json() or {}
        except Exception:
            return [self.make_hit("breach", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        if not data.get("success"):
            error = str(data.get("error") or "")
            if error.lower() == "not found":
                return [self.make_hit("breach", Status.NOT_FOUND, summary="no breaches", elapsed_ms=elapsed)]
            return [self.make_hit("breach", Status.UNKNOWN, summary=error or f"HTTP {resp.status_code}", elapsed_ms=elapsed)]

        sources = [
            {"name": source.get("name"), "date": source.get("date") or None}
            for source in data.get("sources") or []
            if source.get("name")
        ]
        fields = [field for field in data.get("fields") or [] if field]
        names = [f"{s['name']} ({s['date']})" if s["date"] else str(s["name"]) for s in sources]
        parts = [f"{data.get('found', len(sources))} record(s)"]
        if names:
            parts.append("sources: " + ", ".join(names[:8]))
        if fields:
            parts.append("exposed fields: " + ", ".join(fields))
        if any("stealer" in str(s["name"]).lower() for s in sources):
            parts.append("appears in infostealer logs")
        return [
            self.make_hit(
                "breach",
                Status.FOUND,
                url="https://leakcheck.io/",
                summary=" · ".join(parts),
                confidence=0.8,
                elapsed_ms=elapsed,
                extra={"records": data.get("found"), "sources": sources, "fields": fields},
            )
        ]
