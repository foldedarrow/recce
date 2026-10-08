# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hunter.io provider."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class HunterProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="hunter",
            name="Hunter.io",
            tier="free",
            enriches=("email", "domain"),
            config_keys=("HUNTER_API_KEY",),
            setting_attrs=("hunter_api_key",),
            homepage="https://hunter.io/api",
            notes="email verification; domain email format (1 search credit per domain)",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type == "domain":
            return await self._domain(target, ctx)
        if target_type != "email":
            return []

        started = time.perf_counter()
        resp = await ctx.client.get(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": target, "api_key": ctx.settings.hunter_api_key},
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None or resp.status_code != 200:
            code = "?" if resp is None else resp.status_code
            return [
                Hit(
                    source=self.name,
                    category="verification",
                    status=Status.UNKNOWN,
                    summary=f"HTTP {code}",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        try:
            data: dict[str, Any] = resp.json()["data"]
        except Exception:
            return [
                Hit(
                    source=self.name,
                    category="verification",
                    status=Status.UNKNOWN,
                    summary="bad json",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        parts = [
            f"status: {data.get('status', '?')}",
            f"score: {data.get('score', '?')}",
        ]
        if data.get("disposable"):
            parts.append("disposable")
        if data.get("webmail"):
            parts.append("webmail")
        if data.get("accept_all"):
            parts.append("accept-all domain")
        sources = data.get("sources") or []
        if sources:
            parts.append(f"seen on {len(sources)} site(s)")
        return [
            Hit(
                source=self.name,
                category="verification",
                status=Status.FOUND if data.get("status") in ("valid", "accept_all", "webmail") else Status.NOT_FOUND,
                summary=" · ".join(parts),
                extra={"provider_id": self.id, "sources": sources, "raw": data},
                confidence=0.85,
                elapsed_ms=elapsed,
            )
        ]

    async def _domain(self, domain: str, ctx: ProviderContext) -> list[Hit]:
        """Email address format and organisation for a domain.

        Asks for one result: that costs one search credit and still returns
        the pattern and the total count. Individual addresses aren't listed.
        """
        started = time.perf_counter()
        resp = await ctx.client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "limit": 1, "api_key": ctx.settings.hunter_api_key},
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("email", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code == 429:
            return [self.make_hit("email", Status.SKIPPED, summary="rate limit / credits used up", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("email", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            body: dict[str, Any] = resp.json() or {}
            data: dict[str, Any] = body.get("data") or {}
        except Exception:
            return [self.make_hit("email", Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)]
        total = int(((body.get("meta") or {}).get("results")) or 0)
        pattern = data.get("pattern")
        if not pattern and not total:
            return [
                self.make_hit("email", Status.NOT_FOUND, summary="no email format known", elapsed_ms=elapsed)
            ]
        parts = []
        if pattern:
            parts.append(f"email format: {pattern}@{domain}")
        if data.get("organization"):
            parts.append(f"organisation: {data['organization']}")
        parts.append(f"{total:,} address(es) found on the web")
        if data.get("accept_all"):
            parts.append("accept-all mail server")
        if data.get("webmail"):
            parts.append("webmail domain")
        return [
            self.make_hit(
                "email",
                Status.FOUND,
                url=f"https://hunter.io/search/{domain}",
                summary=" · ".join(parts),
                confidence=0.8,
                elapsed_ms=elapsed,
                extra={
                    "pattern": pattern,
                    "organization": data.get("organization"),
                    "results": total,
                    "accept_all": data.get("accept_all"),
                    "webmail": data.get("webmail"),
                    "disposable": data.get("disposable"),
                },
            )
        ]
