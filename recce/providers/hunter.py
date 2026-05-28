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
            enriches=("email",),
            config_keys=("HUNTER_API_KEY",),
            setting_attrs=("hunter_api_key",),
            homepage="https://hunter.io/api",
            notes="email verification; domain pivots planned",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
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
