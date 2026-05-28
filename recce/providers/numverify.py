# SPDX-License-Identifier: AGPL-3.0-or-later
"""NumVerify provider."""

from __future__ import annotations

import time

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class NumVerifyProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="numverify",
            name="NumVerify",
            tier="free",
            enriches=("phone",),
            config_keys=("NUMVERIFY_API_KEY",),
            setting_attrs=("numverify_api_key",),
            homepage="https://numverify.com/",
            notes="free tier is HTTP-only and limited",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "phone":
            return []

        started = time.perf_counter()
        resp = await ctx.client.get(
            "https://apilayer.net/api/validate",
            params={
                "access_key": ctx.settings.numverify_api_key,
                "number": target.lstrip("+"),
                "format": 1,
            },
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None or resp.status_code != 200:
            code = "?" if resp is None else resp.status_code
            return [
                Hit(
                    source=self.name,
                    category="carrier",
                    status=Status.UNKNOWN,
                    summary=f"HTTP {code}",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        try:
            data = resp.json()
        except Exception:
            return [
                Hit(
                    source=self.name,
                    category="carrier",
                    status=Status.UNKNOWN,
                    summary="bad json",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if data.get("error"):
            return [
                Hit(
                    source=self.name,
                    category="carrier",
                    status=Status.ERROR,
                    error=data["error"].get("info", "unknown"),
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if not data.get("valid"):
            return [
                Hit(
                    source=self.name,
                    category="carrier",
                    status=Status.NOT_FOUND,
                    summary="reported as invalid",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        parts = []
        for key in ("country_name", "location", "carrier", "line_type"):
            if data.get(key):
                parts.append(f"{key.replace('_', ' ')}: {data[key]}")
        return [
            Hit(
                source=self.name,
                category="carrier",
                status=Status.FOUND,
                summary=" · ".join(parts),
                extra={"provider_id": self.id, **data},
                confidence=0.9,
                elapsed_ms=elapsed,
            )
        ]
