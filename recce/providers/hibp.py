# SPDX-License-Identifier: AGPL-3.0-or-later
"""Have I Been Pwned provider."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class HIBPProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="hibp",
            name="Have I Been Pwned",
            tier="free",
            enriches=("email",),
            config_keys=("HIBP_API_KEY",),
            setting_attrs=("hibp_api_key",),
            homepage="https://haveibeenpwned.com/API/Key",
            notes="email breach lookups",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "email":
            return []

        started = time.perf_counter()
        headers = {
            "hibp-api-key": ctx.settings.hibp_api_key or "",
            "User-Agent": "recce-osint",
        }
        resp = await ctx.client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false",
            headers=headers,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [
                Hit(
                    source=self.name,
                    category="breach",
                    status=Status.ERROR,
                    error="network",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code == 404:
            return [
                Hit(
                    source=self.name,
                    category="breach",
                    status=Status.NOT_FOUND,
                    summary="no breaches on file",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code == 401:
            return [
                Hit(
                    source=self.name,
                    category="breach",
                    status=Status.ERROR,
                    error="invalid API key",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code != 200:
            return [
                Hit(
                    source=self.name,
                    category="breach",
                    status=Status.UNKNOWN,
                    summary=f"HTTP {resp.status_code}",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        try:
            breaches: list[dict[str, Any]] = resp.json()
        except Exception:
            return [
                Hit(
                    source=self.name,
                    category="breach",
                    status=Status.UNKNOWN,
                    summary="bad json",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]

        names = [b.get("Name") or b.get("Title") for b in breaches][:8]
        summary = f"{len(breaches)} breach(es): " + ", ".join(filter(None, names))
        if len(breaches) > 8:
            summary += f", +{len(breaches) - 8} more"
        return [
            Hit(
                source=self.name,
                category="breach",
                status=Status.FOUND,
                summary=summary,
                extra={"provider_id": self.id, "breaches": breaches},
                confidence=0.99,
                elapsed_ms=elapsed,
            )
        ]
