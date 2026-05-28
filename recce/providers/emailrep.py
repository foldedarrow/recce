# SPDX-License-Identifier: AGPL-3.0-or-later
"""EmailRep provider."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class EmailRepProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="emailrep",
            name="EmailRep",
            tier="free",
            enriches=("email",),
            config_keys=("EMAILREP_API_KEY",),
            setting_attrs=("emailrep_api_key",),
            homepage="https://emailrep.io/",
            notes="key optional; useful for higher rate limits",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "email":
            return []

        started = time.perf_counter()
        headers = {"User-Agent": "recce-osint", "Accept": "application/json"}
        if ctx.settings.emailrep_api_key:
            headers["Key"] = ctx.settings.emailrep_api_key
        resp = await ctx.client.get(f"https://emailrep.io/{target}", headers=headers)
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [
                Hit(
                    source=self.name,
                    category="reputation",
                    status=Status.ERROR,
                    error="network",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code == 429:
            return [
                Hit(
                    source=self.name,
                    category="reputation",
                    status=Status.SKIPPED,
                    summary="rate-limited (set EMAILREP_API_KEY)",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code != 200:
            return [
                Hit(
                    source=self.name,
                    category="reputation",
                    status=Status.UNKNOWN,
                    summary=f"HTTP {resp.status_code}",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        try:
            data: dict[str, Any] = resp.json()
        except Exception:
            return [
                Hit(
                    source=self.name,
                    category="reputation",
                    status=Status.UNKNOWN,
                    summary="bad json",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]

        details = data.get("details", {})
        profiles: list[str] = details.get("profiles", []) or []
        rep = data.get("reputation", "unknown")
        suspicious = data.get("suspicious", False)
        parts = [f"reputation: {rep}"]
        if details.get("first_seen") and details["first_seen"] != "never":
            parts.append(f"first seen {details['first_seen']}")
        if details.get("data_breach"):
            parts.append("in data breaches")
        if details.get("malicious_activity"):
            parts.append("malicious activity")
        if profiles:
            parts.append(f"profiles: {', '.join(profiles)}")
        if suspicious:
            parts.append("flagged suspicious")
        return [
            Hit(
                source=self.name,
                category="reputation",
                status=Status.FOUND if (profiles or rep != "none") else Status.NOT_FOUND,
                summary=" · ".join(parts),
                extra={"provider_id": self.id, "profiles": profiles, "reputation": rep, "details": details},
                confidence=0.8,
                elapsed_ms=elapsed,
            )
        ]
