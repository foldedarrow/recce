# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vonage Number Insight (Advanced) provider — live HLR lookup.

Unlike libphonenumber (which reports the carrier a number was *originally*
allocated to) and NumVerify (prefix-based), an HLR query hits the mobile
network in real time, so it reflects **number portability** (current vs
original carrier), line **reachability**, and **roaming** state.

API: https://developer.vonage.com/en/number-insight/overview
Endpoint: GET https://api.nexmo.com/ni/advanced/json
Auth: api_key + api_secret as query params. Pay-as-you-go (~EUR 0.03/lookup).
"""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

_ENDPOINT = "https://api.nexmo.com/ni/advanced/json"

# A non-committal portability verdict isn't worth showing as a fact.
_UNINFORMATIVE = {"", "unknown", None}


class VonageNumberInsightProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="vonage",
            name="Vonage Number Insight",
            tier="pro",
            enriches=("phone",),
            config_keys=("VONAGE_API_KEY", "VONAGE_API_SECRET"),
            setting_attrs=("vonage_api_key", "vonage_api_secret"),
            homepage="https://developer.vonage.com/en/number-insight/overview",
            notes="live HLR: current/original carrier, ported status, reachability, roaming",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "phone":
            return []

        started = time.perf_counter()
        resp = await ctx.client.get(
            _ENDPOINT,
            params={
                "api_key": ctx.settings.vonage_api_key,
                "api_secret": ctx.settings.vonage_api_secret,
                "number": target.lstrip("+"),
            },
        )
        elapsed = int((time.perf_counter() - started) * 1000)

        def _hit(status: Status, *, summary: str | None = None, error: str | None = None,
                 extra: dict[str, Any] | None = None, confidence: float = 0.5) -> Hit:
            return Hit(
                source=self.name,
                category="carrier",
                status=status,
                summary=summary,
                error=error,
                confidence=confidence,
                elapsed_ms=elapsed,
                extra={"provider_id": self.id, **(extra or {})},
            )

        if resp is None or resp.status_code != 200:
            code = "?" if resp is None else resp.status_code
            return [_hit(Status.UNKNOWN, summary=f"HTTP {code}")]
        try:
            data = resp.json()
        except Exception:
            return [_hit(Status.UNKNOWN, summary="bad json")]

        # Vonage returns status=0 on success; anything else is an API error.
        if str(data.get("status")) != "0":
            msg = data.get("status_message") or data.get("error_text") or f"status {data.get('status')}"
            return [_hit(Status.ERROR, error=str(msg)[:160], extra={"status": data.get("status")})]

        if data.get("valid_number") == "not_valid":
            return [_hit(Status.NOT_FOUND, summary="reported as not a valid number",
                         extra={k: data.get(k) for k in ("valid_number", "reachable")})]

        current = data.get("current_carrier") or {}
        original = data.get("original_carrier") or {}
        ported = data.get("ported")
        reachable = data.get("reachable")
        valid = data.get("valid_number")
        roaming = data.get("roaming")

        parts: list[str] = []
        if current.get("name"):
            net_type = current.get("network_type")
            parts.append(f"carrier: {current['name']}" + (f" ({net_type})" if net_type else ""))
        if ported not in _UNINFORMATIVE:
            parts.append(f"ported: {ported}")
        if original.get("name") and current.get("name") and original["name"] != current["name"]:
            parts.append(f"originally: {original['name']}")
        if reachable not in _UNINFORMATIVE:
            parts.append(f"reachable: {reachable}")
        if isinstance(roaming, dict) and roaming.get("status") not in _UNINFORMATIVE:
            parts.append(f"roaming: {roaming['status']}")
        elif isinstance(roaming, str) and roaming not in _UNINFORMATIVE:
            parts.append(f"roaming: {roaming}")
        if valid not in _UNINFORMATIVE:
            parts.append(f"valid: {valid}")

        if not parts:
            return [_hit(Status.UNKNOWN, summary="no carrier intelligence returned",
                         extra={"lookup_outcome": data.get("lookup_outcome")})]

        return [
            _hit(
                Status.FOUND,
                summary=" · ".join(parts),
                confidence=0.95,
                extra={
                    "current_carrier": current,
                    "original_carrier": original,
                    "ported": ported,
                    "reachable": reachable,
                    "roaming": roaming,
                    "valid_number": valid,
                    "country_name": data.get("country_name"),
                    "lookup_outcome": data.get("lookup_outcome"),
                },
            )
        ]
