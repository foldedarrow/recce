# SPDX-License-Identifier: AGPL-3.0-or-later
"""NumVerify provider."""

from __future__ import annotations

import time
from typing import Any

import httpx

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

_HTTPS_ENDPOINT = "https://apilayer.net/api/validate"
_HTTP_ENDPOINT = "http://apilayer.net/api/validate"


def _json(resp: httpx.Response | None) -> dict[str, Any] | None:
    if resp is None or resp.status_code != 200:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _https_restricted(data: dict[str, Any] | None) -> bool:
    """NumVerify's free plan rejects HTTPS with error 105 / https_access_restricted."""
    err = (data or {}).get("error") or {}
    return err.get("code") == 105 or err.get("type") == "https_access_restricted"


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
            notes="free tier is HTTP-only (auto-falls back) and limited",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "phone":
            return []

        started = time.perf_counter()
        params = {
            "access_key": ctx.settings.numverify_api_key,
            "number": target.lstrip("+"),
            "format": 1,
        }

        # Try HTTPS first to keep the key off the wire in cleartext; the free
        # tier rejects HTTPS (error 105), so transparently retry over HTTP.
        resp = await ctx.client.get(_HTTPS_ENDPOINT, params=params)
        data = _json(resp)
        if _https_restricted(data):
            resp = await ctx.client.get(_HTTP_ENDPOINT, params=params)
            data = _json(resp)

        elapsed = int((time.perf_counter() - started) * 1000)

        def _hit(status: Status, *, summary: str | None = None, error: str | None = None) -> Hit:
            return Hit(
                source=self.name,
                category="carrier",
                status=status,
                summary=summary,
                error=error,
                elapsed_ms=elapsed,
                extra={"provider_id": self.id},
            )

        if resp is None or resp.status_code != 200:
            code = "?" if resp is None else resp.status_code
            return [_hit(Status.UNKNOWN, summary=f"HTTP {code}")]
        if data is None:
            return [_hit(Status.UNKNOWN, summary="bad json")]
        if data.get("error"):
            err = data["error"]
            return [_hit(Status.ERROR, error=err.get("info") or err.get("type", "unknown"))]
        if not data.get("valid"):
            return [_hit(Status.NOT_FOUND, summary="reported as invalid")]

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
