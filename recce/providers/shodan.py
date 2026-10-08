# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shodan provider."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class ShodanProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="shodan",
            name="Shodan",
            tier="pro",
            enriches=("domain",),
            config_keys=("SHODAN_API_KEY",),
            setting_attrs=("shodan_api_key",),
            homepage="https://developer.shodan.io/api",
            notes="DNS domain intelligence and exposed-service pivots",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "domain":
            return []

        started = time.perf_counter()
        resp = await ctx.client.get(
            f"https://api.shodan.io/dns/domain/{target}",
            params={"key": ctx.settings.shodan_api_key},
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [
                Hit(
                    source=self.name,
                    category="subs",
                    status=Status.ERROR,
                    error="network",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code == 401:
            return [
                Hit(
                    source=self.name,
                    category="subs",
                    status=Status.ERROR,
                    error="invalid API key",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code == 403:
            # Shodan answers 403 both for plan limits and for revoked access;
            # the free "oss" plan gets "Requires membership or higher to access"
            # on /dns/domain even though the key itself is valid.
            message = _error_message(resp)
            if "membership" in message.lower():
                return [
                    Hit(
                        source=self.name,
                        category="subs",
                        status=Status.SKIPPED,
                        summary="key is valid, but the Shodan plan lacks DNS API access "
                        "(needs a Membership or higher)",
                        confidence=0.0,
                        elapsed_ms=elapsed,
                        extra={"provider_id": self.id, "shodan_error": message},
                    )
                ]
            return [
                Hit(
                    source=self.name,
                    category="subs",
                    status=Status.ERROR,
                    error=f"forbidden: {message}" if message else "forbidden (HTTP 403)",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]
        if resp.status_code != 200:
            return [
                Hit(
                    source=self.name,
                    category="subs",
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
                    category="subs",
                    status=Status.UNKNOWN,
                    summary="bad json",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id},
                )
            ]

        records = data.get("data") or []
        subdomains = [sub for sub in data.get("subdomains") or [] if sub]
        if not records and not subdomains:
            return [
                Hit(
                    source=self.name,
                    category="subs",
                    status=Status.NOT_FOUND,
                    summary="no Shodan DNS domain records",
                    elapsed_ms=elapsed,
                    extra={"provider_id": self.id, "domain": target},
                )
            ]

        record_types = sorted({str(record.get("type")) for record in records if record.get("type")})
        sample_subs = ", ".join(subdomains[:8])
        parts = [
            f"{len(subdomains)} subdomain(s)",
            f"{len(records)} DNS record(s)",
        ]
        if record_types:
            parts.append("types: " + ", ".join(record_types[:8]))
        if sample_subs:
            parts.append("sample: " + sample_subs)
        if data.get("more"):
            parts.append("more results available")
        return [
            Hit(
                source=self.name,
                category="subs",
                status=Status.FOUND,
                summary=" · ".join(parts),
                extra={
                    "provider_id": self.id,
                    "domain": data.get("domain") or target,
                    "tags": data.get("tags") or [],
                    "subdomains": subdomains[:100],
                    "records": records[:100],
                    "more": bool(data.get("more")),
                },
                confidence=0.85,
                elapsed_ms=elapsed,
            )
        ]


def _error_message(resp: Any) -> str:
    try:
        data = resp.json()
    except Exception:
        return ""
    if isinstance(data, dict):
        return str(data.get("error") or "")[:160]
    return ""
