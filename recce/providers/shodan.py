# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shodan provider."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

API_BASE = "https://api.shodan.io"
MAX_FALLBACK_HOSTS = 4
# Shodan's API allows roughly one request per second per key.
REQUEST_SPACING = 1.0


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
            f"{API_BASE}/dns/domain/{target}",
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
                return await self._host_fallback(target, ctx, elapsed, message)
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

    async def _host_fallback(self, target: str, ctx: ProviderContext, elapsed: int, message: str) -> list[Hit]:
        """Free plans can't use /dns/domain but can look up *some* hosts by IP."""
        # Lazy import: recce.modules imports the provider registry.
        from recce.modules.domain_sources.common import dns_lookup

        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            records, _ = await dns_lookup(target, rtype)
            ips.extend(ip for ip in records if _is_public_ip(ip))
        ips = ips[:MAX_FALLBACK_HOSTS]

        hits: list[Hit] = []
        restricted: list[str] = []
        for ip in ips:
            await asyncio.sleep(REQUEST_SPACING)
            hit = await self._host(ip, ctx)
            if hit is None:
                restricted.append(ip)
            else:
                hits.append(hit)

        summary = "key is valid, but the Shodan plan lacks DNS API access (needs a Membership or higher)"
        if ips:
            available = len(ips) - len(restricted)
            summary += f" · host lookup fallback: {available}/{len(ips)} IP(s) available on this plan"
            if restricted:
                summary += " (restricted: " + ", ".join(restricted) + ")"
        hits.insert(
            0,
            Hit(
                source=self.name,
                category="subs",
                status=Status.SKIPPED,
                summary=summary,
                confidence=0.0,
                elapsed_ms=elapsed,
                extra={"provider_id": self.id, "shodan_error": message, "restricted_ips": restricted},
            ),
        )
        return hits

    async def _host(self, ip: str, ctx: ProviderContext) -> Hit | None:
        """Host lookup; returns None when the plan doesn't cover this IP."""
        started = time.perf_counter()
        resp = await ctx.client.get(f"{API_BASE}/shodan/host/{ip}", params={"key": ctx.settings.shodan_api_key})
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return self._host_error(ip, "network", elapsed)
        if resp.status_code == 403 and "membership" in _error_message(resp).lower():
            return None
        if resp.status_code == 404:
            return Hit(
                source=self.name,
                category="network",
                status=Status.NOT_FOUND,
                summary=f"{ip} · no Shodan host data",
                elapsed_ms=elapsed,
                extra={"provider_id": self.id, "ip": ip},
            )
        if resp.status_code != 200:
            return self._host_error(ip, _error_message(resp) or f"HTTP {resp.status_code}", elapsed)
        try:
            data: dict[str, Any] = resp.json()
        except Exception:
            return self._host_error(ip, "bad json", elapsed)

        ports = sorted(int(port) for port in data.get("ports") or [])
        vulns = sorted(data.get("vulns") or [])
        hostnames = data.get("hostnames") or []
        parts = [ip]
        org = data.get("org") or data.get("isp")
        if data.get("asn") or org:
            parts.append(" ".join(str(v) for v in (data.get("asn"), org) if v))
        if data.get("country_code"):
            parts.append(str(data["country_code"]))
        parts.append("ports: " + ", ".join(str(port) for port in ports[:15]) if ports else "no open ports seen")
        if len(ports) > 15:
            parts.append(f"+{len(ports) - 15} more")
        if vulns:
            parts.append(f"{len(vulns)} CVE(s): " + ", ".join(vulns[:5]))
        if data.get("tags"):
            parts.append("tags: " + ", ".join(data["tags"][:5]))
        return Hit(
            source=self.name,
            category="network",
            status=Status.FOUND,
            url=f"https://www.shodan.io/host/{ip}",
            summary=" · ".join(parts),
            confidence=0.85,
            elapsed_ms=elapsed,
            extra={
                "provider_id": self.id,
                "ip": ip,
                "org": org,
                "asn": data.get("asn"),
                "ports": ports,
                "vulns": vulns[:100],
                "hostnames": hostnames[:50],
                "tags": data.get("tags") or [],
                "last_update": data.get("last_update"),
            },
        )

    def _host_error(self, ip: str, message: str, elapsed: int) -> Hit:
        return Hit(
            source=self.name,
            category="network",
            status=Status.ERROR,
            error=f"{ip}: {message}"[:160],
            elapsed_ms=elapsed,
            extra={"provider_id": self.id, "ip": ip},
        )


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _error_message(resp: Any) -> str:
    try:
        data = resp.json()
    except Exception:
        return ""
    if isinstance(data, dict):
        return str(data.get("error") or "")[:160]
    return ""
