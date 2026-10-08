# SPDX-License-Identifier: AGPL-3.0-or-later
"""Censys Platform provider (v3 API, personal access token)."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

API_BASE = "https://api.platform.censys.io/v3/global/asset"
MAX_HOSTS = 4
# The free tier allows a single in-flight request, so lookups run one at a time
# and a 429 gets one short back-off retry.
RATE_LIMIT_RETRY_DELAY = 1.5


class CensysProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="censys",
            name="Censys",
            tier="pro",
            enriches=("domain",),
            config_keys=("CENSYS_API_TOKEN",),
            setting_attrs=("censys_api_token",),
            homepage="https://docs.censys.com/reference/get-started",
            notes="host services and TLS certificate enrichment",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "domain":
            return []

        # Lazy import: recce.modules imports the provider registry.
        from recce.modules.domain_sources.common import dns_lookup

        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            records, _ = await dns_lookup(target, rtype)
            ips.extend(ip for ip in records if _is_public_ip(ip))

        headers = {"Authorization": f"Bearer {ctx.settings.censys_api_token}", "Accept": "application/json"}
        if ctx.settings.censys_org_id:
            headers["X-Organization-ID"] = ctx.settings.censys_org_id

        hits = [await self._host(ip, headers, ctx) for ip in ips[:MAX_HOSTS]]
        hits.append(await self._web_property(target, headers, ctx))
        if not ips:
            hits.insert(
                0,
                Hit(
                    source=self.name,
                    category="network",
                    status=Status.NOT_FOUND,
                    summary="no public A/AAAA records to look up",
                    extra={"provider_id": self.id, "domain": target},
                ),
            )
        return hits

    async def _host(self, ip: str, headers: dict[str, str], ctx: ProviderContext) -> Hit:
        resource, failure = await self._get(f"{API_BASE}/host/{ip}", headers, ctx)
        if failure:
            return failure
        services = resource.get("services") or []
        asys = resource.get("autonomous_system") or {}
        location = resource.get("location") or {}
        parts = [ip]
        if asys.get("asn"):
            parts.append(f"AS{asys['asn']} {asys.get('name') or ''}".strip())
        if location.get("country_code"):
            parts.append(str(location["country_code"]))
        ports = _service_labels(services)
        parts.append("services: " + ", ".join(ports[:10]) if ports else "no services observed")
        if len(ports) > 10:
            parts.append(f"+{len(ports) - 10} more")
        return Hit(
            source=self.name,
            category="network",
            status=Status.FOUND,
            summary=" · ".join(parts),
            url=f"https://platform.censys.io/hosts/{ip}",
            extra={
                "provider_id": self.id,
                "ip": ip,
                "autonomous_system": asys,
                "location": location,
                "services": ports,
            },
            confidence=0.85,
            elapsed_ms=resource.get("_elapsed_ms"),
        )

    async def _web_property(self, domain: str, headers: dict[str, str], ctx: ProviderContext) -> Hit:
        resource, failure = await self._get(f"{API_BASE}/webproperty/{domain}:443", headers, ctx)
        if failure:
            return failure
        cert = resource.get("cert") or {}
        parsed = cert.get("parsed") or {}
        if not parsed:
            return Hit(
                source=self.name,
                category="web",
                status=Status.NOT_FOUND,
                summary=f"no TLS certificate observed on {domain}:443",
                extra={"provider_id": self.id, "domain": domain},
                elapsed_ms=resource.get("_elapsed_ms"),
            )
        validity = parsed.get("validity_period") or {}
        names = cert.get("names") or []
        parts = [f"TLS {domain}:443"]
        if parsed.get("subject_dn"):
            parts.append(f"subject: {_dn_field(parsed['subject_dn'], 'CN')}")
        issuer = _dn_field(parsed.get("issuer_dn") or "", "O") or _dn_field(parsed.get("issuer_dn") or "", "CN")
        if issuer:
            parts.append(f"issuer: {issuer}")
        if validity.get("not_after"):
            parts.append(f"expires {str(validity['not_after'])[:10]}")
        if names:
            parts.append(f"{len(names)} SAN name(s)")
        return Hit(
            source=self.name,
            category="web",
            status=Status.FOUND,
            summary=" · ".join(parts),
            extra={
                "provider_id": self.id,
                "domain": domain,
                "fingerprint_sha256": cert.get("fingerprint_sha256"),
                "subject_dn": parsed.get("subject_dn"),
                "issuer_dn": parsed.get("issuer_dn"),
                "validity_period": validity,
                "names": names[:100],
            },
            confidence=0.85,
            elapsed_ms=resource.get("_elapsed_ms"),
        )

    async def _get(
        self, url: str, headers: dict[str, str], ctx: ProviderContext
    ) -> tuple[dict[str, Any], Hit | None]:
        started = time.perf_counter()
        resp = await ctx.client.get(url, headers=headers)
        if resp is not None and resp.status_code == 429:
            await asyncio.sleep(RATE_LIMIT_RETRY_DELAY)
            resp = await ctx.client.get(url, headers=headers)
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return {}, self._error("network", elapsed)
        if resp.status_code == 401:
            return {}, self._error("invalid or inactive API token", elapsed)
        if resp.status_code in {403, 422}:
            detail = _error_detail(resp)
            return {}, self._error(detail or f"HTTP {resp.status_code}", elapsed)
        if resp.status_code == 429:
            return {}, self._error("rate-limited by Censys (free tier allows one request at a time)", elapsed)
        if resp.status_code == 404:
            return {}, Hit(
                source=self.name,
                category="network",
                status=Status.NOT_FOUND,
                summary="not in Censys dataset",
                elapsed_ms=elapsed,
                extra={"provider_id": self.id, "url": url},
            )
        if resp.status_code != 200:
            return {}, Hit(
                source=self.name,
                category="network",
                status=Status.UNKNOWN,
                summary=f"HTTP {resp.status_code}",
                elapsed_ms=elapsed,
                extra={"provider_id": self.id},
            )
        try:
            resource = (resp.json().get("result") or {}).get("resource") or {}
        except Exception:
            return {}, Hit(
                source=self.name,
                category="network",
                status=Status.UNKNOWN,
                summary="bad json",
                elapsed_ms=elapsed,
                extra={"provider_id": self.id},
            )
        return {**resource, "_elapsed_ms": elapsed}, None

    def _error(self, message: str, elapsed: int) -> Hit:
        return Hit(
            source=self.name,
            category="network",
            status=Status.ERROR,
            error=message[:160],
            elapsed_ms=elapsed,
            extra={"provider_id": self.id},
        )


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _service_labels(services: list[dict[str, Any]]) -> list[str]:
    labels = []
    for service in services:
        port = service.get("port")
        if port is None:
            continue
        proto = service.get("protocol") or "UNKNOWN"
        transport = service.get("transport_protocol") or "tcp"
        label = f"{port}/{proto}" if transport == "tcp" else f"{port}/{proto} ({transport})"
        if label not in labels:
            labels.append(label)
    return labels


def _dn_field(dn: str, field: str) -> str:
    for part in dn.split(","):
        key, _, value = part.strip().partition("=")
        if key == field:
            return value
    return ""


def _error_detail(resp: Any) -> str:
    try:
        data = resp.json()
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    if isinstance(data.get("error"), dict):
        return str(data["error"].get("message") or data["error"].get("reason") or "")
    return str(data.get("detail") or data.get("title") or "")
