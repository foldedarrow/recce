# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecurityTrails provider: passive subdomains and historical A records."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

API_BASE = "https://api.securitytrails.com/v1"
GUI_BASE = "https://securitytrails.com/domain"
# Free keys get a small monthly quota, so a run spends two queries on what recce
# can't see itself: the subdomain list and past A records (origin IPs used
# before a CDN, old hosting). Current DNS comes from recce's own lookups.
MAX_SUBDOMAINS = 200
MAX_HISTORY = 25
RATE_LIMIT_MESSAGE = "SecurityTrails quota or rate limit reached (free keys get a small monthly quota)"


class SecurityTrailsProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="securitytrails",
            name="SecurityTrails",
            tier="pro",
            enriches=("domain",),
            config_keys=("SECURITYTRAILS_API_KEY",),
            setting_attrs=("securitytrails_api_key",),
            homepage="https://securitytrails.com/corp/api",
            notes="passive subdomains and historical A records (2 queries per domain)",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "domain":
            return []
        domain = target.strip().lower().rstrip(".")
        subs = await self._subdomains(domain, ctx)
        # A bad key or exhausted quota fails both calls; don't spend the second.
        if subs.status is Status.ERROR:
            return [subs]
        return [subs, await self._a_history(domain, ctx)]

    async def _subdomains(self, domain: str, ctx: ProviderContext) -> Hit:
        data, failure = await self._get(
            f"{API_BASE}/domain/{domain}/subdomains",
            ctx,
            category="subs",
            not_found="no SecurityTrails subdomains",
            params={"children_only": "false", "include_inactive": "true"},
        )
        if failure:
            return failure
        labels = [str(label).lower() for label in data.get("subdomains") or [] if label]
        hosts = sorted({f"{label}.{domain}" for label in labels})
        total = int(data.get("subdomain_count") or len(hosts))
        if not hosts:
            return self.make_hit(
                "subs",
                Status.NOT_FOUND,
                summary="no SecurityTrails subdomains",
                elapsed_ms=data.get("_elapsed_ms"),
                extra={"domain": domain},
            )
        limit_reached = bool((data.get("meta") or {}).get("limit_reached"))
        summary = f"{total} subdomain(s) incl. inactive"
        if limit_reached:
            summary += f" · plan shows {len(hosts)}"
        summary += " · sample: " + ", ".join(hosts[:8])
        return self.make_hit(
            "subs",
            Status.FOUND,
            url=f"{GUI_BASE}/{domain}/dns",
            summary=summary,
            confidence=0.8,
            elapsed_ms=data.get("_elapsed_ms"),
            extra={
                "domain": domain,
                "subdomains": hosts[:MAX_SUBDOMAINS],
                "total": total,
                "limit_reached": limit_reached,
            },
        )

    async def _a_history(self, domain: str, ctx: ProviderContext) -> Hit:
        data, failure = await self._get(
            f"{API_BASE}/history/{domain}/dns/a",
            ctx,
            category="network",
            not_found="no SecurityTrails A record history",
        )
        if failure:
            return failure
        periods = []
        for record in data.get("records") or []:
            if not isinstance(record, dict):
                continue
            ips = [str(v["ip"]) for v in record.get("values") or [] if isinstance(v, dict) and v.get("ip")]
            if not ips:
                continue
            periods.append(
                {
                    "ips": ips,
                    "organizations": [str(org) for org in record.get("organizations") or [] if org],
                    "first_seen": record.get("first_seen"),
                    "last_seen": record.get("last_seen"),
                }
            )
        if not periods:
            return self.make_hit(
                "network",
                Status.NOT_FOUND,
                summary="no SecurityTrails A record history",
                elapsed_ms=data.get("_elapsed_ms"),
                extra={"domain": domain},
            )
        periods.sort(key=lambda period: str(period["first_seen"] or ""), reverse=True)
        unique_ips = list(dict.fromkeys(ip for period in periods for ip in period["ips"]))
        orgs = list(dict.fromkeys(org for period in periods for org in period["organizations"]))
        earliest = min((str(p["first_seen"]) for p in periods if p["first_seen"]), default="")
        parts = [f"{len(periods)} A record period(s)", f"{len(unique_ips)} IP(s)"]
        if earliest:
            parts.append(f"since {earliest}")
        if orgs:
            parts.append("hosts: " + ", ".join(orgs[:5]) + (f" +{len(orgs) - 5}" if len(orgs) > 5 else ""))
        oldest = [p for p in periods if p["first_seen"]][-3:]
        if oldest:
            parts.append(
                "earliest: "
                + "; ".join(f"{', '.join(p['ips'][:2])} ({p['first_seen']}–{p['last_seen'] or '?'})" for p in reversed(oldest))
            )
        if int(data.get("pages") or 1) > 1:
            parts.append(f"first of {data['pages']} pages")
        return self.make_hit(
            "network",
            Status.FOUND,
            url=f"{GUI_BASE}/{domain}/history/a",
            summary=" · ".join(parts),
            confidence=0.8,
            elapsed_ms=data.get("_elapsed_ms"),
            extra={
                "domain": domain,
                "a_history": periods[:MAX_HISTORY],
                "ips": unique_ips[:100],
                "organizations": orgs,
                "pages": data.get("pages"),
            },
        )

    async def _get(
        self,
        url: str,
        ctx: ProviderContext,
        *,
        category: str,
        not_found: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], Hit | None]:
        started = time.perf_counter()
        resp = await ctx.client.get(
            url,
            headers={"APIKEY": ctx.settings.securitytrails_api_key or "", "Accept": "application/json"},
            params=params,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return {}, self._error(category, "network", elapsed)
        if resp.status_code == 429:
            return {}, self._error(category, RATE_LIMIT_MESSAGE, elapsed)
        if resp.status_code in {401, 403}:
            message = _error_message(resp)
            return {}, self._error(category, message or f"invalid key or endpoint not in plan (HTTP {resp.status_code})", elapsed)
        if resp.status_code == 404:
            return {}, self.make_hit(category, Status.NOT_FOUND, summary=not_found, elapsed_ms=elapsed)
        if resp.status_code != 200:
            message = _error_message(resp) or f"HTTP {resp.status_code}"
            return {}, self.make_hit(category, Status.UNKNOWN, summary=message, elapsed_ms=elapsed)
        try:
            data = resp.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            return {}, self.make_hit(category, Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)
        return {**data, "_elapsed_ms": elapsed}, None

    def _error(self, category: str, message: str, elapsed: int) -> Hit:
        return self.make_hit(category, Status.ERROR, error=message[:160], elapsed_ms=elapsed)


def _error_message(resp: Any) -> str:
    try:
        data = resp.json()
    except Exception:
        return ""
    if isinstance(data, dict):
        return str(data.get("message") or data.get("error") or "")[:160]
    return ""
