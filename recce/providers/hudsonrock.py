# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hudson Rock Cavalier free OSINT API — infostealer infections tied to an
email or username.

A hit means the identifier was found in credentials stolen from a machine
running infostealer malware. recce reports when and where (date, OS,
computer name, malware path, masked IP, service counts) and deliberately
drops the partial passwords and top logins the API also returns.

For a domain, the API counts infected employees (credentials for the
domain's own services) and users (customers logging in to it), plus the
domain URLs credentials were stolen for, which often names internal login
portals. Password statistics are dropped.
"""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
# Fields never surfaced, even in `extra`: credential material.
_DROPPED = {"top_passwords", "top_logins"}
_DOMAIN_DROPPED = {"employeePasswords", "userPasswords", "logo"}


class HudsonRockProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="hudsonrock",
            name="Hudson Rock (infostealers)",
            tier="free",
            enriches=("email", "username", "domain"),
            config_keys=(),
            setting_attrs=(),
            homepage="https://www.hudsonrock.com/free-tools",
            notes="infostealer-infected machines tied to an email/username, or counts for a domain; no key needed",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type == "domain":
            return await self._domain(target, ctx)
        if target_type not in {"email", "username"}:
            return []
        endpoint, param = ("search-by-email", "email") if target_type == "email" else ("search-by-username", "username")
        started = time.perf_counter()
        resp = await ctx.client.get(f"{API}/{endpoint}", params={param: target})
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("breach", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code == 429:
            return [self.make_hit("breach", Status.SKIPPED, summary="rate-limited", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("breach", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            data: dict[str, Any] = resp.json() or {}
        except Exception:
            return [self.make_hit("breach", Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)]

        stealers = [
            {key: value for key, value in record.items() if key not in _DROPPED}
            for record in data.get("stealers") or []
            if isinstance(record, dict)
        ]
        if not stealers:
            return [
                self.make_hit(
                    "breach",
                    Status.NOT_FOUND,
                    summary="not linked to an infostealer-infected machine",
                    elapsed_ms=elapsed,
                )
            ]
        hits = []
        for record in stealers:
            parts = ["infostealer infection"]
            if record.get("date_compromised"):
                parts.append(f"compromised {str(record['date_compromised'])[:10]}")
            machine = " / ".join(str(record[k]) for k in ("computer_name", "operating_system") if record.get(k))
            if machine:
                parts.append(f"machine: {machine}")
            if record.get("malware_path"):
                parts.append(f"malware: {str(record['malware_path']).strip()}")
            if record.get("ip"):
                parts.append(f"IP {record['ip']}")
            services = record.get("total_user_services") or 0
            corporate = record.get("total_corporate_services") or 0
            parts.append(f"{services} personal + {corporate} corporate service credentials exposed")
            hits.append(
                self.make_hit(
                    "breach",
                    Status.FOUND,
                    url="https://www.hudsonrock.com/free-tools",
                    summary=" · ".join(parts),
                    confidence=0.85,
                    elapsed_ms=elapsed,
                    extra={"stealer": record},
                )
            )
        return hits

    async def _domain(self, domain: str, ctx: ProviderContext) -> list[Hit]:
        started = time.perf_counter()
        url = f"{API}/search-by-domain"
        # Some domains take Hudson Rock over a minute; say "timeout", not "network".
        detailed = getattr(ctx.client, "request_detailed", None)
        if detailed is not None:
            resp, reason = await detailed("GET", url, params={"domain": domain})
        else:
            resp, reason = await ctx.client.get(url, params={"domain": domain}), None
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("breach", Status.ERROR, error=reason or "network", elapsed_ms=elapsed)]
        if resp.status_code == 429:
            return [self.make_hit("breach", Status.SKIPPED, summary="rate-limited", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("breach", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            data: dict[str, Any] = resp.json() or {}
        except Exception:
            return [self.make_hit("breach", Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)]
        employees = int(data.get("employees") or 0)
        users = int(data.get("users") or 0)
        third = int(data.get("third_parties") or 0)
        if not (employees or users or third):
            return [
                self.make_hit(
                    "breach",
                    Status.NOT_FOUND,
                    summary="no infostealer infections tied to this domain",
                    elapsed_ms=elapsed,
                )
            ]
        urls = (data.get("data") or {}).get("employees_urls") or []
        top_urls = [
            # Query strings can carry tokens: keep scheme, host and path only.
            {"url": str(u.get("url")).split("?", 1)[0].split("#", 1)[0], "occurrence": u.get("occurrence")}
            for u in sorted(urls, key=lambda u: -(u.get("occurrence") or 0))
            if isinstance(u, dict) and u.get("url")
        ][:10]
        families = data.get("stealerFamilies") or {}
        top_families = sorted(
            ((k, v) for k, v in families.items() if isinstance(v, int) and k != "total"),
            key=lambda kv: -kv[1],
        )[:5]
        parts = [f"{employees:,} employee(s), {users:,} user(s), {third:,} third-party login(s) on infected machines"]
        if data.get("last_employee_compromised"):
            parts.append(f"last employee infection {str(data['last_employee_compromised'])[:10]}")
        if top_families:
            parts.append("malware: " + ", ".join(f"{name} ({n:,})" for name, n in top_families))
        if top_urls:
            parts.append("employee logins stolen for: " + ", ".join(u["url"] for u in top_urls[:3]))
        summary_extra = {
            k: v[:20] if isinstance(v, list) else v
            for k, v in data.items()
            if k not in _DOMAIN_DROPPED and k != "data"
        }
        return [
            self.make_hit(
                "breach",
                Status.FOUND,
                url=f"https://www.hudsonrock.com/search?domain={domain}",
                summary=" · ".join(parts),
                confidence=0.8,
                elapsed_ms=elapsed,
                extra={**summary_extra, "employee_urls": top_urls},
            )
        ]
