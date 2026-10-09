# SPDX-License-Identifier: AGPL-3.0-or-later
"""VirusTotal provider (v3 API): domain reputation and known subdomains."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

API_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui/domain"
# The public (free) API allows 4 requests/minute and 500/day, so a domain run
# makes two calls (report + one page of subdomains) and an email run one.
SUBDOMAIN_LIMIT = 40
STALE_RANK_SECONDS = 365 * 24 * 3600
RATE_LIMIT_MESSAGE = "rate-limited by VirusTotal (free API: 4 requests/min, 500/day)"
# Consumer mailbox domains say nothing about the person; skip them to save quota.
WEBMAIL_DOMAINS = frozenset(
    {
        "aol.com", "gmail.com", "googlemail.com", "gmx.com", "gmx.de", "gmx.net", "hotmail.co.uk",
        "hotmail.com", "icloud.com", "live.co.uk", "live.com", "mail.com", "mail.ru", "me.com",
        "msn.com", "outlook.com", "pm.me", "proton.me", "protonmail.com", "qq.com", "tutanota.com",
        "yahoo.co.uk", "yahoo.com", "yandex.com", "yandex.ru", "zoho.com",
    }
)


class VirusTotalProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="virustotal",
            name="VirusTotal",
            tier="pro",
            enriches=("domain", "email"),
            config_keys=("VIRUSTOTAL_API_KEY",),
            setting_attrs=("virustotal_api_key",),
            homepage="https://docs.virustotal.com/reference/overview",
            notes="domain reputation, categories and known subdomains (free API: 4/min, 500/day)",
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type == "domain":
            domain = target.strip().lower().rstrip(".")
            report = await self._report(domain, ctx, label=None)
            # No second call when the first failed: a 429 or bad key fails both.
            if report.status is not Status.FOUND:
                return [report]
            return [report, await self._subdomains(domain, ctx)]
        if target_type == "email":
            domain = target.rpartition("@")[2].strip().lower().rstrip(".")
            if not domain:
                return []
            if domain in WEBMAIL_DOMAINS:
                return [
                    self.make_hit(
                        "reputation",
                        Status.SKIPPED,
                        summary=f"{domain} is a consumer webmail domain; not looked up",
                        confidence=0.0,
                        extra={"domain": domain},
                    )
                ]
            return [await self._report(domain, ctx, label=f"domain {domain}")]
        return []

    async def _report(self, domain: str, ctx: ProviderContext, *, label: str | None) -> Hit:
        data, failure = await self._get(
            f"{API_BASE}/domains/{domain}",
            ctx,
            category="reputation",
            not_found=f"{domain} is not in the VirusTotal dataset",
        )
        if failure:
            return failure
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        engines = sum(int(v or 0) for v in stats.values())
        flagged = _flagged_engines(attrs.get("last_analysis_results") or {})
        categories = sorted({str(v) for v in (attrs.get("categories") or {}).values() if v})
        ranks = _ranks(attrs.get("popularity_ranks") or {})
        votes = attrs.get("total_votes") or {}
        created = _iso_date(attrs.get("creation_date"))

        parts = [label] if label else []
        parts.append(f"{malicious}/{engines} engines malicious" + (f", {suspicious} suspicious" if suspicious else ""))
        if flagged:
            parts.append("flagged by: " + ", ".join(flagged[:6]) + (f" +{len(flagged) - 6}" if len(flagged) > 6 else ""))
        if attrs.get("reputation") is not None:
            parts.append(f"reputation {attrs['reputation']}")
        if votes.get("malicious"):
            parts.append(f"community votes {votes.get('harmless', 0)} harmless / {votes['malicious']} malicious")
        if categories:
            parts.append("categories: " + ", ".join(categories[:4]))
        if attrs.get("registrar"):
            parts.append(f"registrar: {attrs['registrar']}")
        if created:
            parts.append(f"created {created}")
        if ranks:
            parts.append("ranks: " + ", ".join(f"{name} #{rank}" for name, rank in list(ranks.items())[:3]))

        verdict = "malicious" if malicious else "suspicious" if suspicious else "clean"
        return self.make_hit(
            "reputation",
            Status.FOUND,
            url=f"{GUI_BASE}/{domain}",
            summary=" · ".join(parts),
            confidence=0.85,
            elapsed_ms=data.get("_elapsed_ms"),
            extra={
                "domain": domain,
                "verdict": verdict,
                "last_analysis_stats": stats,
                "flagged_engines": flagged,
                "reputation": attrs.get("reputation"),
                "total_votes": votes,
                "categories": attrs.get("categories") or {},
                "tags": attrs.get("tags") or [],
                "registrar": attrs.get("registrar"),
                "creation_date": created,
                "last_analysis_date": _iso_date(attrs.get("last_analysis_date")),
                "popularity_ranks": ranks,
                "last_dns_records": (attrs.get("last_dns_records") or [])[:50],
            },
        )

    async def _subdomains(self, domain: str, ctx: ProviderContext) -> Hit:
        data, failure = await self._get(
            f"{API_BASE}/domains/{domain}/relationships/subdomains",
            ctx,
            category="subs",
            not_found="no VirusTotal subdomains",
            params={"limit": SUBDOMAIN_LIMIT},
        )
        if failure:
            return failure
        names = [str(item["id"]).lower() for item in data.get("data") or [] if isinstance(item, dict) and item.get("id")]
        # VirusTotal lists the apex among its own subdomains.
        subdomains = [name for name in names if name != domain]
        total = int((data.get("meta") or {}).get("count") or len(names)) - (len(names) - len(subdomains))
        if not subdomains:
            return self.make_hit(
                "subs",
                Status.NOT_FOUND,
                summary="no VirusTotal subdomains",
                elapsed_ms=data.get("_elapsed_ms"),
                extra={"domain": domain},
            )
        summary = f"{total} known subdomain(s)"
        if total > len(subdomains):
            summary += f" · showing the {len(subdomains)} most recent"
        summary += " · sample: " + ", ".join(subdomains[:8])
        return self.make_hit(
            "subs",
            Status.FOUND,
            url=f"{GUI_BASE}/{domain}/relations",
            summary=summary,
            confidence=0.8,
            elapsed_ms=data.get("_elapsed_ms"),
            extra={"domain": domain, "subdomains": subdomains, "total": total},
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
            headers={"x-apikey": ctx.settings.virustotal_api_key or "", "Accept": "application/json"},
            params=params,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return {}, self._error(category, "network", elapsed)
        if resp.status_code == 401:
            return {}, self._error(category, "invalid API key", elapsed)
        if resp.status_code == 429:
            return {}, self._error(category, RATE_LIMIT_MESSAGE, elapsed)
        if resp.status_code == 404:
            return {}, self.make_hit(category, Status.NOT_FOUND, summary=not_found, elapsed_ms=elapsed)
        if resp.status_code != 200:
            code, message = _error_detail(resp)
            detail = ": ".join(part for part in (code, message) if part) or f"HTTP {resp.status_code}"
            status = Status.ERROR if resp.status_code in {400, 403} else Status.UNKNOWN
            if status is Status.ERROR:
                return {}, self._error(category, detail, elapsed)
            return {}, self.make_hit(category, status, summary=detail[:160], elapsed_ms=elapsed)
        try:
            data = resp.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            return {}, self.make_hit(category, Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)
        return {**data, "_elapsed_ms": elapsed}, None

    def _error(self, category: str, message: str, elapsed: int) -> Hit:
        return self.make_hit(category, Status.ERROR, error=message[:160], elapsed_ms=elapsed)


def _flagged_engines(results: dict[str, Any]) -> list[str]:
    flagged = []
    for name, result in sorted(results.items()):
        if isinstance(result, dict) and result.get("category") in {"malicious", "suspicious"}:
            verdict = result.get("result") or result["category"]
            flagged.append(f"{result.get('engine_name') or name} ({verdict})")
    return flagged


def _ranks(ranks: dict[str, Any]) -> dict[str, int]:
    """Current popularity ranks, best first; lists not refreshed in a year
    (Alexa closed in 2022) are dropped."""
    cutoff = time.time() - STALE_RANK_SECONDS
    out = {
        str(name): int(info["rank"])
        for name, info in ranks.items()
        if isinstance(info, dict)
        and isinstance(info.get("rank"), int)
        and (info.get("timestamp") or 0) >= cutoff
    }
    return dict(sorted(out.items(), key=lambda item: item[1]))


def _iso_date(value: Any) -> str | None:
    if not isinstance(value, int | float) or value <= 0:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).date().isoformat()


def _error_detail(resp: Any) -> tuple[str, str]:
    try:
        data = resp.json()
    except Exception:
        return "", ""
    error = data.get("error") if isinstance(data, dict) else None
    if not isinstance(error, dict):
        return "", ""
    return str(error.get("code") or ""), str(error.get("message") or "")[:120]
