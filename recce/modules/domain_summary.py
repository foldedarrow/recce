# SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain report summary helpers shared by CLI and GUI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..core.result import Hit, Report, Status


@dataclass(frozen=True)
class DomainSummaryRow:
    label: str
    value: str


def build_domain_summary(report: Report) -> list[DomainSummaryRow]:
    if report.query_type != "domain":
        return []

    return [
        DomainSummaryRow("Domain", report.query),
        DomainSummaryRow("Registered", _registered(report.hits)),
        DomainSummaryRow("Registrar", _registrar(report.hits)),
        DomainSummaryRow("Registrant", _registrant(report.hits)),
        DomainSummaryRow("Hosting", _hosting(report.hits)),
        DomainSummaryRow("Email", _email(report.hits)),
        DomainSummaryRow("Web", _web(report.hits)),
        DomainSummaryRow("Subdomains", _subdomains(report.hits)),
        DomainSummaryRow("Socials", _socials(report.hits)),
    ]


def _hit(hits: list[Hit], *, source: str | None = None, category: str | None = None) -> Hit | None:
    for hit in hits:
        if source and hit.source != source:
            continue
        if category and hit.category != category:
            continue
        if hit.status is Status.FOUND:
            return hit
    return None


def _registered(hits: list[Hit]) -> str:
    rdap = _hit(hits, source="RDAP")
    created = (rdap.extra.get("created") if rdap else None) or ""
    if not created:
        return "Unknown"
    date = created[:10]
    age = _age_text(created)
    return f"{date} ({age})" if age else date


def _age_text(value: str) -> str | None:
    try:
        created = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    days = max(0, (now - created).days)
    years, rem = divmod(days, 365)
    if years:
        return f"{years}y {rem}d old"
    return f"{days}d old"


def _registrar(hits: list[Hit]) -> str:
    rdap = _hit(hits, source="RDAP")
    registrar = (rdap.extra.get("registrar") if rdap else None) or ""
    return registrar or "Unknown"


def _registrant(hits: list[Hit]) -> str:
    rdap = _hit(hits, source="RDAP")
    org = (rdap.extra.get("org") if rdap else None) or ""
    return org or "Unknown"


def _hosting(hits: list[Hit]) -> str:
    ip_enrichment = [hit for hit in hits if hit.source == "IP enrichment" and hit.status is Status.FOUND]
    cloudflare = _has_cloudflare_signal(hits)
    if ip_enrichment:
        first = ip_enrichment[0]
        asn = first.extra.get("asn") or {}
        asn_name = (asn.get("name") or "").strip()
        asn_num = (asn.get("asn") or "").strip()
        ip = first.extra.get("ip") or ""
        label = " ".join(part for part in (asn_num, asn_name) if part).strip() or ip or "Resolved IP"
        if len(ip_enrichment) > 1:
            label += f", +{len(ip_enrichment) - 1} more"
        if cloudflare and "cloudflare" not in label.lower():
            label += " - Cloudflare signal"
        return label

    dns_a = _hit(hits, source="DNS A")
    records = dns_a.extra.get("records") if dns_a else []
    if records:
        label = ", ".join(records[:2])
        if len(records) > 2:
            label += f", +{len(records) - 2} more"
        if cloudflare:
            label += " - Cloudflare signal"
        return label
    return "Unknown"


def _has_cloudflare_signal(hits: list[Hit]) -> bool:
    for hit in hits:
        blob = " ".join(
            [
                hit.summary or "",
                str(hit.extra.get("records", "")),
                str(hit.extra.get("server", "")),
                str(hit.extra.get("technologies", "")),
            ]
        ).lower()
        if "cloudflare" in blob:
            return True
    return False


def _email(hits: list[Hit]) -> str:
    realm = _hit(hits, source="Microsoft 365 realm")
    if realm:
        namespace = realm.extra.get("namespace") or "detected"
        brand = realm.extra.get("brand") or realm.extra.get("cloud") or ""
        return f"Microsoft 365 ({namespace})" + (f" - {brand}" if brand else "")

    mx = _hit(hits, source="DNS MX")
    if mx:
        provider = mx.extra.get("provider") or ""
        records = mx.extra.get("records") or []
        if provider:
            return provider
        if records:
            return ", ".join(records[:2]) + (f", +{len(records) - 2} more" if len(records) > 2 else "")

    not_found = next((hit for hit in hits if hit.source == "DNS MX" and hit.status is Status.NOT_FOUND), None)
    return not_found.summary if not_found and not_found.summary else "Unknown"


def _web(hits: list[Hit]) -> str:
    probe = _hit(hits, source="HTTPS probe") or _hit(hits, source="HTTP probe")
    if not probe:
        return "Unknown"
    status = probe.extra.get("status_code")
    parts = [f"HTTP {status}" if status else "HTTP response"]
    tech = probe.extra.get("technologies") or []
    if tech:
        parts.append(", ".join(tech[:3]))
    title = probe.extra.get("title")
    if title:
        parts.append(str(title)[:80])
    return " - ".join(parts)


def _subdomains(hits: list[Hit]) -> str:
    passive_hit = _hit(hits, source="Passive subdomains")
    brute_hit = _hit(hits, source="Subdomain bruteforce")
    passive = _passive_subdomains(passive_hit)
    brute = set(brute_hit.extra.get("subdomains") or []) if brute_hit else set()
    total = passive | brute
    brute_only = brute - passive
    if not total:
        return "0 found"
    if brute:
        return f"{len(total)} found ({len(passive)} passive, {len(brute_only)} bruteforce-only)"
    return f"{len(total)} found (passive)"


def _passive_subdomains(hit: Hit | None) -> set[str]:
    if not hit:
        return set()
    values = hit.extra.get("subdomains") or []
    out: set[str] = set()
    for item in values:
        if isinstance(item, dict) and item.get("host"):
            out.add(str(item["host"]))
        elif isinstance(item, str):
            out.add(item)
    return out


def _socials(hits: list[Hit]) -> str:
    hit = _hit(hits, source="Linked socials")
    links = hit.extra.get("links") if hit else []
    if not links:
        return "None found"
    compact = [_compact_url(link) for link in links[:3]]
    suffix = f", +{len(links) - 3} more" if len(links) > 3 else ""
    return ", ".join(compact) + suffix


def _compact_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.netloc:
        return value
    path = parsed.path.rstrip("/")
    return f"{parsed.netloc}{path}"
