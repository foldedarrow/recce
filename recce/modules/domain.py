# SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain reconnaissance module."""

from __future__ import annotations

import asyncio
import base64
import csv
import random
import re
import socket
import ssl
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from html.parser import HTMLParser
from importlib import resources
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import tldextract

from ..config import Settings
from ..core.http import HttpClient
from ..core.result import Hit, Report, Status

DOMAIN_CATEGORIES = {"ownership", "network", "email", "web", "subs", "companies", "wayback"}
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "mail")
BRUTEFORCE_WORDLIST_FILES = {
    "small": "subdomains-1000.txt",
    "medium": "subdomains-5000.txt",
    "big": "subdomains-20000.txt",
}
BRUTEFORCE_WORDLIST_COUNTS = {"small": 1000, "medium": 5000, "big": 20000}

DomainSource = Callable[[str, HttpClient, Settings], Awaitable[list[Hit]]]


def domain_consent_error(domain: str) -> str:
    return (
        "Active subdomain bruteforce sends DNS queries from a wordlist against the target. "
        "This is recon activity that some organisations and jurisdictions treat as "
        "unauthorised access. Add --i-am-authorised to confirm you have authority to "
        f"perform this scan against {domain}. See docs/CONSENT.md for context."
    )


def normalize_domain(value: str) -> str:
    raw = value.strip().lower()
    if not raw:
        raise ValueError("domain is required")
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/", 1)[0]
    host = host.rstrip(".")
    extracted = tldextract.extract(host)
    if not extracted.domain or not extracted.suffix:
        raise ValueError(f"'{value}' does not contain a registrable domain.")
    return f"{extracted.domain}.{extracted.suffix}"


def _enabled(category: str, only: set[str] | None, exclude: set[str] | None) -> bool:
    if only and category not in only:
        return False
    return not (exclude and category in exclude)


async def search_domain(
    domain_or_url: str,
    client: HttpClient,
    settings: Settings,
    *,
    only_categories: set[str] | None = None,
    exclude_categories: set[str] | None = None,
    bruteforce: bool = False,
    authorised: bool = False,
    bruteforce_wordlist: str = "medium",
    bruteforce_concurrency: int = 25,
    bruteforce_rate: int = 10,
    validate_subs: bool = True,
) -> Report:
    domain = normalize_domain(domain_or_url)
    unknown_only = (only_categories or set()) - DOMAIN_CATEGORIES
    unknown_exclude = (exclude_categories or set()) - DOMAIN_CATEGORIES
    if unknown_only or unknown_exclude:
        unknown = ", ".join(sorted(unknown_only | unknown_exclude))
        raise ValueError(f"unknown domain categories: {unknown}")
    if bruteforce and not authorised:
        raise ValueError(domain_consent_error(domain))
    if bruteforce_wordlist not in BRUTEFORCE_WORDLIST_FILES:
        raise ValueError("bruteforce wordlist must be one of: small, medium, big")

    report = Report(query=domain, query_type="domain")
    sources: list[tuple[str, DomainSource]] = [
        ("ownership", _ownership_hits),
        ("network", _network_hits),
        ("email", _email_infra_hits),
        ("web", _web_hits),
        ("subs", lambda d, c, s: _passive_subdomain_hits(d, c, s, validate=validate_subs)),
        ("companies", _company_hits),
        ("wayback", _wayback_hits),
    ]
    coros = [
        _run_source(category, source, domain, client, settings)
        for category, source in sources
        if _enabled(category, only_categories, exclude_categories)
    ]
    if coros:
        for result in await asyncio.gather(*coros):
            for hit in result:
                report.add(hit)
    if bruteforce and _enabled("subs", only_categories, exclude_categories):
        for hit in await _bruteforce_hits(
            domain,
            wordlist=bruteforce_wordlist,
            concurrency=bruteforce_concurrency,
            rate=bruteforce_rate,
        ):
            report.add(hit)
    report.finish()
    return report


async def _run_source(
    category: str,
    source: DomainSource,
    domain: str,
    client: HttpClient,
    settings: Settings,
) -> list[Hit]:
    try:
        return await source(domain, client, settings)
    except Exception as e:
        return [
            Hit(
                source=category,
                category=category,
                status=Status.ERROR,
                error=str(e)[:160],
                confidence=0.2,
            )
        ]


async def _ownership_hits(domain: str, client: HttpClient, settings: Settings) -> list[Hit]:
    del settings
    hits: list[Hit] = []
    started = time.perf_counter()
    rdap = await client.get(f"https://rdap.org/domain/{domain}")
    elapsed = int((time.perf_counter() - started) * 1000)
    if rdap is None:
        hits.append(Hit(source="RDAP", category="ownership", status=Status.ERROR, error="network"))
    elif rdap.status_code == 404:
        hits.append(Hit(source="RDAP", category="ownership", status=Status.NOT_FOUND, summary="No RDAP record"))
    elif rdap.status_code >= 400:
        hits.append(Hit(source="RDAP", category="ownership", status=Status.UNKNOWN, summary=f"HTTP {rdap.status_code}"))
    else:
        data = _safe_json(rdap)
        created = _rdap_event(data, "registration")
        expires = _rdap_event(data, "expiration")
        updated = _rdap_event(data, "last changed")
        registrar = _rdap_registrar(data)
        org = _rdap_org(data)
        parts = []
        if registrar:
            parts.append(f"registrar: {registrar}")
        if created:
            parts.append(f"created: {created[:10]}")
            age = _domain_age_days(created)
            if age is not None:
                parts.append(f"age: {age // 365}y {age % 365}d")
        if expires:
            parts.append(f"expires: {expires[:10]}")
        if org:
            parts.append(f"org: {org}")
        status = Status.FOUND if parts else Status.UNKNOWN
        hits.append(
            Hit(
                source="RDAP",
                category="ownership",
                status=status,
                url=f"https://rdap.org/domain/{domain}",
                summary=" · ".join(parts) if parts else "RDAP record returned",
                extra={"created": created, "expires": expires, "updated": updated, "registrar": registrar, "org": org},
                confidence=0.9,
                elapsed_ms=elapsed,
            )
        )
    whois_text = await asyncio.to_thread(_whois_lookup, domain)
    if whois_text:
        hits.append(
            Hit(
                source="Whois",
                category="ownership",
                status=Status.FOUND,
                summary=_summarise_whois(whois_text),
                extra={"sample": whois_text[:3000]},
                confidence=0.65,
            )
        )
    else:
        hits.append(Hit(source="Whois", category="ownership", status=Status.UNKNOWN, summary="No whois response"))
    return hits


async def _network_hits(domain: str, client: HttpClient, settings: Settings) -> list[Hit]:
    del client, settings
    hits: list[Hit] = []
    for rtype in ("A", "AAAA", "NS", "SOA", "TXT", "CNAME"):
        started = time.perf_counter()
        records, error = await _dns_lookup(domain, rtype)
        elapsed = int((time.perf_counter() - started) * 1000)
        if records:
            hits.append(
                Hit(
                    source=f"DNS {rtype}",
                    category="network",
                    status=Status.FOUND,
                    summary=", ".join(records[:6]) + (f", +{len(records) - 6} more" if len(records) > 6 else ""),
                    extra={"records": records},
                    confidence=0.9,
                    elapsed_ms=elapsed,
                )
            )
        else:
            status = Status.NOT_FOUND if error in {"NXDOMAIN", "NoAnswer"} else Status.ERROR
            hits.append(Hit(source=f"DNS {rtype}", category="network", status=status, summary=error, elapsed_ms=elapsed))
    ips = []
    for rtype in ("A", "AAAA"):
        records, _ = await _dns_lookup(domain, rtype)
        ips.extend(records)
    for ip in ips[:8]:
        ptr_records, _ = await _dns_lookup(ip, "PTR")
        asn = await asyncio.to_thread(_cymru_lookup, ip)
        parts = []
        if ptr_records:
            parts.append(f"PTR: {ptr_records[0]}")
        if asn:
            parts.append(f"ASN: {asn.get('asn')} {asn.get('name')}")
        if parts:
            hits.append(
                Hit(
                    source="IP enrichment",
                    category="network",
                    status=Status.FOUND,
                    summary=f"{ip} · " + " · ".join(parts),
                    extra={"ip": ip, "ptr": ptr_records, "asn": asn},
                    confidence=0.75,
                )
            )
    return hits


async def _email_infra_hits(domain: str, client: HttpClient, settings: Settings) -> list[Hit]:
    del settings
    hits: list[Hit] = []
    mx_records, mx_error = await _dns_lookup(domain, "MX")
    has_null_mx = any(re.fullmatch(r"0\s*\.?", record.strip()) for record in mx_records)
    if mx_records and not has_null_mx:
        provider = _classify_mx(mx_records)
        hits.append(
            Hit(
                source="DNS MX",
                category="email",
                status=Status.FOUND,
                summary=f"{provider or 'unknown provider'} · " + ", ".join(mx_records[:4]),
                extra={"records": mx_records, "provider": provider},
                confidence=0.9,
            )
        )
    else:
        summary = "Null MX: domain does not accept email" if has_null_mx else mx_error
        hits.append(Hit(source="DNS MX", category="email", status=Status.NOT_FOUND, summary=summary))
    txt_records, _ = await _dns_lookup(domain, "TXT")
    spf = [r for r in txt_records if r.lower().startswith("v=spf1")]
    if spf:
        includes = sorted(set(re.findall(r"\binclude:([^\s]+)", " ".join(spf), flags=re.I)))
        hits.append(
            Hit(
                source="SPF",
                category="email",
                status=Status.FOUND,
                summary=("SPF present" + (f" · includes: {', '.join(includes[:6])}" if includes else "")),
                extra={"records": spf, "includes": includes},
                confidence=0.85,
            )
        )
    else:
        hits.append(Hit(source="SPF", category="email", status=Status.NOT_FOUND, summary="No SPF TXT record"))
    dmarc_records, _ = await _dns_lookup(f"_dmarc.{domain}", "TXT")
    dmarc = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
    if dmarc:
        policy = _txt_tag(dmarc[0], "p") or "unknown"
        hits.append(
            Hit(
                source="DMARC",
                category="email",
                status=Status.FOUND,
                summary=f"policy: {policy}",
                extra={"record": dmarc[0], "policy": policy},
                confidence=0.85,
            )
        )
    else:
        hits.append(Hit(source="DMARC", category="email", status=Status.NOT_FOUND, summary="No DMARC policy"))
    selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        records, _ = await _dns_lookup(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            selectors.append(selector)
    hits.append(
        Hit(
            source="DKIM selectors",
            category="email",
            status=Status.FOUND if selectors else Status.NOT_FOUND,
            summary=", ".join(selectors) if selectors else "No common DKIM selectors resolved",
            extra={"selectors": selectors},
            confidence=0.7,
        )
    )
    autodiscover, _ = await _dns_lookup(f"autodiscover.{domain}", "CNAME")
    if autodiscover:
        hits.append(
            Hit(
                source="Autodiscover",
                category="email",
                status=Status.FOUND,
                summary=", ".join(autodiscover),
                extra={"records": autodiscover},
                confidence=0.75,
            )
        )
    realm = await _m365_realm(domain, client)
    hits.append(realm)
    return hits


async def _m365_realm(domain: str, client: HttpClient) -> Hit:
    url = "https://login.microsoftonline.com/getuserrealm.srf"
    started = time.perf_counter()
    resp = await client.get(url, params={"login": f"anyuser@{domain}", "xml": "1"})
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return Hit(source="Microsoft 365 realm", category="email", status=Status.ERROR, error="network", elapsed_ms=elapsed)
    if resp.status_code >= 400:
        return Hit(source="Microsoft 365 realm", category="email", status=Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)
    text = resp.text
    namespace = _xml_tag(text, "NameSpaceType")
    brand = _xml_tag(text, "FederationBrandName")
    cloud = _xml_tag(text, "CloudInstanceName")
    sts = _xml_tag(text, "STSAuthURL")
    if namespace in {"Managed", "Federated"}:
        summary = f"{namespace}"
        if brand:
            summary += f" · {brand}"
        if cloud:
            summary += f" · {cloud}"
        if sts:
            summary += f" · STS {sts}"
        return Hit(
            source="Microsoft 365 realm",
            category="email",
            status=Status.FOUND,
            url=url,
            summary=summary,
            extra={"namespace": namespace, "brand": brand, "cloud": cloud, "sts": sts, "raw": text[:2000]},
            confidence=0.85,
            elapsed_ms=elapsed,
        )
    return Hit(
        source="Microsoft 365 realm",
        category="email",
        status=Status.NOT_FOUND,
        url=url,
        summary=f"No M365 tenant detected ({namespace or 'unknown'})",
        extra={"namespace": namespace, "raw": text[:2000]},
        elapsed_ms=elapsed,
    )


async def _web_hits(domain: str, client: HttpClient, settings: Settings) -> list[Hit]:
    del settings
    hits: list[Hit] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        started = time.perf_counter()
        resp = await client.get(url)
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            hits.append(Hit(source=f"{scheme.upper()} probe", category="web", status=Status.ERROR, url=url, error="network", elapsed_ms=elapsed))
            continue
        title, meta, canonical, socials, technologies = _parse_html(resp.text, resp.headers)
        parts = [f"HTTP {resp.status_code}", f"final: {resp.url}"]
        if title:
            parts.append(f"title: {title}")
        if technologies:
            parts.append("tech: " + ", ".join(technologies[:6]))
        hits.append(
            Hit(
                source=f"{scheme.upper()} probe",
                category="web",
                status=Status.FOUND if resp.status_code < 500 else Status.UNKNOWN,
                url=str(resp.url),
                summary=" · ".join(parts),
                extra={
                    "status_code": resp.status_code,
                    "server": resp.headers.get("server"),
                    "title": title,
                    "meta_description": meta,
                    "canonical": canonical,
                    "technologies": technologies,
                    "socials": socials,
                },
                confidence=0.85,
                elapsed_ms=elapsed,
            )
        )
        if socials:
            hits.append(
                Hit(
                    source="Linked socials",
                    category="web",
                    status=Status.FOUND,
                    summary=", ".join(socials[:8]),
                    extra={"links": socials},
                    confidence=0.7,
                )
            )
    cert = await asyncio.to_thread(_tls_certificate, domain)
    if cert:
        hits.append(
            Hit(
                source="TLS certificate",
                category="web",
                status=Status.FOUND,
                summary=cert["summary"],
                extra=cert,
                confidence=0.85,
            )
        )
    for path in ("robots.txt", "sitemap.xml"):
        url = f"https://{domain}/{path}"
        resp = await client.get(url)
        if resp is not None and resp.status_code == 200:
            summary = _summarise_declared_file(path, resp.text)
            hits.append(
                Hit(
                    source=path,
                    category="web",
                    status=Status.FOUND,
                    url=url,
                    summary=summary,
                    extra={"sample": resp.text[:3000]},
                    confidence=0.7,
                )
            )
        else:
            code = "network" if resp is None else f"HTTP {resp.status_code}"
            hits.append(Hit(source=path, category="web", status=Status.NOT_FOUND, url=url, summary=code))
    return hits


async def _passive_subdomain_hits(
    domain: str,
    client: HttpClient,
    settings: Settings,
    *,
    validate: bool,
) -> list[Hit]:
    del settings
    sources = await asyncio.gather(
        _crtsh_subdomains(domain, client),
        _hackertarget_subdomains(domain, client),
        _otx_subdomains(domain, client),
        _wayback_subdomains(domain, client),
    )
    found: dict[str, set[str]] = {}
    source_errors: list[str] = []
    for source_name, subs, error in sources:
        if error:
            source_errors.append(f"{source_name}: {error}")
        for sub in subs:
            found.setdefault(sub, set()).add(source_name)
    live: list[str] = []
    unresolved: list[str] = []
    if validate:
        for sub in sorted(found):
            records, _ = await _dns_lookup(sub, "A")
            records6, _ = await _dns_lookup(sub, "AAAA")
            if records or records6:
                live.append(sub)
            else:
                unresolved.append(sub)
    else:
        live = sorted(found)
    summary = f"{len(found)} passive subdomain(s)"
    if validate:
        summary += f" · {len(live)} resolving · {len(unresolved)} historical/unresolved"
    if source_errors:
        summary += f" · source issues: {len(source_errors)}"
    return [
        Hit(
            source="Passive subdomains",
            category="subs",
            status=Status.FOUND if found else Status.NOT_FOUND,
            summary=summary,
            extra={
                "subdomains": [
                    {"host": sub, "sources": sorted(found[sub]), "resolves": sub in live}
                    for sub in sorted(found)
                ],
                "source_errors": source_errors,
            },
            confidence=0.8,
        )
    ]


async def _bruteforce_hits(
    domain: str,
    *,
    wordlist: str,
    concurrency: int,
    rate: int,
) -> list[Hit]:
    labels = load_bruteforce_wordlist(wordlist)
    wildcard_label = f"{random.randrange(10**10, 10**11)}-recce-check"
    wildcard_records, _ = await _dns_lookup(f"{wildcard_label}.{domain}", "A")
    if wildcard_records:
        return [
            Hit(
                source="Subdomain bruteforce",
                category="subs",
                status=Status.UNKNOWN,
                summary="Wildcard DNS detected; bruteforce results would be noisy.",
                extra={"wildcard_records": wildcard_records},
                confidence=0.4,
            )
        ]
    sem = asyncio.Semaphore(max(1, concurrency))
    delay = 1 / max(1, rate)
    hits: list[str] = []

    async def check(idx: int, label: str) -> None:
        await asyncio.sleep(idx * delay / max(1, concurrency))
        async with sem:
            host = f"{label}.{domain}"
            records, _ = await _dns_lookup(host, "A")
            records6, _ = await _dns_lookup(host, "AAAA")
            if records or records6:
                hits.append(host)

    await asyncio.gather(*(check(idx, label) for idx, label in enumerate(labels)))
    return [
        Hit(
            source="Subdomain bruteforce",
            category="subs",
            status=Status.FOUND if hits else Status.NOT_FOUND,
            summary=f"{len(hits)} resolving subdomain(s) from {wordlist} wordlist ({len(labels)} labels checked)",
            extra={"subdomains": sorted(hits), "wordlist": wordlist, "labels_checked": len(labels)},
            confidence=0.75,
        )
    ]


@lru_cache(maxsize=3)
def load_bruteforce_wordlist(name: str) -> tuple[str, ...]:
    if name not in BRUTEFORCE_WORDLIST_FILES:
        raise ValueError("bruteforce wordlist must be one of: small, medium, big")
    raw = (
        resources.files("recce.data")
        .joinpath("wordlists")
        .joinpath(BRUTEFORCE_WORDLIST_FILES[name])
        .read_text()
    )
    labels = tuple(
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    expected = BRUTEFORCE_WORDLIST_COUNTS[name]
    if len(labels) != expected:
        raise RuntimeError(f"{name} wordlist has {len(labels)} entries; expected {expected}")
    return labels


async def _company_hits(domain: str, client: HttpClient, settings: Settings) -> list[Hit]:
    org_guess = domain.rsplit(".", 1)[0].replace("-", " ")
    hits: list[Hit] = []
    if settings.companies_house_key:
        auth = base64.b64encode(f"{settings.companies_house_key}:".encode()).decode()
        resp = await client.get(
            "https://api.company-information.service.gov.uk/search/companies",
            params={"q": org_guess, "items_per_page": 5},
            headers={"Authorization": f"Basic {auth}"},
        )
        if resp is not None and resp.status_code == 200:
            data = _safe_json(resp)
            items = data.get("items") or []
            if items:
                top = items[0]
                hits.append(
                    Hit(
                        source="Companies House",
                        category="companies",
                        status=Status.FOUND,
                        url=top.get("links", {}).get("self"),
                        summary=f"{top.get('title')} · {top.get('company_status')} · {top.get('company_number')}",
                        extra={"items": items[:5]},
                        confidence=0.55,
                    )
                )
            else:
                hits.append(Hit(source="Companies House", category="companies", status=Status.NOT_FOUND, summary=f"No obvious match for '{org_guess}'"))
        else:
            code = "network" if resp is None else f"HTTP {resp.status_code}"
            hits.append(Hit(source="Companies House", category="companies", status=Status.UNKNOWN, summary=code))
    else:
        hits.append(
            Hit(
                source="Companies House",
                category="companies",
                status=Status.SKIPPED,
                summary="set COMPANIES_HOUSE_KEY to enable UK company lookup",
            )
        )
    resp = await client.get(
        "https://www.sec.gov/cgi-bin/browse-edgar",
        params={"action": "getcompany", "company": org_guess, "owner": "include", "count": "10"},
        headers={"User-Agent": settings.user_agent},
    )
    if resp is not None and resp.status_code == 200 and "CIK" in resp.text:
        hits.append(
            Hit(
                source="SEC EDGAR",
                category="companies",
                status=Status.FOUND,
                url=str(resp.url),
                summary=f"Possible EDGAR match for '{org_guess}'",
                confidence=0.45,
            )
        )
    else:
        hits.append(Hit(source="SEC EDGAR", category="companies", status=Status.NOT_FOUND, summary=f"No obvious match for '{org_guess}'"))
    return hits


async def _wayback_hits(domain: str, client: HttpClient, settings: Settings) -> list[Hit]:
    del settings
    url = "https://web.archive.org/cdx/search/cdx"
    resp = await client.get(url, params={"url": domain, "output": "json", "limit": "1", "fl": "timestamp,original"})
    if resp is None:
        return [Hit(source="Wayback first seen", category="wayback", status=Status.ERROR, error="network")]
    if resp.status_code != 200:
        return [Hit(source="Wayback first seen", category="wayback", status=Status.UNKNOWN, summary=f"HTTP {resp.status_code}")]
    data = _safe_json(resp, default=[])
    if len(data) < 2:
        return [Hit(source="Wayback first seen", category="wayback", status=Status.NOT_FOUND, summary="No archived snapshot")]
    ts = data[1][0]
    date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    original = data[1][1] if len(data[1]) > 1 else domain
    return [
        Hit(
            source="Wayback first seen",
            category="wayback",
            status=Status.FOUND,
            url=f"https://web.archive.org/web/{ts}/{original}",
            summary=date,
            extra={"timestamp": ts, "original": original},
            confidence=0.7,
        )
    ]


async def _crtsh_subdomains(domain: str, client: HttpClient) -> tuple[str, set[str], str | None]:
    resp = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    if resp is None:
        return "crt.sh", set(), "network"
    if resp.status_code != 200:
        return "crt.sh", set(), f"HTTP {resp.status_code}"
    data = _safe_json(resp, default=[])
    subs: set[str] = set()
    if isinstance(data, list):
        for item in data:
            for key in ("common_name", "name_value"):
                for raw in str(item.get(key, "")).splitlines():
                    host = _normalise_subdomain(raw, domain)
                    if host:
                        subs.add(host)
    return "crt.sh", subs, None


async def _hackertarget_subdomains(domain: str, client: HttpClient) -> tuple[str, set[str], str | None]:
    resp = await client.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    if resp is None:
        return "HackerTarget", set(), "network"
    if resp.status_code != 200:
        return "HackerTarget", set(), f"HTTP {resp.status_code}"
    subs = set()
    for row in csv.reader(resp.text.splitlines()):
        if row:
            host = _normalise_subdomain(row[0], domain)
            if host:
                subs.add(host)
    return "HackerTarget", subs, None


async def _otx_subdomains(domain: str, client: HttpClient) -> tuple[str, set[str], str | None]:
    resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if resp is None:
        return "AlienVault OTX", set(), "network"
    if resp.status_code != 200:
        return "AlienVault OTX", set(), f"HTTP {resp.status_code}"
    data = _safe_json(resp)
    subs = set()
    for item in data.get("passive_dns") or []:
        host = _normalise_subdomain(item.get("hostname", ""), domain)
        if host:
            subs.add(host)
    return "AlienVault OTX", subs, None


async def _wayback_subdomains(domain: str, client: HttpClient) -> tuple[str, set[str], str | None]:
    resp = await client.get(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": f"*.{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey"},
    )
    if resp is None:
        return "Wayback CDX", set(), "network"
    if resp.status_code != 200:
        return "Wayback CDX", set(), f"HTTP {resp.status_code}"
    data = _safe_json(resp, default=[])
    subs = set()
    for row in data[1:] if isinstance(data, list) else []:
        value = row[0] if isinstance(row, list) and row else ""
        host = _normalise_subdomain(urlparse(value).hostname or value, domain)
        if host:
            subs.add(host)
    return "Wayback CDX", subs, None


async def _dns_lookup(name: str, rtype: str) -> tuple[list[str], str | None]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 4
    try:
        answers = await resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NoAnswer"
    except dns.resolver.NoNameservers:
        return [], "NoNameservers"
    except dns.exception.DNSException as e:
        return [], str(e)[:120]
    records = []
    for answer in answers:
        if rtype == "MX":
            exchange = str(answer.exchange).rstrip(".") or "."
            records.append(f"{answer.preference} {exchange}")
        elif rtype == "TXT":
            records.append("".join(part.decode(errors="replace") for part in answer.strings))
        else:
            records.append(str(answer).rstrip("."))
    return sorted(set(records)), None


def _whois_lookup(domain: str) -> str:
    tld = domain.rsplit(".", 1)[-1]
    server = _whois_query("whois.iana.org", tld)
    match = re.search(r"whois:\s*(\S+)", server, flags=re.I)
    whois_server = match.group(1) if match else "whois.iana.org"
    return _whois_query(whois_server, domain)


def _whois_query(server: str, query: str) -> str:
    try:
        with socket.create_connection((server, 43), timeout=6) as sock:
            sock.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode(errors="replace")
    except OSError:
        return ""


def _cymru_lookup(ip: str) -> dict[str, str] | None:
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=5) as sock:
            sock.sendall((f" -v {ip}\n").encode())
            text = sock.recv(4096).decode(errors="replace")
    except OSError:
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2 or "|" not in lines[1]:
        return None
    parts = [part.strip() for part in lines[1].split("|")]
    if len(parts) < 7:
        return None
    return {"asn": parts[0], "prefix": parts[2], "cc": parts[3], "registry": parts[4], "allocated": parts[5], "name": parts[6]}


def _tls_certificate(domain: str) -> dict[str, Any] | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as sock:
                cert = sock.getpeercert()
    except OSError:
        return None
    subject = ", ".join("=".join(item) for part in cert.get("subject", []) for item in part)
    issuer = ", ".join("=".join(item) for part in cert.get("issuer", []) for item in part)
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    not_after = cert.get("notAfter")
    summary = f"issuer: {issuer or '-'}"
    if not_after:
        summary += f" · expires: {_cert_date(not_after)}"
    if sans:
        summary += f" · {len(sans)} SAN(s)"
    return {"subject": subject, "issuer": issuer, "not_after": not_after, "sans": sans[:200], "summary": summary}


def _parse_html(html: str, headers: Any) -> tuple[str | None, str | None, str | None, list[str], list[str]]:
    parser = _HomepageParser()
    try:
        parser.feed(html[:500_000])
    except Exception:
        pass
    technologies = _detect_technologies(html, headers, parser.meta)
    return parser.title, parser.meta.get("description"), parser.canonical, sorted(parser.socials), technologies


class _HomepageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title: str | None = None
        self.meta: dict[str, str] = {}
        self.canonical: str | None = None
        self.socials: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            name = (attr.get("name") or attr.get("property") or "").lower()
            content = attr.get("content") or ""
            if name and content:
                self.meta[name] = content[:300]
        if tag == "link" and attr.get("rel", "").lower() == "canonical":
            self.canonical = attr.get("href") or None
        if tag == "a" and attr.get("href"):
            link = attr["href"]
            if re.search(r"(linkedin\.com/company/|twitter\.com/|x\.com/|facebook\.com/|instagram\.com/|youtube\.com/|github\.com/)", link, re.I):
                self.socials.add(link.split("?", 1)[0].rstrip("/"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            self.title = " ".join(data.split())[:160]


def _detect_technologies(html: str, headers: Any, meta: dict[str, str]) -> list[str]:
    text = html[:200_000].lower()
    header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    generator = (meta.get("generator") or "").lower()
    checks = [
        ("WordPress", "wp-content" in text or "wordpress" in generator),
        ("Drupal", "drupal" in generator or "/sites/default/" in text),
        ("Shopify", "cdn.shopify.com" in text or "shopify" in header_text),
        ("Wix", "wixstatic.com" in text),
        ("Squarespace", "squarespace" in text),
        ("Webflow", "webflow" in text),
        ("HubSpot", "hs-scripts.com" in text or "hubspot" in text),
        ("Cloudflare", "cloudflare" in header_text),
        ("AWS CloudFront", "cloudfront" in header_text),
        ("Fastly", "fastly" in header_text),
        ("Google Analytics", "google-analytics.com" in text or "gtag/js" in text),
        ("Google Tag Manager", "googletagmanager.com" in text),
        ("React", "react" in text),
        ("Next.js", "__next" in text),
        ("Vue", "vue" in text),
    ]
    return [name for name, ok in checks if ok]


def _summarise_declared_file(path: str, text: str) -> str:
    if path == "robots.txt":
        disallow = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.lower().startswith("disallow:")]
        return f"{len(disallow)} disallow rule(s)" + (f" · {', '.join(disallow[:5])}" if disallow else "")
    urls = re.findall(r"<loc>(.*?)</loc>", text, flags=re.I)
    return f"{len(urls)} sitemap URL(s)" + (f" · {', '.join(urls[:3])}" if urls else "")


def _normalise_subdomain(value: str, domain: str) -> str | None:
    host = value.strip().lower().lstrip("*.").rstrip(".")
    if not host or host == domain or not host.endswith(f".{domain}"):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    return host


def _safe_json(resp: Any, default: Any | None = None) -> Any:
    try:
        return resp.json()
    except Exception:
        return {} if default is None else default


def _rdap_event(data: dict[str, Any], action: str) -> str | None:
    for event in data.get("events") or []:
        if str(event.get("eventAction", "")).lower() == action:
            return event.get("eventDate")
    return None


def _rdap_registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        roles = {str(role).lower() for role in entity.get("roles") or []}
        if "registrar" in roles:
            return _vcard_name(entity)
    return None


def _rdap_org(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        roles = {str(role).lower() for role in entity.get("roles") or []}
        if roles & {"registrant", "administrative", "technical"}:
            name = _vcard_name(entity)
            if name and "redacted" not in name.lower():
                return name
    return None


def _vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray") or [None, []]
    entries = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
    for item in entries:
        if item and item[0] in {"fn", "org"} and len(item) > 3:
            value = item[3]
            if isinstance(value, list):
                return " ".join(str(v) for v in value if v)
            return str(value)
    return entity.get("handle")


def _domain_age_days(created: str) -> int | None:
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def _summarise_whois(text: str) -> str:
    fields = []
    for label in ("Registrar", "Creation Date", "Registry Expiry Date", "Updated Date", "Registrant Organization", "Registrant Country"):
        match = re.search(rf"^{re.escape(label)}:\s*(.+)$", text, flags=re.I | re.M)
        if match:
            fields.append(f"{label}: {match.group(1).strip()}")
    return " · ".join(fields[:5]) if fields else "Whois response returned"


def _classify_mx(records: list[str]) -> str | None:
    joined = " ".join(records).lower()
    table = [
        ("mail.protection.outlook.com", "Microsoft 365"),
        ("outlook.com", "Microsoft 365 / Outlook"),
        ("aspmx.l.google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("protection.proofpoint.com", "Proofpoint"),
        ("pphosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("zoho", "Zoho"),
        ("protonmail", "Proton Mail"),
        ("fastmail", "Fastmail"),
        ("amazonses", "Amazon SES"),
        ("sendgrid", "SendGrid"),
        ("mailgun", "Mailgun"),
    ]
    for needle, label in table:
        if needle in joined:
            return label
    return None


def _txt_tag(record: str, tag: str) -> str | None:
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}=([^;]+)", record, flags=re.I)
    return match.group(1).strip() if match else None


def _xml_tag(text: str, tag: str) -> str | None:
    match = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, flags=re.I | re.S)
    return match.group(1).strip() if match else None


def _cert_date(value: str) -> str:
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError):
        return value
