# SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain reconnaissance orchestrator."""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import tldextract

from ..config import Settings
from ..core.egress import exit_label
from ..core.http import HttpClient
from ..core.result import Hit, Report, Status
from ..providers import query_registered_providers
from .domain_sources import DOMAIN_CATEGORIES, DomainSource, SourceContext, source_registry
from .domain_sources import bruteforce as bruteforce_source

BRUTEFORCE_WORDLIST_COUNTS = bruteforce_source.BRUTEFORCE_WORDLIST_COUNTS
BRUTEFORCE_WORDLIST_FILES = bruteforce_source.BRUTEFORCE_WORDLIST_FILES
load_bruteforce_wordlist = bruteforce_source.load_bruteforce_wordlist


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
    skip_provider_ids: set[str] | None = None,
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

    report = Report(query=domain, query_type="domain", exit=exit_label(getattr(client, "proxy", None)))
    ctx = SourceContext(client=client, settings=settings, validate_subdomains=validate_subs)
    coros = [
        _run_source(category, source, domain, ctx)
        for category, source in source_registry()
        if _enabled(category, only_categories, exclude_categories)
    ]
    if coros:
        for result in await asyncio.gather(*coros):
            for hit in result:
                report.add(hit)
    if bruteforce and _enabled("subs", only_categories, exclude_categories):
        for hit in await bruteforce_source.query(
            domain,
            wordlist=bruteforce_wordlist,
            concurrency=bruteforce_concurrency,
            rate=bruteforce_rate,
        ):
            report.add(hit)
    if _enabled("subs", only_categories, exclude_categories):
        for hit in await query_registered_providers(
            domain,
            "domain",
            client,
            settings,
            skip_provider_ids=skip_provider_ids,
        ):
            report.add(hit)
    report.finish()
    return report


async def _run_source(
    category: str,
    source: DomainSource,
    domain: str,
    ctx: SourceContext,
) -> list[Hit]:
    try:
        return await source(domain, ctx)
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
