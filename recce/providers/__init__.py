# SPDX-License-Identifier: AGPL-3.0-or-later
"""Optional API provider registry."""

from __future__ import annotations

import asyncio

from recce.config import Settings
from recce.core.http import HttpClient
from recce.core.result import Hit, Status

from .base import Provider, ProviderContext, ProviderStatus, append_provider_gate_hits
from .censys import CensysProvider
from .emailrep import EmailRepProvider
from .github_commits import GitHubCommitsProvider
from .github_identity import GitHubIdentityProvider
from .hibp import HIBPProvider
from .hudsonrock import HudsonRockProvider
from .hunter import HunterProvider
from .leakcheck import LeakCheckProvider
from .numverify import NumVerifyProvider
from .profiles import PROFILE_PROVIDERS
from .proton import ProtonKeyProvider
from .shodan import ShodanProvider
from .virustotal import VirusTotalProvider
from .vonage import VonageNumberInsightProvider
from .wayback_profiles import WaybackProfilesProvider
from .websearch import WebSearchProvider
from .xposedornot import XposedOrNotProvider

PROVIDERS: tuple[Provider, ...] = (
    Provider(
        id="companies-house",
        name="Companies House",
        tier="free",
        enriches=("domain",),
        config_keys=("COMPANIES_HOUSE_KEY",),
        setting_attrs=("companies_house_key",),
        homepage="https://developer.company-information.service.gov.uk/",
        notes="UK company lookup",
    ),
    HIBPProvider(),
    XposedOrNotProvider(),
    LeakCheckProvider(),
    HudsonRockProvider(),
    ProtonKeyProvider(),
    GitHubCommitsProvider(),
    GitHubIdentityProvider(),
    *PROFILE_PROVIDERS,
    WaybackProfilesProvider(),
    HunterProvider(),
    NumVerifyProvider(),
    VonageNumberInsightProvider(),
    WebSearchProvider(),
    EmailRepProvider(),
    ShodanProvider(),
    VirusTotalProvider(),
    Provider(
        id="securitytrails",
        name="SecurityTrails",
        tier="pro",
        enriches=("domain",),
        config_keys=("SECURITYTRAILS_API_KEY",),
        setting_attrs=("securitytrails_api_key",),
        homepage="https://securitytrails.com/corp/api",
        notes="passive DNS and subdomain enrichment",
    ),
    CensysProvider(),
)


def provider_by_id(provider_id: str) -> Provider | None:
    lookup = {provider.id: provider for provider in PROVIDERS}
    return lookup.get(provider_id.strip().lower())


def providers_for_target(target_type: str, *, skip_provider_ids: set[str] | None = None) -> list[Provider]:
    skipped = skip_provider_ids or set()
    return [
        provider
        for provider in PROVIDERS
        if target_type in provider.enriches and provider.id not in skipped
    ]


def queryable_providers_for_target(
    target_type: str,
    *,
    skip_provider_ids: set[str] | None = None,
) -> list[Provider]:
    return [
        provider
        for provider in providers_for_target(target_type, skip_provider_ids=skip_provider_ids)
        if type(provider).query is not Provider.query
    ]


async def query_registered_providers(
    target: str,
    target_type: str,
    client: HttpClient,
    settings: Settings,
    *,
    skip_provider_ids: set[str] | None = None,
) -> list[Hit]:
    providers = queryable_providers_for_target(target_type, skip_provider_ids=skip_provider_ids)
    ctx = ProviderContext(settings=settings, client=client)

    async def run_one(provider: Provider) -> list[Hit]:
        status = provider.status(settings)
        if status.state == "disabled":
            return [provider.disabled_hit()]
        if status.state == "not_configured":
            return [provider.not_configured_hit()]
        if status.state == "inactive_pro":
            hit = provider.pro_gate_hit(target_type)
            return [hit] if hit else []
        try:
            return await provider.query(target, target_type, ctx)
        except Exception as e:
            return [
                Hit(
                    source=provider.name,
                    category="provider",
                    status=Status.ERROR,
                    error=str(e)[:160],
                    confidence=0.0,
                    extra={"provider_id": provider.id, "tier": provider.tier},
                )
            ]

    results = await asyncio.gather(*(run_one(provider) for provider in providers))
    return [hit for provider_hits in results for hit in provider_hits]


def provider_status_rows(settings: Settings) -> list[dict[str, str]]:
    rows = []
    for provider in PROVIDERS:
        status: ProviderStatus = provider.status(settings)
        rows.append(
            {
                "id": provider.id,
                "name": provider.name,
                "tier": provider.tier,
                "enriches": ", ".join(provider.enriches),
                "keys": ", ".join(provider.config_keys),
                "status": status.state,
                "detail": status.detail,
                "homepage": provider.homepage,
            }
        )
    return rows


def append_registry_gate_hits(
    report,
    settings: Settings,
    *,
    skip_provider_ids: set[str] | None = None,
) -> None:
    append_provider_gate_hits(
        report,
        settings,
        providers_for_target(report.query_type, skip_provider_ids=skip_provider_ids),
        skip_provider_ids=skip_provider_ids,
    )
