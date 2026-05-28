# SPDX-License-Identifier: AGPL-3.0-or-later
"""Optional API provider registry."""

from __future__ import annotations

from recce.config import Settings

from .base import Provider, ProviderStatus, append_provider_gate_hits

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
    Provider(
        id="hibp",
        name="Have I Been Pwned",
        tier="free",
        enriches=("email",),
        config_keys=("HIBP_API_KEY",),
        setting_attrs=("hibp_api_key",),
        homepage="https://haveibeenpwned.com/API/Key",
        notes="email breach lookups",
    ),
    Provider(
        id="hunter",
        name="Hunter.io",
        tier="free",
        enriches=("email", "domain"),
        config_keys=("HUNTER_API_KEY",),
        setting_attrs=("hunter_api_key",),
        homepage="https://hunter.io/api",
        notes="email verification and domain pivots",
    ),
    Provider(
        id="numverify",
        name="NumVerify",
        tier="free",
        enriches=("phone",),
        config_keys=("NUMVERIFY_API_KEY",),
        setting_attrs=("numverify_api_key",),
        homepage="https://numverify.com/",
        notes="free tier is HTTP-only and limited",
    ),
    Provider(
        id="emailrep",
        name="EmailRep",
        tier="free",
        enriches=("email",),
        config_keys=("EMAILREP_API_KEY",),
        setting_attrs=("emailrep_api_key",),
        homepage="https://emailrep.io/",
        notes="key optional; useful for higher rate limits",
        key_optional=True,
    ),
    Provider(
        id="shodan",
        name="Shodan",
        tier="pro",
        enriches=("domain",),
        config_keys=("SHODAN_API_KEY",),
        setting_attrs=("shodan_api_key",),
        homepage="https://developer.shodan.io/",
        notes="host and internet-exposure enrichment",
    ),
    Provider(
        id="virustotal",
        name="VirusTotal",
        tier="pro",
        enriches=("domain", "email"),
        config_keys=("VIRUSTOTAL_API_KEY",),
        setting_attrs=("virustotal_api_key",),
        homepage="https://docs.virustotal.com/reference/overview",
        notes="domain and indicator reputation enrichment",
    ),
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
    Provider(
        id="censys",
        name="Censys",
        tier="pro",
        enriches=("domain",),
        config_keys=("CENSYS_API_ID", "CENSYS_API_SECRET"),
        setting_attrs=("censys_api_id", "censys_api_secret"),
        homepage="https://search.censys.io/api",
        notes="host and certificate enrichment",
    ),
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
