# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest

from recce.config import Settings
from recce.core.result import Hit, Status
from recce.modules import domain as domain_module
from recce.modules.domain import (
    BRUTEFORCE_WORDLIST_COUNTS,
    DOMAIN_CATEGORIES,
    domain_consent_error,
    load_bruteforce_wordlist,
    normalize_domain,
    search_domain,
)
from recce.modules.domain_sources import SourceContext, source_registry
from recce.modules.domain_sources import companies as companies_source


class DummyClient:
    pass


def _settings() -> Settings:
    return Settings(
        hibp_api_key=None,
        hunter_api_key=None,
        numverify_api_key=None,
        emailrep_api_key=None,
        leakcheck_api_key=None,
        companies_house_key=None,
        shodan_api_key=None,
        virustotal_api_key=None,
        securitytrails_api_key=None,
        censys_api_id=None,
        censys_api_secret=None,
        user_agent="recce-test",
        timeout=3.0,
        max_concurrency=2,
    )


def test_normalize_domain_accepts_urls_and_subdomains() -> None:
    assert normalize_domain("https://www.Example.co.uk/path?q=1") == "example.co.uk"
    assert normalize_domain("mail.example.com") == "example.com"


def test_bruteforce_wordlists_match_promised_sizes() -> None:
    for name, expected in BRUTEFORCE_WORDLIST_COUNTS.items():
        labels = load_bruteforce_wordlist(name)
        assert len(labels) == expected
        assert labels[0] == "www"
        assert len(labels) == len(set(labels))


def test_domain_source_registry_covers_all_categories() -> None:
    categories = {category for category, _source in source_registry()}

    assert categories == DOMAIN_CATEGORIES


@pytest.mark.asyncio
async def test_domain_bruteforce_requires_authorisation() -> None:
    with pytest.raises(ValueError, match="Active subdomain bruteforce"):
        await search_domain(
            "example.com",
            DummyClient(),  # type: ignore[arg-type]
            _settings(),
            bruteforce=True,
            authorised=False,
        )
    assert "docs/CONSENT.md" in domain_consent_error("example.com")


@pytest.mark.asyncio
async def test_search_domain_filters_categories(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_email(domain: str, ctx: SourceContext) -> list[Hit]:
        del ctx
        return [
            Hit(
                source="DNS MX",
                category="email",
                status=Status.FOUND,
                summary=f"mail for {domain}",
            )
        ]

    async def forbidden(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("disabled source should not run")

    monkeypatch.setattr(
        domain_module,
        "source_registry",
        lambda: [
            ("ownership", forbidden),
            ("network", forbidden),
            ("email", fake_email),
            ("web", forbidden),
            ("subs", forbidden),
            ("companies", forbidden),
            ("wayback", forbidden),
        ],
    )

    report = await search_domain(
        "https://www.example.com",
        DummyClient(),  # type: ignore[arg-type]
        _settings(),
        only_categories={"email"},
    )

    assert report.query == "example.com"
    assert report.query_type == "domain"
    assert len(report.hits) == 1
    assert report.hits[0].category == "email"


@pytest.mark.asyncio
async def test_companies_source_uses_rdap_org_before_domain_label(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    async def fake_rdap(domain: str, ctx: SourceContext) -> Hit:
        del ctx
        assert domain == "example.com"
        return Hit(
            source="RDAP",
            category="ownership",
            status=Status.FOUND,
            extra={"org": "Example Holdings Ltd"},
        )

    async def fake_companies_house(org_guess: str, ctx: SourceContext) -> Hit:
        del ctx
        calls.append(("ch", org_guess))
        return Hit(source="Companies House", category="companies", status=Status.NOT_FOUND)

    async def fake_edgar(org_guess: str, ctx: SourceContext) -> Hit:
        del ctx
        calls.append(("edgar", org_guess))
        return Hit(source="SEC EDGAR", category="companies", status=Status.NOT_FOUND)

    monkeypatch.setattr(companies_source.rdap, "query", fake_rdap)
    monkeypatch.setattr(companies_source.companies_house, "query", fake_companies_house)
    monkeypatch.setattr(companies_source.edgar, "query", fake_edgar)

    hits = await companies_source.query(
        "example.com",
        SourceContext(client=DummyClient(), settings=_settings()),  # type: ignore[arg-type]
    )

    assert [hit.source for hit in hits] == ["Companies House", "SEC EDGAR"]
    assert calls == [("ch", "Example Holdings Ltd"), ("edgar", "Example Holdings Ltd")]


@pytest.mark.asyncio
async def test_companies_source_falls_back_to_domain_label_when_rdap_org_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    async def fake_rdap(domain: str, ctx: SourceContext) -> Hit:
        del domain, ctx
        return Hit(source="RDAP", category="ownership", status=Status.FOUND, extra={"org": None})

    async def fake_companies_house(org_guess: str, ctx: SourceContext) -> Hit:
        del ctx
        calls.append(org_guess)
        return Hit(source="Companies House", category="companies", status=Status.NOT_FOUND)

    async def fake_edgar(org_guess: str, ctx: SourceContext) -> Hit:
        del ctx
        calls.append(org_guess)
        return Hit(source="SEC EDGAR", category="companies", status=Status.NOT_FOUND)

    monkeypatch.setattr(companies_source.rdap, "query", fake_rdap)
    monkeypatch.setattr(companies_source.companies_house, "query", fake_companies_house)
    monkeypatch.setattr(companies_source.edgar, "query", fake_edgar)

    await companies_source.query(
        "example-holdings.co.uk",
        SourceContext(client=DummyClient(), settings=_settings()),  # type: ignore[arg-type]
    )

    assert calls == ["example holdings", "example holdings"]
