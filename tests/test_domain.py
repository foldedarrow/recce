# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest

from recce.config import Settings
from recce.core.result import Hit, Status
from recce.modules import domain as domain_module
from recce.modules.domain import (
    BRUTEFORCE_WORDLIST_COUNTS,
    domain_consent_error,
    load_bruteforce_wordlist,
    normalize_domain,
    search_domain,
)


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
    async def fake_email(domain: str, client: DummyClient, settings: Settings) -> list[Hit]:
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

    monkeypatch.setattr(domain_module, "_email_infra_hits", fake_email)
    monkeypatch.setattr(domain_module, "_ownership_hits", forbidden)
    monkeypatch.setattr(domain_module, "_network_hits", forbidden)
    monkeypatch.setattr(domain_module, "_web_hits", forbidden)
    monkeypatch.setattr(domain_module, "_passive_subdomain_hits", forbidden)
    monkeypatch.setattr(domain_module, "_company_hits", forbidden)
    monkeypatch.setattr(domain_module, "_wayback_hits", forbidden)

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
