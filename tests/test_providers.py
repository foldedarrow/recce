# SPDX-License-Identifier: AGPL-3.0-or-later
from recce.config import Settings
from recce.core.result import Report, Status
from recce.providers import append_registry_gate_hits, provider_status_rows


def _settings(**overrides) -> Settings:  # type: ignore[no-untyped-def]
    data = {
        "hibp_api_key": None,
        "hunter_api_key": None,
        "numverify_api_key": None,
        "emailrep_api_key": None,
        "leakcheck_api_key": None,
        "companies_house_key": None,
        "shodan_api_key": None,
        "virustotal_api_key": None,
        "securitytrails_api_key": None,
        "censys_api_id": None,
        "censys_api_secret": None,
        "user_agent": "recce-test",
        "timeout": 3.0,
        "max_concurrency": 2,
        "provider_integrations_enabled": True,
    }
    data.update(overrides)
    return Settings(**data)


def test_provider_statuses_include_optional_key_and_not_configured(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    rows = {row["id"]: row for row in provider_status_rows(_settings())}

    assert rows["emailrep"]["status"] == "active"
    assert rows["hibp"]["status"] == "not_configured"
    assert rows["shodan"]["status"] == "not_configured"


def test_pro_provider_is_gated_without_entitlement(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    rows = {row["id"]: row for row in provider_status_rows(_settings(shodan_api_key="key"))}

    assert rows["shodan"]["status"] == "inactive_pro"


def test_append_registry_gate_hits_adds_pro_skip(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)
    report = Report(query="example.com", query_type="domain")

    append_registry_gate_hits(report, _settings(shodan_api_key="key"))

    assert len(report.hits) == 1
    assert report.hits[0].source == "Shodan"
    assert report.hits[0].status is Status.SKIPPED


def test_no_providers_disables_registry_status(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)

    rows = provider_status_rows(_settings(provider_integrations_enabled=False))

    assert {row["status"] for row in rows} == {"disabled"}
