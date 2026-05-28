# SPDX-License-Identifier: AGPL-3.0-or-later
from recce.core.result import Hit, Report, Status
from recce.modules.domain_summary import build_domain_summary


def _row_map(report: Report) -> dict[str, str]:
    return {row.label: row.value for row in build_domain_summary(report)}


def test_domain_summary_extracts_key_domain_facts() -> None:
    report = Report(query="example.com", query_type="domain")
    report.add(
        Hit(
            source="RDAP",
            category="ownership",
            status=Status.FOUND,
            extra={
                "created": "2014-08-22T00:00:00Z",
                "registrar": "Tucows",
                "org": "Example Corp (US)",
            },
        )
    )
    report.add(
        Hit(
            source="IP enrichment",
            category="network",
            status=Status.FOUND,
            extra={"ip": "203.0.113.10", "asn": {"asn": "13335", "name": "CLOUDFLARENET"}},
        )
    )
    report.add(
        Hit(
            source="Microsoft 365 realm",
            category="email",
            status=Status.FOUND,
            extra={"namespace": "Managed", "brand": "Example"},
        )
    )
    report.add(
        Hit(
            source="HTTPS probe",
            category="web",
            status=Status.FOUND,
            extra={"status_code": 200, "technologies": ["Apache", "WordPress"], "title": "Example"},
        )
    )
    report.add(
        Hit(
            source="Passive subdomains",
            category="subs",
            status=Status.FOUND,
            extra={
                "subdomains": [
                    {"host": "www.example.com", "sources": ["crt.sh"], "resolves": True},
                    {"host": "mail.example.com", "sources": ["OTX"], "resolves": True},
                ]
            },
        )
    )
    report.add(
        Hit(
            source="Subdomain bruteforce",
            category="subs",
            status=Status.FOUND,
            extra={"subdomains": ["vpn.example.com", "mail.example.com"]},
        )
    )
    report.add(
        Hit(
            source="Linked socials",
            category="web",
            status=Status.FOUND,
            extra={"links": ["https://www.linkedin.com/company/example/", "https://twitter.com/example"]},
        )
    )

    rows = _row_map(report)

    assert rows["Domain"] == "example.com"
    assert rows["Registered"].startswith("2014-08-22")
    assert rows["Registrar"] == "Tucows"
    assert rows["Registrant"] == "Example Corp (US)"
    assert rows["Hosting"] == "13335 CLOUDFLARENET"
    assert rows["Email"] == "Microsoft 365 (Managed) - Example"
    assert rows["Web"] == "HTTP 200 - Apache, WordPress - Example"
    assert rows["Subdomains"] == "3 found (2 passive, 1 bruteforce-only)"
    assert rows["Socials"] == "www.linkedin.com/company/example, twitter.com/example"


def test_domain_summary_has_safe_fallbacks() -> None:
    report = Report(query="example.net", query_type="domain")

    rows = _row_map(report)

    assert rows["Registered"] == "Unknown"
    assert rows["Email"] == "Unknown"
    assert rows["Subdomains"] == "0 found"
    assert rows["Socials"] == "None found"
