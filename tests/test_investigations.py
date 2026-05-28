# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from stat import S_IMODE

from recce.core.investigations import InvestigationStore
from recce.core.result import Hit, Report, Status


def test_investigation_store_uses_private_db_permissions(tmp_path: Path) -> None:
    db_path = tmp_path / "recce.sqlite3"
    InvestigationStore(db_path)

    assert S_IMODE(db_path.stat().st_mode) == 0o600


def test_investigation_store_records_run_and_audit_chain(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(
        name="Acme review",
        case_ref="KYC-1",
        scope_note="Authorised onboarding check.",
        classification="Confidential",
    )
    report = Report(query="alice", query_type="username")
    report.add(Hit(source="Example", status=Status.FOUND, url="https://example.test/alice"))
    report.finish()

    run = store.record_run(
        investigation_id=inv["id"],
        report=report,
        args={"include_nsfw": False},
        recce_version="0.4.0",
        wmn_cache={"exists": False},
    )

    runs = store.list_runs(inv["id"])
    audit = store.list_audit_events(inv["id"])
    assert run["query"] == "alice"
    assert runs[0]["report"]["query"] == "alice"
    assert runs[0]["report"]["hits"][0]["source"] == "Example"
    assert [event["event_type"] for event in audit] == ["run.recorded", "investigation.created"]
    assert audit[0]["previous_hash"] == audit[1]["event_hash"]
    assert store.verify_audit_chain() == (True, "2 event(s) verified")


def test_redacted_export_masks_subject_in_json_and_markdown(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Subject review")
    report = Report(query="alice@example.com", query_type="email")
    report.add(
        Hit(
            source="Example",
            status=Status.FOUND,
            summary="alice@example.com profile",
            url="https://example.test/alice@example.com",
        )
    )
    report.finish()
    store.record_run(
        investigation_id=inv["id"],
        report=report,
        args={},
        recce_version="0.4.0",
        wmn_cache={},
    )

    redacted_json = store.export_json_bytes(inv["id"], redacted=True).decode()
    redacted_md = store.export_markdown(inv["id"], redacted=True)

    assert "alice@example.com" not in redacted_json
    assert "alice@example.com" not in redacted_md
    assert "[REDACTED:" in redacted_json
    assert "[REDACTED:" in redacted_md


def test_domain_run_uses_domain_audit_events(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Domain review")
    report = Report(query="example.com", query_type="domain")
    report.add(Hit(source="DNS A", category="network", status=Status.FOUND, summary="93.184.216.34"))
    report.finish()

    store.record_run(
        investigation_id=inv["id"],
        report=report,
        args={
            "bruteforce": True,
            "i_am_authorised": True,
            "bruteforce_wordlist": "small",
            "bruteforce_concurrency": 25,
            "bruteforce_rate": 10,
        },
        recce_version="0.4.0",
        wmn_cache={},
    )

    events = store.list_audit_events(inv["id"])
    assert [event["event_type"] for event in events[:2]] == [
        "domain.bruteforce.run",
        "domain.run",
    ]
