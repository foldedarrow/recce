# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3
from pathlib import Path
from stat import S_IMODE

import pytest
from typer.testing import CliRunner

from recce.cli import app
from recce.core.investigations import InvestigationStore, delete_confirmation_matches
from recce.core.result import Hit, Report, Status

runner = CliRunner()


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


def test_audit_events_migrate_from_delete_cascade_to_set_null(tmp_path: Path) -> None:
    db_path = tmp_path / "old.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(
            """
            CREATE TABLE investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                case_ref TEXT NOT NULL DEFAULT '',
                scope_note TEXT NOT NULL DEFAULT '',
                classification TEXT NOT NULL DEFAULT 'Internal',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE runs (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                query_type TEXT NOT NULL,
                query TEXT NOT NULL,
                args_json TEXT NOT NULL,
                report_json TEXT NOT NULL,
                recce_version TEXT NOT NULL,
                wmn_cache_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE audit_events (
                id TEXT PRIMARY KEY,
                investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            INSERT INTO investigations
            (id, name, created_at, updated_at)
            VALUES ('old-case', 'Old case', '2026-05-28T00:00:00+00:00', '2026-05-28T00:00:00+00:00')
            """
        )
        conn.execute(
            """
            INSERT INTO audit_events
            (id, investigation_id, event_type, payload_json, created_at, previous_hash, event_hash)
            VALUES ('audit-1', 'old-case', 'investigation.created', '{}',
                    '2026-05-28T00:00:00+00:00', '', 'hash-1')
            """
        )

    InvestigationStore(db_path)

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        fk_rows = conn.execute("PRAGMA foreign_key_list(audit_events)").fetchall()
        assert fk_rows[0][6].upper() == "SET NULL"
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
        conn.execute("DELETE FROM investigations WHERE id = 'old-case'")
        audit_row = conn.execute("SELECT investigation_id FROM audit_events WHERE id = 'audit-1'").fetchone()

    assert audit_row[0] is None


def test_investigation_lifecycle_status_transitions_and_list_filtering(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    closed = store.create_investigation(name="Closed case")
    archived = store.create_investigation(name="Archived case")
    open_case = store.create_investigation(name="Open case")

    updated = store.close_investigation(closed["id"], reason="done")
    assert updated["status"] == "closed"
    assert {case["id"] for case in store.list_investigations()} == {open_case["id"], archived["id"]}

    archived_updated = store.archive_investigation(archived["id"], reason="tidy")
    assert archived_updated["status"] == "archived"
    assert [case["id"] for case in store.list_investigations()] == [open_case["id"]]

    assert {case["id"] for case in store.list_investigations(include_statuses={"open", "closed"})} == {
        open_case["id"],
        closed["id"],
    }
    assert {
        case["id"]
        for case in store.list_investigations(include_statuses={"open", "closed", "archived"})
    } == {open_case["id"], closed["id"], archived["id"]}

    assert store.reopen_investigation(closed["id"])["status"] == "open"
    assert store.unarchive_investigation(archived["id"])["status"] == "open"

    with pytest.raises(ValueError, match="closed"):
        store.reopen_investigation(open_case["id"])
    with pytest.raises(ValueError, match="archived"):
        store.unarchive_investigation(open_case["id"])

    events = store.list_audit_events(closed["id"], limit=10)
    assert "investigation.closed" in [event["event_type"] for event in events]
    assert "investigation.reopened" in [event["event_type"] for event in events]


def test_delete_investigation_writes_tombstone_and_preserves_chain(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Smoke case", case_ref="SMOKE-1")
    other = store.create_investigation(name="Retained case")
    report = Report(query="alice", query_type="username")
    report.add(Hit(source="Example", status=Status.FOUND, url="https://example.test/alice"))
    report.finish()
    run = store.record_run(
        investigation_id=inv["id"],
        report=report,
        args={},
        recce_version="0.4.0",
        wmn_cache={},
    )

    tombstone = store.delete_investigation(inv["id"], reason="smoke test")

    assert tombstone["case_id"] == inv["id"]
    assert tombstone["name"] == "Smoke case"
    assert tombstone["case_ref"] == "SMOKE-1"
    assert tombstone["reason"] == "smoke test"
    assert tombstone["deleted_run_count"] == 1
    assert store.get_investigation(inv["id"]) is None
    assert store.list_runs(inv["id"]) == []
    assert store.get_investigation(other["id"]) is not None

    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        deleted_events = conn.execute(
            "SELECT * FROM audit_events WHERE event_type = 'investigation.deleted'"
        ).fetchall()
        case_run_count = conn.execute("SELECT COUNT(*) FROM runs WHERE id = ?", (run["id"],)).fetchone()[0]
        orphaned_case_events = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE investigation_id = ?", (inv["id"],)
        ).fetchone()[0]

    assert case_run_count == 0
    assert orphaned_case_events == 0
    assert len(deleted_events) == 1
    assert deleted_events[0]["investigation_id"] is None
    assert f'"case_id": "{inv["id"]}"' in deleted_events[0]["payload_json"]
    assert store.verify_audit_chain()[0] is True

    store.append_audit_event(other["id"], "investigation.note", {"note": "after delete"})
    assert store.verify_audit_chain()[0] is True


def test_delete_confirmation_matches_case_name() -> None:
    assert delete_confirmation_matches("Smoke Case", "Smoke Case")
    assert delete_confirmation_matches("Smoke Case", "  Smoke Case  ")
    assert not delete_confirmation_matches("Smoke Case", "smoke case")
    assert not delete_confirmation_matches("Smoke Case", "")


def test_investigations_delete_cli_requires_yes(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "investigations.sqlite3")
    inv = store.create_investigation(name="CLI smoke")

    result = runner.invoke(
        app,
        ["investigations", "delete", inv["id"], "--reason", "mistake"],
        env={"RECCE_DATA_DIR": str(tmp_path)},
    )

    assert result.exit_code != 0
    assert "--yes" in result.output
    assert store.get_investigation(inv["id"]) is not None


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


def test_pdf_export_generates_report_and_redacts_subject(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(
        name="Subject review",
        case_ref="KYC-2",
        scope_note="Shareable report test.",
        classification="Restricted",
    )
    report = Report(query="alice@example.com", query_type="email")
    report.add(
        Hit(
            source="Example",
            category="profile",
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

    full_pdf = store.export_pdf_bytes(inv["id"])
    redacted_pdf = store.export_pdf_bytes(inv["id"], redacted=True)

    assert full_pdf.startswith(b"%PDF-")
    assert b"Recce Investigation Report" in full_pdf
    assert b"alice@example.com" in full_pdf
    assert redacted_pdf.startswith(b"%PDF-")
    assert b"alice@example.com" not in redacted_pdf
    assert b"[REDACTED:" in redacted_pdf


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


def test_compare_latest_runs_for_query_detects_added_removed_and_changed(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Monitoring review")

    first = Report(query="alice", query_type="username")
    first.add(
        Hit(
            source="Example",
            category="social",
            status=Status.FOUND,
            url="https://example.test/alice",
            summary="old bio",
        )
    )
    first.add(
        Hit(
            source="Gone",
            category="social",
            status=Status.FOUND,
            url="https://gone.test/alice",
            summary="present",
        )
    )
    first.finish()
    store.record_run(
        investigation_id=inv["id"],
        report=first,
        args={},
        recce_version="0.4.0",
        wmn_cache={},
    )

    second = Report(query="alice", query_type="username")
    second.add(
        Hit(
            source="Example",
            category="social",
            status=Status.FOUND,
            url="https://example.test/alice",
            summary="new bio",
        )
    )
    second.add(
        Hit(
            source="New",
            category="social",
            status=Status.FOUND,
            url="https://new.test/alice",
            summary="appeared",
        )
    )
    second.add(Hit(source="Miss", category="social", status=Status.NOT_FOUND))
    second.finish()
    store.record_run(
        investigation_id=inv["id"],
        report=second,
        args={},
        recce_version="0.4.0",
        wmn_cache={},
    )

    comparison = store.compare_latest_runs_for_query(
        inv["id"],
        query_type="username",
        query="alice",
    )

    assert comparison is not None
    assert [hit["source"] for hit in comparison["added"]] == ["New"]
    assert [hit["source"] for hit in comparison["removed"]] == ["Gone"]
    assert len(comparison["changed"]) == 1
    assert comparison["changed"][0]["before"]["summary"] == "old bio"
    assert comparison["changed"][0]["after"]["summary"] == "new bio"
    assert comparison["unchanged_count"] == 0


def test_compare_latest_runs_for_query_requires_two_snapshots(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Single run")
    report = Report(query="alice", query_type="username")
    report.add(Hit(source="Example", status=Status.FOUND, url="https://example.test/alice"))
    report.finish()
    store.record_run(
        investigation_id=inv["id"],
        report=report,
        args={},
        recce_version="0.4.0",
        wmn_cache={},
    )

    assert store.compare_latest_runs_for_query(inv["id"], query_type="username", query="alice") is None
