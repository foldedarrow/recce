"""Local investigation workspace storage.

This is intentionally standard-library only. The beta GUI needs a durable,
local-first case workspace before Recce Pro needs a full desktop shell.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .result import Report


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_data_dir() -> Path:
    root = os.getenv("RECCE_DATA_DIR")
    if root:
        return Path(root).expanduser()
    return Path.home() / ".local" / "share" / "recce"


class InvestigationStore:
    """SQLite-backed local investigation workspace."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.root = default_data_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path or self.root / "investigations.sqlite3"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    case_ref TEXT NOT NULL DEFAULT '',
                    scope_note TEXT NOT NULL DEFAULT '',
                    classification TEXT NOT NULL DEFAULT 'Internal',
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runs (
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

                CREATE TABLE IF NOT EXISTS audit_events (
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

    def create_investigation(
        self,
        *,
        name: str,
        case_ref: str = "",
        scope_note: str = "",
        classification: str = "Internal",
    ) -> dict[str, Any]:
        inv = {
            "id": str(uuid4()),
            "name": name.strip(),
            "case_ref": case_ref.strip(),
            "scope_note": scope_note.strip(),
            "classification": classification,
            "status": "open",
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }
        if not inv["name"]:
            raise ValueError("Investigation name is required.")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO investigations
                (id, name, case_ref, scope_note, classification, status, created_at, updated_at)
                VALUES
                (:id, :name, :case_ref, :scope_note, :classification, :status, :created_at, :updated_at)
                """,
                inv,
            )
        self.append_audit_event(inv["id"], "investigation.created", inv)
        return inv

    def list_investigations(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT i.*,
                       COUNT(r.id) AS run_count,
                       MAX(r.created_at) AS last_run_at
                FROM investigations i
                LEFT JOIN runs r ON r.investigation_id = i.id
                GROUP BY i.id
                ORDER BY i.updated_at DESC, i.created_at DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM investigations WHERE id = ?",
                (investigation_id,),
            ).fetchone()
        return dict(row) if row else None

    def record_run(
        self,
        *,
        investigation_id: str,
        report: Report,
        args: dict[str, Any],
        recce_version: str,
        wmn_cache: dict[str, Any],
    ) -> dict[str, Any]:
        if self.get_investigation(investigation_id) is None:
            raise ValueError("Investigation does not exist.")
        created_at = utc_now()
        run = {
            "id": str(uuid4()),
            "investigation_id": investigation_id,
            "query_type": report.query_type,
            "query": report.query,
            "args_json": json.dumps(args, sort_keys=True, default=str),
            "report_json": report.model_dump_json(),
            "recce_version": recce_version,
            "wmn_cache_json": json.dumps(wmn_cache, sort_keys=True, default=str),
            "created_at": created_at,
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs
                (id, investigation_id, query_type, query, args_json, report_json,
                 recce_version, wmn_cache_json, created_at)
                VALUES
                (:id, :investigation_id, :query_type, :query, :args_json, :report_json,
                 :recce_version, :wmn_cache_json, :created_at)
                """,
                run,
            )
            conn.execute(
                "UPDATE investigations SET updated_at = ? WHERE id = ?",
                (created_at, investigation_id),
            )
        self.append_audit_event(
            investigation_id,
            "run.recorded",
            {
                "run_id": run["id"],
                "query_type": report.query_type,
                "query": report.query,
                "hits": len(report.found),
                "sources_checked": len(report.hits),
            },
        )
        return self._decode_run(run)

    def list_runs(self, investigation_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM runs
                WHERE investigation_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (investigation_id, limit),
            ).fetchall()
        return [self._decode_run(dict(row)) for row in rows]

    def list_audit_events(self, investigation_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM audit_events
                WHERE investigation_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (investigation_id, limit),
            ).fetchall()
        return [self._decode_audit(dict(row)) for row in rows]

    def append_audit_event(
        self,
        investigation_id: str | None,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        created_at = utc_now()
        payload_json = json.dumps(payload, sort_keys=True, default=str)
        previous_hash = self._last_audit_hash()
        event_hash = hashlib.sha256(
            f"{previous_hash}|{created_at}|{event_type}|{payload_json}".encode()
        ).hexdigest()
        event = {
            "id": str(uuid4()),
            "investigation_id": investigation_id,
            "event_type": event_type,
            "payload_json": payload_json,
            "created_at": created_at,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events
                (id, investigation_id, event_type, payload_json, created_at, previous_hash, event_hash)
                VALUES
                (:id, :investigation_id, :event_type, :payload_json, :created_at,
                 :previous_hash, :event_hash)
                """,
                event,
            )
        return self._decode_audit(event)

    def export_investigation(
        self,
        investigation_id: str,
        *,
        redacted: bool = False,
    ) -> dict[str, Any]:
        inv = self.get_investigation(investigation_id)
        if inv is None:
            raise ValueError("Investigation does not exist.")
        runs = self.list_runs(investigation_id, limit=10_000)
        audit = self.list_audit_events(investigation_id, limit=10_000)
        payload: dict[str, Any] = {
            "exported_at": utc_now(),
            "redacted": redacted,
            "investigation": inv,
            "runs": runs,
            "audit_events": audit,
        }
        if redacted:
            subjects = [run["query"] for run in runs]
            payload = _redact_payload(payload, subjects)
        return payload

    def export_json_bytes(self, investigation_id: str, *, redacted: bool = False) -> bytes:
        payload = self.export_investigation(investigation_id, redacted=redacted)
        return json.dumps(payload, indent=2, default=str).encode()

    def export_markdown(self, investigation_id: str, *, redacted: bool = False) -> str:
        payload = self.export_investigation(investigation_id, redacted=redacted)
        inv = payload["investigation"]
        runs = payload["runs"]
        lines = [
            f"# Recce Investigation Report: {inv['name']}",
            "",
            f"- Case ref: {inv.get('case_ref') or '-'}",
            f"- Classification: {inv.get('classification') or '-'}",
            f"- Status: {inv.get('status') or '-'}",
            f"- Created: {inv.get('created_at') or '-'}",
            f"- Exported: {payload['exported_at']}",
            f"- Redacted: {'yes' if payload['redacted'] else 'no'}",
            "",
        ]
        if inv.get("scope_note"):
            lines.extend(["## Scope", "", inv["scope_note"], ""])
        lines.extend(["## Runs", ""])
        if not runs:
            lines.append("No runs recorded.")
        for run in runs:
            report = run["report"]
            found = report.get("hits", [])
            confirmed = [h for h in found if h.get("status") == "found"]
            lines.extend(
                [
                    f"### {run['query_type']}: {run['query']}",
                    "",
                    f"- Run at: {run['created_at']}",
                    f"- Recce version: {run['recce_version']}",
                    f"- Sources checked: {len(found)}",
                    f"- Confirmed hits: {len(confirmed)}",
                    "",
                ]
            )
            if confirmed:
                lines.append("| Source | Category | URL | Notes |")
                lines.append("|---|---|---|---|")
                for hit in confirmed:
                    lines.append(
                        "| {source} | {category} | {url} | {notes} |".format(
                            source=_md_cell(hit.get("source")),
                            category=_md_cell(hit.get("category")),
                            url=_md_cell(hit.get("url")),
                            notes=_md_cell(hit.get("summary") or hit.get("error")),
                        )
                    )
                lines.append("")
        lines.extend(
            [
                "## Methodology Note",
                "",
                "This report was generated from a local Recce investigation workspace. "
                "Results reflect public-source probes at the time each run was recorded. "
                "Ambiguous, blocked, rate-limited, and missing responses should be reviewed "
                "in the underlying JSON evidence before being relied on.",
                "",
            ]
        )
        return "\n".join(lines)

    def _last_audit_hash(self) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
        return str(row["event_hash"]) if row else ""

    @staticmethod
    def _decode_run(run: dict[str, Any]) -> dict[str, Any]:
        run = dict(run)
        run["args"] = json.loads(run.pop("args_json"))
        run["report"] = json.loads(run.pop("report_json"))
        run["wmn_cache"] = json.loads(run.pop("wmn_cache_json"))
        return run

    @staticmethod
    def _decode_audit(event: dict[str, Any]) -> dict[str, Any]:
        event = dict(event)
        event["payload"] = json.loads(event.pop("payload_json"))
        return event


def _redact_payload(payload: dict[str, Any], subjects: list[str]) -> dict[str, Any]:
    replacements = {
        subject: f"[REDACTED:{hashlib.sha256(subject.lower().encode()).hexdigest()[:12]}]"
        for subject in subjects
        if subject
    }

    def redact(value: Any) -> Any:
        if isinstance(value, str):
            out = value
            for subject, replacement in replacements.items():
                out = out.replace(subject, replacement)
            return out
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    return redact(payload)


def _md_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()
