# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local investigation workspace storage.

This is intentionally standard-library only. The beta GUI needs a durable,
local-first case workspace before Recce Pro needs a full desktop shell.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import textwrap
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
        self._ensure_private_db_file()
        self._init_db()

    def _ensure_private_db_file(self) -> None:
        fd = os.open(self.db_path, os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(self.db_path, 0o600)

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
        event_type = "domain.run" if report.query_type == "domain" else "run.recorded"
        self.append_audit_event(
            investigation_id,
            event_type,
            {
                "run_id": run["id"],
                "query_type": report.query_type,
                "query": report.query,
                "hits": len(report.found),
                "sources_checked": len(report.hits),
            },
        )
        if report.query_type == "domain" and args.get("bruteforce"):
            self.append_audit_event(
                investigation_id,
                "domain.bruteforce.run",
                {
                    "run_id": run["id"],
                    "query": report.query,
                    "wordlist": args.get("bruteforce_wordlist"),
                    "concurrency": args.get("bruteforce_concurrency"),
                    "rate": args.get("bruteforce_rate"),
                    "authorised": args.get("i_am_authorised", False),
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

    def list_runs_for_query(
        self,
        investigation_id: str,
        *,
        query_type: str,
        query: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM runs
                WHERE investigation_id = ?
                  AND query_type = ?
                  AND query = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (investigation_id, query_type, query, limit),
            ).fetchall()
        return [self._decode_run(dict(row)) for row in rows]

    def compare_latest_runs_for_query(
        self,
        investigation_id: str,
        *,
        query_type: str,
        query: str,
    ) -> dict[str, Any] | None:
        runs = self.list_runs_for_query(
            investigation_id,
            query_type=query_type,
            query=query,
            limit=2,
        )
        if len(runs) < 2:
            return None
        return compare_runs(runs[1], runs[0])

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
        # "|" is reserved as a structural delimiter. payload_json is canonical
        # JSON and is treated as one opaque field in the hash input.
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

    def verify_audit_chain(self) -> tuple[bool, str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, payload_json, created_at, previous_hash, event_hash
                FROM audit_events
                ORDER BY rowid ASC
                """
            ).fetchall()
        previous_hash = ""
        for index, row in enumerate(rows, start=1):
            event = dict(row)
            expected = hashlib.sha256(
                "{previous_hash}|{created_at}|{event_type}|{payload_json}".format(
                    previous_hash=previous_hash,
                    created_at=event["created_at"],
                    event_type=event["event_type"],
                    payload_json=event["payload_json"],
                ).encode()
            ).hexdigest()
            if event["previous_hash"] != previous_hash:
                return False, f"event {index} previous hash mismatch"
            if event["event_hash"] != expected:
                return False, f"event {index} hash mismatch"
            previous_hash = event["event_hash"]
        return True, f"{len(rows)} event(s) verified"

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

    def export_pdf_bytes(self, investigation_id: str, *, redacted: bool = False) -> bytes:
        payload = self.export_investigation(investigation_id, redacted=redacted)
        inv = payload["investigation"]
        runs = payload["runs"]
        pdf = _PdfDocument()

        pdf.heading(f"Recce Investigation Report: {inv['name']}", level=1)
        pdf.text(f"Case ref: {inv.get('case_ref') or '-'}")
        pdf.text(f"Classification: {inv.get('classification') or '-'}")
        pdf.text(f"Status: {inv.get('status') or '-'}")
        pdf.text(f"Created: {inv.get('created_at') or '-'}")
        pdf.text(f"Exported: {payload['exported_at']}")
        pdf.text(f"Redacted: {'yes' if payload['redacted'] else 'no'}")

        if inv.get("scope_note"):
            pdf.heading("Scope", level=2)
            pdf.paragraph(inv["scope_note"])

        total_hits = sum(len(run["report"].get("hits", [])) for run in runs)
        confirmed_count = sum(
            len([hit for hit in run["report"].get("hits", []) if hit.get("status") == "found"])
            for run in runs
        )
        pdf.heading("Subject Summary", level=2)
        pdf.text(f"Runs: {len(runs)}")
        pdf.text(f"Sources checked: {total_hits}")
        pdf.text(f"Confirmed findings: {confirmed_count}")

        pdf.heading("Runs", level=2)
        if not runs:
            pdf.text("No runs recorded.")
        for run in runs:
            report = run["report"]
            hits = report.get("hits", [])
            confirmed = [hit for hit in hits if hit.get("status") == "found"]
            pdf.heading(f"{run['query_type']}: {run['query']}", level=3)
            pdf.text(f"Run at: {run['created_at']}")
            pdf.text(f"Recce version: {run['recce_version']}")
            pdf.text(f"Sources checked: {len(hits)}")
            pdf.text(f"Confirmed hits: {len(confirmed)}")
            if confirmed:
                for hit in confirmed[:12]:
                    detail = hit.get("summary") or hit.get("error") or hit.get("url") or ""
                    pdf.bullet(
                        "{source} ({category}) - {detail}".format(
                            source=hit.get("source") or "-",
                            category=hit.get("category") or "-",
                            detail=detail or "-",
                        )
                    )
                if len(confirmed) > 12:
                    pdf.text(f"+{len(confirmed) - 12} additional confirmed finding(s) in JSON evidence.")

        pdf.heading("Evidence Appendix", level=2)
        for run in runs:
            confirmed = [hit for hit in run["report"].get("hits", []) if hit.get("status") == "found"]
            if not confirmed:
                continue
            pdf.heading(f"{run['query_type']}: {run['query']}", level=3)
            for hit in confirmed:
                pdf.text(f"Source: {hit.get('source') or '-'}")
                pdf.text(f"Category: {hit.get('category') or '-'}")
                if hit.get("url"):
                    pdf.paragraph(f"URL: {hit['url']}")
                if hit.get("summary") or hit.get("error"):
                    pdf.paragraph(f"Notes: {hit.get('summary') or hit.get('error')}")
                pdf.rule()

        pdf.heading("Methodology Note", level=2)
        pdf.paragraph(
            "This report was generated from a local Recce investigation workspace. "
            "Results reflect public-source probes at the time each run was recorded. "
            "Ambiguous, blocked, rate-limited, and missing responses should be reviewed "
            "in the underlying JSON evidence before being relied on."
        )
        pdf.heading("Audit Summary", level=2)
        pdf.text(f"Audit events included: {len(payload['audit_events'])}")
        pdf.text("Full event hashes and payloads are preserved in the JSON export.")
        return pdf.render()

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


class _PdfDocument:
    width = 595
    height = 842
    margin = 54

    def __init__(self) -> None:
        self.pages: list[list[str]] = []
        self._new_page()

    def heading(self, text: str, *, level: int) -> None:
        size = 18 if level == 1 else 14 if level == 2 else 11
        gap = 18 if level == 1 else 14
        self._ensure_space(gap + size)
        self._line(text, size=size, bold=True)
        self.y -= 4

    def text(self, text: str) -> None:
        for line in self._wrap(text, size=9):
            self._line(line, size=9)

    def paragraph(self, text: str) -> None:
        for line in self._wrap(text, size=9):
            self._line(line, size=9)
        self.y -= 4

    def bullet(self, text: str) -> None:
        for index, line in enumerate(self._wrap(text, size=9, prefix_width=12)):
            prefix = "- " if index == 0 else "  "
            self._line(f"{prefix}{line}", size=9)

    def rule(self) -> None:
        self._ensure_space(14)
        y = self.y
        self.pages[-1].append(f"0.8 w {self.margin} {y:.2f} m {self.width - self.margin} {y:.2f} l S")
        self.y -= 10

    def render(self) -> bytes:
        objects: list[bytes] = []
        catalog_id = 1
        pages_id = 2
        font_regular_id = 3
        font_bold_id = 4
        page_ids = []
        next_id = 5
        for _page in self.pages:
            page_ids.append(next_id)
            next_id += 2

        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode())
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        for page_index, commands in enumerate(self.pages):
            page_id = page_ids[page_index]
            content_id = page_id + 1
            content = "\n".join(commands).encode("latin-1", "replace")
            objects.append(
                (
                    f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.width} {self.height}] "
                    f"/Resources << /Font << /F1 {font_regular_id} 0 R /F2 {font_bold_id} 0 R >> >> "
                    f"/Contents {content_id} 0 R >>"
                ).encode()
            )
            objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")

        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(out))
            out.extend(f"{index} 0 obj\n".encode())
            out.extend(obj)
            out.extend(b"\nendobj\n")
        xref_at = len(out)
        out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            out.extend(f"{offset:010d} 00000 n \n".encode())
        out.extend(
            (
                "trailer\n"
                f"<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
                "startxref\n"
                f"{xref_at}\n"
                "%%EOF\n"
            ).encode()
        )
        return bytes(out)

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = self.height - self.margin
        self._line("recce investigation report", size=8, muted=True)
        self.y -= 12

    def _ensure_space(self, needed: int) -> None:
        if self.y - needed < self.margin:
            self._new_page()

    def _line(self, text: str, *, size: int, bold: bool = False, muted: bool = False) -> None:
        self._ensure_space(size + 6)
        font = "F2" if bold else "F1"
        gray = "0.45 g" if muted else "0 g"
        safe = _pdf_escape(text)
        self.pages[-1].append(f"BT /{font} {size} Tf {gray} {self.margin} {self.y:.2f} Td ({safe}) Tj ET")
        self.y -= size + 4

    def _wrap(self, text: str, *, size: int, prefix_width: int = 0) -> list[str]:
        text = " ".join(str(text).split())
        available = self.width - (self.margin * 2) - prefix_width
        chars = max(28, int(available / (size * 0.5)))
        return textwrap.wrap(text, width=chars, break_long_words=True) or [""]


def _pdf_escape(value: str) -> str:
    text = str(value).encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def compare_runs(previous_run: dict[str, Any], current_run: dict[str, Any]) -> dict[str, Any]:
    """Diff two saved run snapshots.

    The comparison focuses on found evidence. Misses, skips, and transient errors
    are preserved in the saved runs but are intentionally noisy for monitoring.
    """
    previous_hits = _found_hit_map(previous_run["report"].get("hits", []))
    current_hits = _found_hit_map(current_run["report"].get("hits", []))
    previous_keys = set(previous_hits)
    current_keys = set(current_hits)

    added = [current_hits[key] for key in sorted(current_keys - previous_keys)]
    removed = [previous_hits[key] for key in sorted(previous_keys - current_keys)]
    changed = []
    for key in sorted(previous_keys & current_keys):
        before = previous_hits[key]
        after = current_hits[key]
        if _hit_fingerprint(before) != _hit_fingerprint(after):
            changed.append({"before": before, "after": after})

    return {
        "query": current_run["query"],
        "query_type": current_run["query_type"],
        "previous_run_id": previous_run["id"],
        "current_run_id": current_run["id"],
        "previous_at": previous_run["created_at"],
        "current_at": current_run["created_at"],
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": len(previous_keys & current_keys) - len(changed),
    }


def _found_hit_map(hits: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    out = {}
    for hit in hits:
        if hit.get("status") != "found":
            continue
        out[_hit_key(hit)] = hit
    return out


def _hit_key(hit: dict[str, Any]) -> tuple[str, str, str]:
    extra = hit.get("extra") if isinstance(hit.get("extra"), dict) else {}
    identity = (
        hit.get("url")
        or extra.get("profile_url")
        or extra.get("username")
        or extra.get("domain")
        or extra.get("provider_id")
        or hit.get("summary")
        or ""
    )
    return (str(hit.get("source") or ""), str(hit.get("category") or ""), str(identity))


def _hit_fingerprint(hit: dict[str, Any]) -> str:
    material = {
        "source": hit.get("source"),
        "category": hit.get("category"),
        "status": hit.get("status"),
        "url": hit.get("url"),
        "summary": hit.get("summary"),
        "confidence": hit.get("confidence"),
        "extra": hit.get("extra"),
        "error": hit.get("error"),
    }
    return json.dumps(material, sort_keys=True, default=str)
