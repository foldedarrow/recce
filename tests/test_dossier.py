# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from typer.testing import CliRunner

from recce.cli import app
from recce.core.investigations import InvestigationStore
from recce.core.result import Cluster, ClusterMember, Hit, PivotOrigin, Report, Status

runner = CliRunner()


def _case(tmp_path: Path) -> tuple[InvestigationStore, str]:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Sample <case>", case_ref="T-1", scope_note="Test scope.")

    root = Report(query="sample", query_type="username", exit="direct")
    root.add(Hit(source="GitHub identity", category="identity", status=Status.FOUND,
                 url="https://github.com/sample", summary="<script>alert(1)</script>",
                 extra={"created_at": "2015-03-01T00:00:00Z", "emails": ["sam@example.test"],
                        "attribution": {"cluster": 1, "confidence": 0.8, "signals": []}}))
    root.add(Hit(source="GitLab profile", category="identity", status=Status.FOUND,
                 url="https://gitlab.com/sample", extra={"created_at": "2018-06-01",
                 "attribution": {"cluster": 1, "confidence": 0.8, "signals": []}}))
    root.add(Hit(source="Wayback: Twitter", category="archive", status=Status.FOUND,
                 url="https://web.archive.org/web/20120101000000/twitter.com/sample",
                 extra={"first_capture": "20120101000000"}))
    root.add(Hit(source="Pinterest", category="social", status=Status.NOT_FOUND))
    root.clusters = [
        Cluster(id=1, confidence=0.8,
                members=[ClusterMember(source="GitHub identity", url="https://github.com/sample"),
                         ClusterMember(source="GitLab profile", url="https://gitlab.com/sample")],
                signals=["GitHub identity ↔ GitLab profile: same avatar"],
                timeline=[ClusterMember(source="GitHub identity", created_at="2015-03-01T00:00:00Z"),
                          ClusterMember(source="GitLab profile", created_at="2018-06-01")])
    ]
    root.finish()

    child = Report(query="sam@example.test", query_type="email", exit="tor (socks5h://127.0.0.1:9050)",
                   pivot=PivotOrigin(from_query="sample", from_type="username", source="GitHub identity",
                                     field="emails", hit_url="https://github.com/sample", depth=1))
    child.add(Hit(source="Have I Been Pwned", category="breach", status=Status.FOUND,
                  summary="1 breach(es): ExampleBreach",
                  extra={"breaches": [{"Name": "ExampleBreach", "BreachDate": "2019-05-01"}]}))
    child.add(Hit(source="Hudson Rock (infostealers)", category="breach", status=Status.FOUND,
                  extra={"stealer": {"date_compromised": "2023-02-02T00:00:00.000Z"}}))
    child.finish()

    for report in (root, child):
        store.record_run(investigation_id=inv["id"], report=report, args={}, recce_version="0.5.0",
                         wmn_cache={})
    return store, inv["id"]


def test_dossier_has_every_section_and_is_self_contained(tmp_path: Path) -> None:
    store, case_id = _case(tmp_path)

    html = store.export_html(case_id)

    assert html.startswith("<!doctype html>")
    for heading in ("Summary", "Identity graph", "Likely the same person", "Timeline", "Findings", "Methodology"):
        assert f"<h2>{heading}</h2>" in html
    # Self-contained: no scripts, stylesheets or images fetched from anywhere.
    assert "<script" not in html and "<link" not in html and "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Sample &lt;case&gt;" in html


def test_dossier_graph_timeline_and_provenance(tmp_path: Path) -> None:
    store, case_id = _case(tmp_path)

    html = store.export_html(case_id)

    # Graph: both identifiers, root vs pivot, edge labelled with the hit that linked them.
    assert '<g class="node root">' in html and '<g class="node pivot">' in html
    assert "GitHub identity (emails)" in html
    # Timeline is sorted and covers each kind of dated evidence.
    timeline = html[html.index("<h2>Timeline</h2>"):html.index("<h2>Findings</h2>")]
    order = [timeline.index(s) for s in ("2012-01-01", "2015-03-01", "2018-06-01", "2019-05-01", "2023-02-02")]
    assert order == sorted(order)
    for tag in ("first archived", "account created", "breach", "infostealer infection"):
        assert f">{tag}</span>" in timeline
    assert "ExampleBreach (Have I Been Pwned)" in html
    # Provenance, attribution and exits.
    assert "Discovered via the <strong>GitHub identity</strong> hit (emails)" in html
    assert '<span class="badge">cluster 1</span>' in html
    assert "exit: tor (socks5h://127.0.0.1:9050)" in html
    assert "Audit hash chain: verified" in html
    assert "Pinterest" not in html  # misses aren't findings


def test_redacted_dossier_hides_identifiers(tmp_path: Path) -> None:
    store, case_id = _case(tmp_path)

    html = store.export_html(case_id, redacted=True)

    assert "sam@example.test" not in html
    assert "[REDACTED:" in html
    assert "searched identifiers are replaced with hashes" in html


def test_cli_exports_html_dossier(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_DATA_DIR", str(tmp_path))
    store, case_id = _case(tmp_path)
    monkeypatch.setattr("recce.cli._investigation_store", lambda: store)
    out = tmp_path / "dossier.html"

    result = runner.invoke(app, ["investigations", "export", case_id, "--format", "html", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.read_text().startswith("<!doctype html>")


def test_empty_case_dossier_renders(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Empty")

    html = store.export_html(inv["id"])

    assert "No runs recorded." in html
