# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTML dossier: one self-contained page per investigation.

Built from `InvestigationStore.export_investigation()` (so the redacted
variant redacts the same way the other exports do). No external assets or
scripts: the file opens offline, prints, and can be attached to a case.

Sections: summary, identity graph (the pivot chain as inline SVG), likely-
same-person clusters, timeline (account creation, first archive capture,
infostealer infections, breaches, searches), findings per run, methodology.
"""

from __future__ import annotations

import re
from html import escape
from typing import Any

_DATE_RE = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})")
_YEAR_RE = re.compile(r"^(\d{4})$")


def render_dossier(payload: dict[str, Any], *, audit_status: tuple[bool, str] | None = None) -> str:
    inv = payload["investigation"]
    runs = sorted(payload["runs"], key=lambda r: r.get("created_at") or "")
    chain = payload.get("pivot_chain") or []
    found_by_run = {run["id"]: _found(run) for run in runs}

    parts = [
        _header(inv, payload),
        _summary(runs, chain, found_by_run),
        _graph_section(runs, chain, found_by_run),
        _clusters_section(runs),
        _identities_section(runs),
        _timeline_section(runs, found_by_run),
        _findings_section(runs, found_by_run),
        _methodology(runs, payload, audit_status),
    ]
    title = f"Recce dossier: {inv.get('name') or 'investigation'}"
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{escape(title)}</title><style>{_CSS}</style></head><body><main>"
        + "".join(parts)
        + "</main></body></html>\n"
    )


# --- sections -----------------------------------------------------------------


def _header(inv: dict[str, Any], payload: dict[str, Any]) -> str:
    facts = [
        ("Case ref", inv.get("case_ref") or "—"),
        ("Classification", inv.get("classification") or "—"),
        ("Status", inv.get("status") or "—"),
        ("Created", _day(inv.get("created_at")) or "—"),
        ("Exported", _day(payload.get("exported_at")) or "—"),
        ("Redacted", "yes" if payload.get("redacted") else "no"),
    ]
    scope = (
        f"<p class=\"scope\"><strong>Scope:</strong> {escape(inv['scope_note'])}</p>"
        if inv.get("scope_note")
        else ""
    )
    return (
        "<header><p class=\"eyebrow\">Recce investigation dossier</p>"
        f"<h1>{escape(inv.get('name') or 'Investigation')}</h1>"
        "<dl class=\"facts\">"
        + "".join(f"<div><dt>{escape(k)}</dt><dd>{escape(str(v))}</dd></div>" for k, v in facts)
        + f"</dl>{scope}</header>"
    )


def _summary(runs: list[dict], chain: list[dict], found_by_run: dict[str, list[dict]]) -> str:
    identifiers = {(r["query_type"], r["query"]) for r in runs}
    findings = sum(len(hits) for hits in found_by_run.values())
    clusters = sum(len(r["report"].get("clusters") or []) for r in runs)
    breaches = sum(1 for hits in found_by_run.values() for h in hits if h.get("category") == "breach")
    exits = sorted({r["report"].get("exit") for r in runs if r["report"].get("exit")})
    cards = [
        ("Identifiers searched", len(identifiers)),
        ("Confirmed findings", findings),
        ("Pivots followed", len(chain)),
        ("Identity clusters", clusters),
        ("Breach / infostealer hits", breaches),
        ("Network exits", len(exits) or "—"),
    ]
    return _section(
        "Summary",
        "<div class=\"cards\">"
        + "".join(
            f"<div class=\"card\"><span class=\"num\">{escape(str(v))}</span>"
            f"<span class=\"lbl\">{escape(k)}</span></div>"
            for k, v in cards
        )
        + "</div>",
    )


def _graph_section(runs: list[dict], chain: list[dict], found_by_run: dict[str, list[dict]]) -> str:
    latest: dict[tuple[str, str], dict] = {}
    for run in runs:
        latest[(run["query_type"], run["query"])] = run
    if not latest:
        return _section("Identity graph", "<p class=\"muted\">No runs recorded.</p>")
    depth = {key: 0 for key in latest}
    for edge in chain:
        to_key = (edge.get("to_type"), edge.get("to_query"))
        if to_key in depth:
            depth[to_key] = max(depth[to_key], int(edge.get("depth") or 1))
    columns: dict[int, list[tuple[str, str]]] = {}
    for key in latest:
        columns.setdefault(depth[key], []).append(key)

    node_w, node_h, col_gap, row_gap, pad = 250, 58, 140, 22, 16
    pos: dict[tuple[str, str], tuple[float, float]] = {}
    for col, keys in sorted(columns.items()):
        for row, key in enumerate(keys):
            pos[key] = (pad + col * (node_w + col_gap), pad + row * (node_h + row_gap))
    width = pad * 2 + (max(columns) + 1) * node_w + max(columns) * col_gap
    height = pad * 2 + max(len(k) for k in columns.values()) * (node_h + row_gap) - row_gap

    shapes: list[str] = []
    for edge in chain:
        a = pos.get((edge.get("from_type"), edge.get("from_query")))
        b = pos.get((edge.get("to_type"), edge.get("to_query")))
        if not a or not b:
            continue
        x1, y1 = a[0] + node_w, a[1] + node_h / 2
        x2, y2 = b[0], b[1] + node_h / 2
        mid = (x1 + x2) / 2
        shapes.append(
            f"<path class=\"edge\" d=\"M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}\" marker-end=\"url(#arrow)\"/>"
        )
        label = _clip(f"{edge.get('source')} ({edge.get('field')})", 26)
        shapes.append(
            f"<text class=\"edge-label\" x=\"{mid}\" y=\"{(y1 + y2) / 2 - 6}\" text-anchor=\"middle\">"
            f"{escape(label)}</text>"
        )
    for key, (x, y) in pos.items():
        run = latest[key]
        n_found = len(found_by_run[run["id"]])
        n_clusters = len(run["report"].get("clusters") or [])
        sub = f"{n_found} finding(s)" + (f" · {n_clusters} cluster(s)" if n_clusters else "")
        root = "root" if depth[key] == 0 else "pivot"
        shapes.append(
            f"<g class=\"node {root}\"><rect x=\"{x}\" y=\"{y}\" width=\"{node_w}\" height=\"{node_h}\" rx=\"8\"/>"
            f"<text class=\"kind\" x=\"{x + 12}\" y=\"{y + 18}\">{escape(key[0])}</text>"
            f"<text class=\"ident\" x=\"{x + 12}\" y=\"{y + 36}\">{escape(_clip(key[1], 30))}</text>"
            f"<text class=\"sub\" x=\"{x + 12}\" y=\"{y + 51}\">{escape(sub)}</text></g>"
        )
    svg = (
        f"<svg viewBox=\"0 0 {width} {height}\" width=\"{width}\" role=\"img\" "
        "aria-label=\"Identity graph: searched identifiers and the hits that led from one to the next\">"
        "<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" "
        "markerHeight=\"7\" orient=\"auto\"><path d=\"M0,0 L10,5 L0,10 z\" class=\"arrowhead\"/></marker></defs>"
        + "".join(shapes)
        + "</svg>"
    )
    note = (
        "Each box is an identifier that was searched; arrows show which hit named the next "
        "identifier (a pivot). Roots were searched directly."
    )
    return _section("Identity graph", f"<p class=\"muted\">{note}</p><div class=\"graph\">{svg}</div>")


def _clusters_section(runs: list[dict]) -> str:
    blocks = []
    for run in runs:
        for cluster in run["report"].get("clusters") or []:
            members = "".join(
                f"<li>{_link(m.get('url'), m.get('source'))}</li>" for m in cluster.get("members", [])
            )
            signals = "".join(f"<li>{escape(s)}</li>" for s in cluster.get("signals", []))
            timeline = " → ".join(
                f"{escape(m.get('source') or '')} {escape(_day(m.get('created_at')) or '')}"
                for m in cluster.get("timeline", [])
                if m.get("created_at")
            )
            blocks.append(
                "<article class=\"cluster\">"
                f"<h3>{escape(run['query_type'])} {escape(run['query'])}: cluster {cluster.get('id')} "
                f"<span class=\"badge\">confidence {float(cluster.get('confidence') or 0):.2f}</span></h3>"
                f"<div class=\"two\"><div><h4>Accounts</h4><ul>{members}</ul></div>"
                f"<div><h4>Why they're linked</h4><ul>{signals}</ul></div></div>"
                + (f"<p class=\"muted\">Account timeline: {timeline}</p>" if timeline else "")
                + "</article>"
            )
    if not blocks:
        body = (
            "<p class=\"muted\">No accounts were linked by corroborating profile data (same profile, "
            "cross-links, shared email, avatar or display name). Accounts matching only on a "
            "username are not evidence of a single owner.</p>"
        )
    else:
        body = "".join(blocks)
    return _section("Likely the same person", body)


def _identities_section(runs: list[dict]) -> str:
    from ..modules.attribution import merged_identities

    identities = merged_identities(runs)
    if not identities:
        return ""
    blocks = []
    for cluster in identities:
        members = "".join(
            f"<li>{_link(m.get('url'), m.get('source'))}</li>" for m in cluster.get("members", [])
        )
        signals = "".join(f"<li>{escape(s)}</li>" for s in cluster.get("signals", []))
        blocks.append(
            "<article class=\"cluster\">"
            f"<h3>Identity {cluster.get('id')} "
            f"<span class=\"badge\">confidence {float(cluster.get('confidence') or 0):.2f}</span></h3>"
            f"<div class=\"two\"><div><h4>Accounts (search in brackets)</h4><ul>{members}</ul></div>"
            f"<div><h4>Why they're linked</h4><ul>{signals}</ul></div></div></article>"
        )
    note = (
        "<p class=\"muted\">Accounts from different searches in this case that public profile data "
        "links to each other, so the handles or emails searched probably belong to one person.</p>"
    )
    return _section("Linked across searches", note + "".join(blocks))


def _timeline_section(runs: list[dict], found_by_run: dict[str, list[dict]]) -> str:
    events: list[tuple[str, str, str, str | None]] = []
    for run in runs:
        events.append((_day(run.get("created_at")) or "", "searched",
                       f"{run['query_type']} {run['query']}", None))
        for hit in found_by_run[run["id"]]:
            extra = hit.get("extra") or {}
            src = hit.get("source") or ""
            if _day(extra.get("created_at")):
                events.append((_day(extra["created_at"]), "account created", src, hit.get("url")))
            if _day(extra.get("first_capture")):
                events.append((_day(extra["first_capture"]), "first archived", src, hit.get("url")))
            stealer = extra.get("stealer") or {}
            if isinstance(stealer, dict) and _day(stealer.get("date_compromised")):
                events.append((_day(stealer["date_compromised"]), "infostealer infection", src, None))
            for breach in extra.get("breaches") or []:
                if not isinstance(breach, dict):
                    continue
                when = _day(breach.get("BreachDate") or breach.get("breach_date") or breach.get("date") or breach.get("year"))
                name = breach.get("Name") or breach.get("Title") or breach.get("name") or "breach"
                if when:
                    events.append((when, "breach", f"{name} ({src})", None))
    dated = sorted((e for e in events if e[0]), key=lambda e: (e[0], e[1]))
    if len(dated) <= len(runs):
        return _section("Timeline", "<p class=\"muted\">No dated evidence beyond the searches themselves.</p>")
    rows = "".join(
        f"<tr><td class=\"date\">{escape(day)}</td><td><span class=\"tag {escape(kind.split()[0])}\">"
        f"{escape(kind)}</span></td><td>{_link(url, label)}</td></tr>"
        for day, kind, label, url in dated
    )
    return _section("Timeline", f"<table><thead><tr><th>Date</th><th>Event</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>")


def _findings_section(runs: list[dict], found_by_run: dict[str, list[dict]]) -> str:
    blocks = []
    for run in runs:
        report = run["report"]
        hits = sorted(found_by_run[run["id"]], key=lambda h: (h.get("category") or "", h.get("source") or ""))
        meta = [f"run {escape(_day(run.get('created_at')) or '')}", f"recce {escape(run.get('recce_version') or '?')}"]
        if report.get("exit"):
            meta.append(f"exit: {escape(report['exit'])}")
        origin = report.get("pivot")
        via = ""
        if origin:
            via = (
                f"<p class=\"via\">Discovered via the <strong>{escape(str(origin.get('source')))}</strong> hit "
                f"({escape(str(origin.get('field')))}) in the {escape(str(origin.get('from_type')))} search for "
                f"<strong>{escape(str(origin.get('from_query')))}</strong>"
                + (f" — {_link(origin.get('hit_url'), origin.get('hit_url'))}" if origin.get("hit_url") else "")
                + "</p>"
            )
        if hits:
            rows = "".join(_finding_row(h) for h in hits)
            table = (
                "<table><thead><tr><th>Source</th><th>Category</th><th>Evidence</th><th>Notes</th>"
                f"<th>Attribution</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        else:
            table = "<p class=\"muted\">No confirmed findings.</p>"
        blocks.append(
            f"<article class=\"run\"><h3>{escape(run['query_type'])}: {escape(run['query'])}</h3>"
            f"<p class=\"muted\">{' · '.join(meta)} · {len(report.get('hits') or [])} sources checked</p>"
            f"{via}{table}</article>"
        )
    return _section("Findings", "".join(blocks) or "<p class=\"muted\">No runs recorded.</p>")


def _finding_row(hit: dict) -> str:
    from ..modules.attribution import cluster_attribution

    extra = hit.get("extra") or {}
    attribution = cluster_attribution(extra) or {}
    if attribution.get("cluster") is not None:
        attr = f"<span class=\"badge\">cluster {attribution['cluster']}</span>"
    elif attribution:
        attr = "<span class=\"muted\">username only</span>"
    else:
        attr = ""
    notes = escape(_clip(hit.get("summary") or "", 260))
    if extra.get("exit"):
        notes += f" <span class=\"muted\">(via {escape(extra['exit'])})</span>"
    return (
        f"<tr><td>{escape(hit.get('source') or '')}</td><td>{escape(hit.get('category') or '')}</td>"
        f"<td>{_link(hit.get('url'), 'open')}</td><td>{notes}</td><td>{attr}</td></tr>"
    )


def _methodology(runs: list[dict], payload: dict[str, Any], audit_status: tuple[bool, str] | None) -> str:
    exits = sorted({r["report"].get("exit") for r in runs if r["report"].get("exit")})
    versions = sorted({r.get("recce_version") or "?" for r in runs})
    items = [
        "Results reflect public sources at the time of each run. Blocked, rate-limited and "
        "ambiguous responses are kept in the JSON evidence and are not findings.",
        "Username hits are re-checked with a made-up username; sites that 'find' it are downgraded.",
        "Deep email probes and subdomain bruteforce only run with recorded consent; "
        "pivots never trigger them.",
        f"Network exits used: {', '.join(exits) if exits else 'not recorded'}.",
        f"Recce version(s): {', '.join(versions) or '—'}.",
        f"Audit events in this case: {len(payload.get('audit_events') or [])}.",
    ]
    if audit_status is not None:
        ok, detail = audit_status
        items.append(f"Audit hash chain: {'verified' if ok else 'FAILED'} ({detail}).")
    if payload.get("redacted"):
        items.append("Redacted export: searched identifiers are replaced with hashes.")
    return _section("Methodology", "<ul>" + "".join(f"<li>{escape(i)}</li>" for i in items) + "</ul>")


# --- helpers --------------------------------------------------------------------


def _found(run: dict) -> list[dict]:
    return [h for h in run["report"].get("hits") or [] if h.get("status") == "found"]


def _section(title: str, body: str) -> str:
    return f"<section><h2>{escape(title)}</h2>{body}</section>"


def _link(url: Any, label: Any) -> str:
    text = escape(str(label or url or ""))
    if isinstance(url, str) and url.startswith(("http://", "https://")):
        return f"<a href=\"{escape(url, quote=True)}\" rel=\"noopener noreferrer\">{text}</a>"
    return text


def _clip(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _day(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if m := _DATE_RE.match(text):
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    if m := _YEAR_RE.match(text):
        return m.group(1)
    return None


_CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--accent:#2f5d8a;
--accent-soft:#e6eef6;--warn:#9a4b16;--warn-soft:#f8ece2;--node:#fff;--node-root:#e6eef6}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;--muted:#a3a29b;
--line:#33332f;--accent:#8fb6dc;--accent-soft:#22313f;--warn:#e3a272;--warn-soft:#3a2a1e;--node:#1d1d1b;
--node-root:#22313f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:8px}
.eyebrow{margin:0;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-size:12px}
h1{margin:4px 0 12px;font-size:28px}h2{font-size:19px;margin:32px 0 12px}
h3{font-size:16px;margin:0 0 6px}h4{font-size:13px;margin:0 0 4px;color:var(--muted)}
.facts{display:flex;flex-wrap:wrap;gap:8px 24px;margin:0}.facts div{min-width:110px}
.facts dt{font-size:12px;color:var(--muted)}.facts dd{margin:0;font-weight:600}
.scope{margin:12px 0 0}.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .num{display:block;font-size:24px;font-weight:700}.card .lbl{color:var(--muted);font-size:13px}
.graph{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px}
.graph svg{display:block;max-width:none}
.node rect{fill:var(--node);stroke:var(--line);stroke-width:1.5}.node.root rect{fill:var(--node-root);
stroke:var(--accent)}.node text{fill:var(--ink)}.node .kind{font-size:11px;fill:var(--muted);
text-transform:uppercase;letter-spacing:.06em}.node .ident{font-size:14px;font-weight:600}
.node .sub{font-size:11px;fill:var(--muted)}.edge{fill:none;stroke:var(--accent);stroke-width:1.5}
.arrowhead{fill:var(--accent)}.edge-label{font-size:11px;fill:var(--muted)}
article{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;
margin-bottom:12px}.two{display:grid;grid-template-columns:1fr 2fr;gap:16px}
@media (max-width:640px){.two{grid-template-columns:1fr}}
ul{margin:0;padding-left:18px}.badge{display:inline-block;font-size:12px;font-weight:600;
background:var(--accent-soft);color:var(--accent);border-radius:999px;padding:1px 8px}
.via{background:var(--accent-soft);border-radius:8px;padding:6px 10px}
table{width:100%;border-collapse:collapse;font-size:13.5px;display:block;overflow-x:auto}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}td.date{white-space:nowrap;font-variant-numeric:tabular-nums}
.tag{font-size:12px;border-radius:6px;padding:1px 6px;background:var(--accent-soft);color:var(--accent)}
.tag.infostealer,.tag.breach{background:var(--warn-soft);color:var(--warn)}
a{color:var(--accent)}
@media print{body{background:#fff}article,.card,.graph{break-inside:avoid}}
"""
