# SPDX-License-Identifier: AGPL-3.0-or-later
"""Streamlit GUI for recce — modes on top
of the same async modules the CLI uses.

Run via the `recce-gui` console script, which invokes:
    streamlit run recce/gui/app.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import pandas as pd
import streamlit as st

from recce import __version__, monitor
from recce.config import Settings, user_env_path, write_user_env
from recce.core.egress import Exit, resolve_exit, resolve_fallback
from recce.core.http import http_client
from recce.core.investigations import InvestigationStore, delete_confirmation_matches
from recce.core.output import fallback_note
from recce.core.result import Report, Status
from recce.gui import theme
from recce.licensing import has_pro_entitlement, pro_licence_path, write_pro_licence
from recce.modules.attribution import cluster_attribution, uncorroborated_accounts
from recce.modules.domain import search_domain
from recce.modules.domain_summary import build_domain_summary
from recce.modules.email import search_email
from recce.modules.email_deep import deep_email_probes
from recce.modules.phone import search_phone
from recce.modules.pivot import Pivot, describe_origin, extract_pivots, pivot_key
from recce.modules.username import (
    DEFAULT_PER_DOMAIN_RATE,
    cache_status,
    category_counts,
    search_username,
    site_count,
)
from recce.providers import append_registry_gate_hits, provider_status_rows

# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

MODE_ICONS = {
    "Investigations": "folder_open",
    "Username": "alternate_email",
    "Email": "mail",
    "Phone": "call",
    "Domain": "language",
    "API Keys": "key",
}
MODE_GROUP = {"Investigations": "Cases", "API Keys": "System"}

st.set_page_config(
    page_title="recce",
    page_icon=":material/radar:",
    layout="wide",
    menu_items={
        "Get help": "https://github.com/foldedarrow/recce",
        "About": f"recce {__version__} — personal OSINT toolkit",
    },
)

theme.apply()

settings = Settings.load()


@st.cache_resource
def _investigation_store() -> InvestigationStore:
    return InvestigationStore()


store = _investigation_store()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    theme.brand(__version__)

    # Order matters: theme.CSS hangs the "Search" and "System" group labels
    # off the 2nd and 6th items.
    mode = st.radio(
        "Mode",
        list(MODE_ICONS),
        format_func=lambda m: f":material/{MODE_ICONS[m]}: {m}",
        horizontal=False,
        label_visibility="collapsed",
        key="mode",
    )

    theme.group("Case")
    case_filter_label = st.selectbox(
        "Case filter",
        ["Active only", "Active + closed", "All"],
        label_visibility="collapsed",
        key="case_status_filter",
    )
    case_filter_statuses = {
        "Active only": None,
        "Active + closed": {"open", "closed"},
        "All": {"open", "closed", "archived"},
    }[case_filter_label]
    investigations = store.list_investigations(include_statuses=case_filter_statuses)
    valid_ids = {inv["id"] for inv in investigations}
    current_id = st.session_state.get("active_investigation_id")
    if current_id not in valid_ids:
        st.session_state["active_investigation_id"] = investigations[0]["id"] if investigations else None
    active_id = st.session_state.get("active_investigation_id")
    if investigations:
        labels = [
            f"{inv['name']} ({inv['case_ref'] or 'no ref'}) · {inv['run_count']} run(s)"
            for inv in investigations
        ]
        selected_idx = next(
            (idx for idx, inv in enumerate(investigations) if inv["id"] == active_id),
            0,
        )
        selected_label = st.selectbox(
            "Active case",
            labels,
            index=selected_idx,
            label_visibility="collapsed",
        )
        st.session_state["active_investigation_id"] = investigations[labels.index(selected_label)]["id"]
    else:
        st.info("Create a case to start saving runs.")

    with st.expander("New case", expanded=not investigations):
        with st.form("new_investigation_form"):
            new_name = st.text_input("Name", placeholder="Acme onboarding fraud review")
            new_ref = st.text_input("Case ref", placeholder="KYC-2026-001")
            new_classification = st.selectbox(
                "Classification",
                ["Internal", "Confidential", "Restricted"],
                index=1,
            )
            new_scope = st.text_area("Scope note", placeholder="Authorised checks, subject scope, limits.")
            create_case = st.form_submit_button("Create case", use_container_width=True)
        if create_case:
            try:
                inv = store.create_investigation(
                    name=new_name,
                    case_ref=new_ref,
                    classification=new_classification,
                    scope_note=new_scope,
                )
                st.session_state["active_investigation_id"] = inv["id"]
                st.success("Case created.")
                st.rerun()
            except ValueError as e:
                st.error(str(e))

    rows = provider_status_rows(settings)
    active_count = len([row for row in rows if row["status"] == "active"])
    gated_count = len([row for row in rows if row["status"] == "inactive_pro"])
    n_default = site_count(include_nsfw=False)
    n_nsfw = site_count(include_nsfw=True) - n_default

    theme.group("Runtime")
    runtime_panel = st.expander("Network & limits", expanded=False)
    runtime_timeout = runtime_panel.number_input(
        "Timeout (seconds)", min_value=3.0, max_value=60.0, value=float(settings.timeout), step=1.0
    )
    runtime_concurrency = runtime_panel.number_input(
        "Request concurrency",
        min_value=1,
        max_value=100,
        value=int(settings.max_concurrency),
        step=1,
    )
    runtime_per_domain_rate = runtime_panel.number_input(
        "Username domain rate",
        min_value=0.0,
        max_value=10.0,
        value=float(DEFAULT_PER_DOMAIN_RATE),
        step=0.5,
    )
    runtime_proxy = runtime_panel.text_input(
        "Exit (proxy)",
        placeholder=f"configured: {resolve_exit('username').label}",
        help="Proxy URL (socks5h://, http://), an exit name from RECCE_EXITS, or 'direct'. "
        "Blank uses each mode's configured exit (RECCE_<MODE>_PROXY, then RECCE_PROXY).",
    ).strip()
    configured_fallback = resolve_fallback()
    runtime_fallback = runtime_panel.text_input(
        "Username fallback exit",
        placeholder=f"configured: {configured_fallback.label}" if configured_fallback else "e.g. tor or tor,home",
        help="Username probes bot-walled on the main exit (HTTP 401/403/429) are retried "
        "through this exit. Blank uses RECCE_USERNAME_FALLBACK_PROXY.",
    ).strip()

    runtime_panel.caption(
        f"{n_default} sites loaded (Maigret's only once selftest verifies them), "
        f"{n_nsfw} NSFW gated. Categories: "
        + ", ".join(f"{k} ({v})" for k, v in category_counts(include_nsfw=False).items())
    )
    if runtime_panel.button("Refresh site data", icon=":material/sync:", use_container_width=True):
        from recce.modules.maigret import refresh_data as refresh_maigret_data
        from recce.modules.username import refresh_wmn_data

        async def _refresh():
            async with http_client(
                user_agent=settings.user_agent,
                timeout=30.0,
                max_concurrency=2,
            ) as client:
                return await refresh_wmn_data(client), await refresh_maigret_data(client)

        with runtime_panel, st.spinner("Fetching latest from WhatsMyName and Maigret…"):
            try:
                (wmn_before, wmn_after), (m_before, m_after) = asyncio.run(_refresh())
                st.success(
                    f"WMN {wmn_before} → {wmn_after}; Maigret {m_before} → {m_after} "
                    "(used once `recce selftest` verifies them)"
                )
                st.rerun()
            except Exception as e:
                st.error(f"Update failed: {e}")

    theme.foot("Authorised, lawful investigations only", st.context.headers.get("X-Gate-User"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Status text colours in result tables (vantage's semantic palette).
STATUS_COLOUR = {
    Status.FOUND.value: "#3fb37f",
    Status.NOT_FOUND.value: "#45505b",
    Status.UNKNOWN.value: "#d6a531",
    Status.SKIPPED.value: "#64727f",
    Status.ERROR.value: "#e5484d",
}


def _status_style(value: Any) -> str:
    colour = STATUS_COLOUR.get(str(value))
    return f"color: {colour}" if colour else ""


def _cluster_label(hit: Any) -> str:
    attribution = cluster_attribution(hit.extra) if hit.is_found else None
    if not attribution:
        return ""
    if attribution.get("cluster") is None:
        return "username only"
    return f"#{attribution['cluster']} ({attribution['confidence']:.2f})"


def render_clusters(report: Report) -> None:
    if not report.clusters:
        return
    theme.section("Likely the same person", len(report.clusters))
    st.caption(
        "Hits linked by corroborating public data: same profile, cross-links, "
        "shared email, same avatar, same display name or location. A shared "
        "username alone is not evidence of one owner."
    )
    cards = []
    for cluster in report.clusters:
        signals = list(cluster.signals)
        if cluster.timeline:
            signals.append(
                "Timeline: "
                + " → ".join(f"{m.source} {m.created_at[:10]}" for m in cluster.timeline if m.created_at)
            )
        cards.append(theme.card(
            f"Cluster {cluster.id}",
            pills=[
                theme.pill(f"{len(cluster.members)} profiles"),
                theme.pill(f"confidence {cluster.confidence:.2f}", "accent"),
            ],
            body=", ".join(m.source for m in cluster.members),
            signals=signals,
            accent=True,
        ))
    theme.html("".join(cards))
    alone = uncorroborated_accounts(report)
    if alone:
        st.caption(f"{alone} other account(s) match on the username only.")


def report_to_df(report: Report) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for h in report.hits:
        rows.append(
            {
                "Source": h.source,
                "Category": h.category,
                "Status": h.status.value,
                "URL": h.url or "",
                "Notes": h.summary or h.error or "",
                "Confidence": round(h.confidence, 2),
                "Cluster": _cluster_label(h),
                "ms": h.elapsed_ms or 0,
            }
        )
    return pd.DataFrame(rows)


def _gui_exit(module: str) -> Exit:
    """The sidebar's exit override, else the module's configured exit."""
    return resolve_exit(module, runtime_proxy or None)


def _gui_fallback() -> Exit | None:
    return resolve_fallback(runtime_fallback or None)


def _gui_fallback_label() -> str | None:
    fallback = _gui_fallback()
    return fallback.label if fallback else None


def active_investigation() -> dict[str, Any] | None:
    inv_id = st.session_state.get("active_investigation_id")
    if not inv_id:
        return None
    return store.get_investigation(inv_id)


def audit_event_label(event_type: str) -> str:
    labels = {
        "investigation.created": "Case created",
        "investigation.closed": "Case closed",
        "investigation.reopened": "Case reopened",
        "investigation.archived": "Case archived",
        "investigation.unarchived": "Case unarchived",
        "investigation.deleted": "Case deleted",
        "run.recorded": "Run recorded",
        "domain.run": "Domain run",
        "domain.bruteforce.run": "Domain bruteforce run",
        "pivot.run": "Pivot run",
    }
    return labels.get(event_type, event_type)


def record_gui_run(report: Report, args: dict[str, Any]) -> None:
    inv = active_investigation()
    if inv is None:
        st.warning("Run completed but was not saved. Create or select a case to keep an audit trail.")
        return
    store.record_run(
        investigation_id=inv["id"],
        report=report,
        args=args,
        recce_version=__version__,
        wmn_cache=cache_status(),
    )
    st.toast(f"Saved to case: {inv['name']}")


async def rerun_saved_query(run: dict[str, Any]) -> Report:
    """Re-run a saved query using the sidebar's exit and runtime settings."""
    return await monitor.rerun_saved_query(
        run,
        settings,
        exit=_gui_exit(run["query_type"]),
        fallback_exit=_gui_fallback(),
        timeout=float(runtime_timeout),
        max_concurrency=int(runtime_concurrency),
    )


def render_run_comparison(comparison: dict[str, Any]) -> None:
    added = comparison["added"]
    removed = comparison["removed"]
    changed = comparison["changed"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("New", len(added))
    c2.metric("Gone", len(removed))
    c3.metric("Changed", len(changed))
    c4.metric("Unchanged", comparison["unchanged_count"])
    st.caption(f"{comparison['previous_at']} → {comparison['current_at']}")

    if not added and not removed and not changed:
        st.success("No confirmed-evidence changes between the latest two snapshots.")
        return

    rows = []
    for hit in added:
        rows.append(_comparison_row("New", hit))
    for hit in removed:
        rows.append(_comparison_row("Gone", hit))
    for item in changed:
        before = item["before"]
        after = item["after"]
        rows.append(
            {
                "Change": "Changed",
                "Source": after.get("source") or before.get("source") or "",
                "Category": after.get("category") or before.get("category") or "",
                "URL": after.get("url") or before.get("url") or "",
                "Before": before.get("summary") or before.get("error") or "",
                "After": after.get("summary") or after.get("error") or "",
            }
        )
    st.dataframe(
        pd.DataFrame(rows),
        column_config={"URL": st.column_config.LinkColumn("URL", display_text=r"open ↗")},
        hide_index=True,
        use_container_width=True,
    )


def _comparison_row(change: str, hit: dict[str, Any]) -> dict[str, str]:
    return {
        "Change": change,
        "Source": str(hit.get("source") or ""),
        "Category": str(hit.get("category") or ""),
        "URL": str(hit.get("url") or ""),
        "Before": "" if change == "New" else str(hit.get("summary") or hit.get("error") or ""),
        "After": str(hit.get("summary") or hit.get("error") or "") if change == "New" else "",
    }


def _mark_searched(report: Report) -> None:
    searched = st.session_state.setdefault("pivot_searched", set())
    searched.add(pivot_key(report.query_type, report.query))


def _queue_pivot(pivot: Pivot) -> None:
    """Button callback: switch mode, pre-fill the identifier, run it next render."""
    if pivot.kind == "username":
        st.session_state["mode"] = "Username"
        st.session_state["u_target"] = pivot.value
    else:
        st.session_state["mode"] = "Email"
        st.session_state["e_target"] = pivot.value
    st.session_state["pending_pivot"] = pivot


def _take_pending_pivot(kind: str) -> Pivot | None:
    pending = st.session_state.get("pending_pivot")
    if pending is None or pending.kind != kind:
        return None
    del st.session_state["pending_pivot"]
    return pending


def render_pivot_suggestions(report: Report) -> None:
    """Identifiers named in this report's hits, as one-click follow-up searches."""
    searched = st.session_state.get("pivot_searched", set())
    depth = (report.pivot.depth if report.pivot else 0) + 1
    pivots = [p for p in extract_pivots(report, depth=depth) if p.key not in searched]
    if not pivots:
        return
    theme.section("Follow-up searches", len(pivots))
    st.caption(
        "Identifiers named in these hits. Follow-ups are passive lookups only; "
        "deep mode never runs on a discovered identifier. Saved runs record which "
        "hit led to each one."
    )
    for i, p in enumerate(pivots):
        cols = st.columns([4, 6])
        cols[0].button(
            f"{p.kind}: {p.value}",
            icon=":material/travel_explore:",
            key=f"pivot-{report.query_type}-{report.query}-{i}",
            on_click=_queue_pivot,
            args=(p,),
            use_container_width=True,
        )
        cols[1].caption(f"from **{p.origin.source}** ({p.origin.field})")


def render_results(report: Report, *, show_misses: bool, show_errors: bool) -> None:
    found = report.found
    errors = report.errors

    if report.pivot is not None:
        st.info(f"Pivot search — discovered via {describe_origin(report.pivot)}")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sources checked", len(report.hits))
    c2.metric("Hits", len(found), delta=None)
    c3.metric("Errors", len(errors))
    c4.metric("Elapsed", _elapsed_str(report))
    if report.exit:
        theme.meta([("exit", f"{report.exit}{fallback_note(report)}")])

    render_clusters(report)

    if found:
        theme.section("Confirmed hits", len(found))
        cards = []
        for h in found:
            cluster = _cluster_label(h)
            pills = [theme.pill(h.category)] if h.category else []
            if cluster.startswith("#"):
                pills.append(theme.pill(f"cluster {cluster}", "accent"))
            pills.append(theme.pill(f"{h.confidence:.2f}", "ok" if h.confidence >= 0.8 else ""))
            cards.append(theme.card(h.source, pills=pills, url=h.url, body=h.summary or "(no detail)"))
        theme.html("".join(cards))
    else:
        st.info("No confirmed hits. Try toggling 'Show misses' or 'Show errors' below for the full audit.")

    df = report_to_df(report)
    if not show_misses and not df.empty:
        df = df[df["Status"] != Status.NOT_FOUND.value]
    if not show_errors and not df.empty:
        df = df[df["Status"] != Status.ERROR.value]

    if not df.empty:
        theme.section("All results", len(df))
        st.dataframe(
            df.style.map(_status_style, subset=["Status"]),
            column_config={
                "URL": st.column_config.LinkColumn(
                    "URL", display_text=r"open ↗"
                ),
                "Confidence": st.column_config.ProgressColumn(
                    "Confidence", min_value=0.0, max_value=1.0, format="%.2f"
                ),
                "ms": st.column_config.NumberColumn("ms", format="%d"),
            },
            hide_index=True,
            use_container_width=True,
            height=min(50 + 35 * len(df), 600),
        )

    # Downloads
    csv = _csv_bytes(report)
    js = report.model_dump_json(indent=2).encode()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() else "-" for c in report.query)[:40]
    base = f"recce-{report.query_type}-{safe}-{ts}"

    dc1, dc2 = st.columns(2)
    dc1.download_button(
        "CSV", csv, file_name=f"{base}.csv", mime="text/csv", icon=":material/download:", use_container_width=True
    )
    dc2.download_button(
        "JSON", js, file_name=f"{base}.json", mime="application/json", icon=":material/download:",
        use_container_width=True,
    )


def render_domain_summary(report: Report) -> None:
    rows = build_domain_summary(report)
    if not rows:
        return
    theme.section("Summary")
    st.dataframe(
        pd.DataFrame([{"Field": row.label, "Value": row.value} for row in rows]),
        hide_index=True,
        use_container_width=True,
    )


def _elapsed_str(report: Report) -> str:
    total = report.duration_ms
    if total is None:
        total = sum((h.elapsed_ms or 0) for h in report.hits)
    if total < 1000:
        return f"{total} ms"
    return f"{total / 1000:.1f} s"


def _csv_bytes(report: Report) -> bytes:
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["query", "query_type", "source", "category", "status", "url", "summary", "confidence", "elapsed_ms", "error"])
    for h in report.hits:
        w.writerow([
            report.query, report.query_type, h.source, h.category, h.status.value,
            h.url or "", h.summary or "", f"{h.confidence:.2f}",
            h.elapsed_ms if h.elapsed_ms is not None else "",
            h.error or "",
        ])
    return buf.getvalue().encode()


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def _investigations_mode() -> None:
    theme.page_header(
        "Investigations",
        "Local case workspace for saved runs, evidence, audit history, and redacted exports.",
    )
    st.info(
        "Recce Pro stores investigation data locally at "
        f"`{store.db_path}`. This file is not encrypted at the application layer. "
        "Use full-disk encryption (BitLocker / FileVault / LUKS) on the host machine.",
    )

    inv = active_investigation()
    if inv is None:
        st.info("Create a case in the sidebar to start recording GUI runs.")
        return

    runs = store.list_runs(inv["id"], limit=250)
    audit = store.list_audit_events(inv["id"], limit=250)
    audit_ok, audit_message = store.verify_audit_chain()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Runs", len(runs))
    c2.metric("Confirmed hits", sum(len([h for h in run["report"].get("hits", []) if h.get("status") == "found"]) for run in runs))
    c3.metric("Classification", inv["classification"])
    c4.metric("Status", inv["status"])

    theme.section(inv["name"])
    meta_cols = st.columns([2, 2, 3])
    meta_cols[0].markdown(f"**Case ref**  \n{inv['case_ref'] or '-'}")
    meta_cols[1].markdown(f"**Created**  \n{inv['created_at']}")
    meta_cols[2].markdown(f"**Storage**  \n`{store.db_path}`")
    if inv.get("scope_note"):
        st.markdown("**Scope note**")
        st.write(inv["scope_note"])

    with st.expander("Case actions", expanded=False):
        reason = st.text_input("Reason", key=f"case_action_reason_{inv['id']}")
        action_cols = st.columns(2)
        if inv["status"] == "open":
            if action_cols[0].button("Close case", use_container_width=True):
                store.close_investigation(inv["id"], reason=reason)
                st.session_state["active_investigation_id"] = None
                st.success("Case closed.")
                st.rerun()
            if action_cols[1].button("Archive case", use_container_width=True):
                store.archive_investigation(inv["id"], reason=reason)
                st.session_state["active_investigation_id"] = None
                st.success("Case archived.")
                st.rerun()
        elif inv["status"] == "closed":
            if action_cols[0].button("Reopen case", use_container_width=True):
                store.reopen_investigation(inv["id"], reason=reason)
                st.success("Case reopened.")
                st.rerun()
            if action_cols[1].button("Archive case", use_container_width=True):
                store.archive_investigation(inv["id"], reason=reason)
                st.session_state["active_investigation_id"] = None
                st.success("Case archived.")
                st.rerun()
        elif inv["status"] == "archived":
            if action_cols[0].button("Unarchive case", use_container_width=True):
                store.unarchive_investigation(inv["id"], reason=reason)
                st.success("Case unarchived.")
                st.rerun()
            if action_cols[1].button("Close case", use_container_width=True):
                store.close_investigation(inv["id"], reason=reason)
                st.session_state["active_investigation_id"] = None
                st.success("Case closed.")
                st.rerun()

        st.divider()
        with st.form(f"delete_case_form_{inv['id']}"):
            st.caption("Permanent delete removes the case and saved runs. A tombstone remains in the audit chain.")
            delete_reason = st.text_input("Delete reason", key=f"delete_reason_{inv['id']}")
            typed_name = st.text_input("Type case name to confirm", key=f"delete_confirm_{inv['id']}")
            delete_submitted = st.form_submit_button("Delete case", type="secondary", use_container_width=True)
        if delete_submitted:
            if not delete_confirmation_matches(inv["name"], typed_name):
                st.error("Case name confirmation did not match.")
            else:
                store.delete_investigation(inv["id"], reason=delete_reason)
                st.session_state["active_investigation_id"] = None
                st.success("Case deleted.")
                st.rerun()

    export_base = "".join(c if c.isalnum() else "-" for c in inv["name"].lower())[:40]
    theme.section("Exports")
    h1, h2 = st.columns(2)
    h1.download_button(
        "HTML dossier",
        store.export_html(inv["id"], redacted=False).encode(),
        file_name=f"recce-{export_base}-dossier.html",
        mime="text/html",
        type="primary",
        use_container_width=True,
    )
    h2.download_button(
        "Redacted HTML dossier",
        store.export_html(inv["id"], redacted=True).encode(),
        file_name=f"recce-{export_base}-dossier-redacted.html",
        mime="text/html",
        use_container_width=True,
    )
    d1, d2, d3 = st.columns(3)
    d1.download_button(
        "Full JSON",
        store.export_json_bytes(inv["id"], redacted=False),
        file_name=f"recce-{export_base}-full.json",
        mime="application/json",
        use_container_width=True,
    )
    d2.download_button(
        "Redacted JSON",
        store.export_json_bytes(inv["id"], redacted=True),
        file_name=f"recce-{export_base}-redacted.json",
        mime="application/json",
        use_container_width=True,
    )
    d3.download_button(
        "Full PDF",
        store.export_pdf_bytes(inv["id"], redacted=False),
        file_name=f"recce-{export_base}.pdf",
        mime="application/pdf",
        use_container_width=True,
    )
    d4, d5, d6 = st.columns(3)
    d4.download_button(
        "Markdown",
        store.export_markdown(inv["id"], redacted=False).encode(),
        file_name=f"recce-{export_base}.md",
        mime="text/markdown",
        use_container_width=True,
    )
    d5.download_button(
        "Redacted MD",
        store.export_markdown(inv["id"], redacted=True).encode(),
        file_name=f"recce-{export_base}-redacted.md",
        mime="text/markdown",
        use_container_width=True,
    )
    d6.download_button(
        "Redacted PDF",
        store.export_pdf_bytes(inv["id"], redacted=True),
        file_name=f"recce-{export_base}-redacted.pdf",
        mime="application/pdf",
        use_container_width=True,
    )

    run_rows = []
    for run in runs:
        hits = run["report"].get("hits", [])
        confirmed = [h for h in hits if h.get("status") == "found"]
        run_rows.append(
            {
                "Run at": run["created_at"],
                "Type": run["query_type"],
                "Query": run["query"],
                "Sources": len(hits),
                "Hits": len(confirmed),
                "Version": run["recce_version"],
            }
        )
    theme.section("Run history")
    if run_rows:
        st.dataframe(pd.DataFrame(run_rows), hide_index=True, use_container_width=True)
    else:
        st.info("No runs recorded yet. Use Username, Email, or Phone while this case is active.")

    theme.section("Run comparison")
    latest_by_query: dict[tuple[str, str], dict[str, Any]] = {}
    for run in runs:
        latest_by_query.setdefault((run["query_type"], run["query"]), run)
    if not latest_by_query:
        st.info("Run a query in this case to start monitoring changes.")
    else:
        labels = {
            f"{run['query_type']}: {run['query']} · latest {run['created_at']}": run
            for run in latest_by_query.values()
        }
        selected_label = st.selectbox("Saved query", list(labels), key="compare_saved_query")
        selected_run = labels[selected_label]
        comparison = store.compare_latest_runs_for_query(
            inv["id"],
            query_type=selected_run["query_type"],
            query=selected_run["query"],
        )
        if comparison:
            render_run_comparison(comparison)
        else:
            st.caption("No previous snapshot for this query yet.")

        if st.button("Re-run and compare", type="primary", use_container_width=True):
            with st.status(f"Re-running **{selected_run['query']}**…", expanded=False) as status:
                try:
                    report = asyncio.run(rerun_saved_query(selected_run))
                    append_registry_gate_hits(report, settings)
                    store.record_run(
                        investigation_id=inv["id"],
                        report=report,
                        args=selected_run["args"],
                        recce_version=__version__,
                        wmn_cache=cache_status(),
                    )
                    status.update(label="Comparison snapshot saved.", state="complete")
                    st.session_state["latest_comparison"] = store.compare_latest_runs_for_query(
                        inv["id"],
                        query_type=selected_run["query_type"],
                        query=selected_run["query"],
                    )
                    st.rerun()
                except Exception as e:
                    status.update(label=str(e), state="error")
                    st.error(str(e))

    with st.expander("Audit events", expanded=False):
        if audit_ok:
            st.success(f"Audit chain verified: {audit_message}")
        else:
            st.error(f"Audit chain verification failed: {audit_message}")
        if audit:
            audit_rows = [
                {
                    "At": event["created_at"],
                    "Event": audit_event_label(event["event_type"]),
                    "Hash": event["event_hash"][:16],
                    "Previous": event["previous_hash"][:16],
                }
                for event in audit
            ]
            st.dataframe(pd.DataFrame(audit_rows), hide_index=True, use_container_width=True)
        else:
            st.caption("No audit events recorded.")


def _api_keys_mode() -> None:
    theme.page_header(
        "API Keys",
        "Manage optional provider keys stored locally for this user account.",
    )

    rows = provider_status_rows(settings)
    status_df = pd.DataFrame(
        [
            {
                "Provider": row["name"],
                "Tier": row["tier"].title(),
                "Enriches": row["enriches"],
                "Status": row["status"].replace("_", " "),
                "Detail": row["detail"],
            }
            for row in rows
        ]
    )
    st.dataframe(status_df, hide_index=True, use_container_width=True)

    c1, c2 = st.columns(2)
    c1.metric("User .env", str(user_env_path()))
    c2.metric("Recce Pro", "Active" if has_pro_entitlement() else "Inactive")

    fields = [
        ("HIBP_API_KEY", "Have I Been Pwned", settings.hibp_api_key),
        ("HUNTER_API_KEY", "Hunter.io", settings.hunter_api_key),
        ("NUMVERIFY_API_KEY", "NumVerify", settings.numverify_api_key),
        ("EMAILREP_API_KEY", "EmailRep", settings.emailrep_api_key),
        ("COMPANIES_HOUSE_KEY", "Companies House", settings.companies_house_key),
        ("SHODAN_API_KEY", "Shodan", settings.shodan_api_key),
        ("BRAVE_API_KEY", "Brave Search (phone web search)", settings.brave_api_key),
        ("SERPAPI_API_KEY", "SerpAPI (phone web search)", settings.serpapi_api_key),
        ("VIRUSTOTAL_API_KEY", "VirusTotal", settings.virustotal_api_key),
        ("SECURITYTRAILS_API_KEY", "SecurityTrails", settings.securitytrails_api_key),
        ("CENSYS_API_TOKEN", "Censys personal access token", settings.censys_api_token),
        ("CENSYS_ORG_ID", "Censys organization ID (paid plans only)", settings.censys_org_id),
        ("GITHUB_TOKEN", "GitHub token (optional; raises search rate limits)", settings.github_token),
    ]

    with st.form("api_keys_form"):
        theme.section("Provider credentials")
        updates: dict[str, str] = {}
        for env_key, label, current in fields:
            updates[env_key] = st.text_input(
                label,
                value=current or "",
                type="password",
                key=f"api_key_{env_key}",
            ).strip()

        theme.section("Recce Pro entitlement")
        licence_value = st.text_input(
            "Licence token",
            value="",
            type="password",
            placeholder=f"Stored at {pro_licence_path()}",
            key="api_key_pro_licence",
        )
        save = st.form_submit_button("Save", type="primary", use_container_width=True)

    if save:
        path = write_user_env(updates)
        if licence_value.strip():
            write_pro_licence(licence_value)
        st.success(f"Saved provider settings to {path}")
        st.rerun()

    with st.expander("Provider notes", expanded=False):
        st.markdown(
            "- EmailRep works without a key but benefits from higher rate limits when configured.\n"
            "- NumVerify's free tier is HTTP-only and limited; recce warns rather than blocking it.\n"
            "- Shodan is a live Pro-gated provider for domain DNS intelligence; its DNS API needs a "
            "paid Shodan Membership; free keys fall back to host lookups for the IPs the plan allows.\n"
            "- Censys is a live Pro-gated provider: host services and TLS certificate lookups via a "
            "Platform personal access token. Leave the organization ID blank on the free tier.\n"
            "- VirusTotal and SecurityTrails remain Pro-gated placeholders for future live enrichment."
        )


def _username_mode() -> None:
    theme.page_header(
        "Username search",
        "Hunt a username across hundreds of platforms in parallel.",
    )

    with st.form("u_form"):
        target = st.text_input("Username", placeholder="e.g. foldedarrow", key="u_target")
        c1, c2, c3 = st.columns(3)
        nsfw = c1.checkbox("Include NSFW sites", value=False, key="u_nsfw")
        c2.checkbox("Show misses", value=False, key="u_misses")
        c3.checkbox("Show errors", value=False, key="u_errors")
        cats = st.text_input(
            "Filter categories (comma-separated; leave blank for all)",
            placeholder="dev,social,gaming",
            help="Match WMN categories. See sidebar for total counts.",
            key="u_cats",
        )
        excludes = st.text_input(
            "Exclude categories (comma-separated)",
            placeholder="gaming,fandom",
            key="u_excludes",
        )
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    pending = _take_pending_pivot("username")
    if (submitted or pending) and target.strip():
        query = pending.value if pending else target.strip()
        only = {c.strip().lower() for c in cats.split(",") if c.strip()} or None
        exclude = {c.strip().lower() for c in excludes.split(",") if c.strip()} or None
        n_sites = site_count(include_nsfw=nsfw)
        with st.status(f"Hunting **{query}** across {n_sites} sites…", expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=runtime_timeout,
                    max_concurrency=int(runtime_concurrency),
                    proxy=_gui_exit("username").proxy,
                ) as client:
                    return await search_username(
                        query, client,
                        only_categories=only,
                        exclude_categories=exclude,
                        include_nsfw=nsfw,
                        per_domain_rate=float(runtime_per_domain_rate),
                        show_progress=False,
                        settings=settings,
                        fallback_exit=_gui_fallback(),
                    )

            try:
                report = asyncio.run(run())
                append_registry_gate_hits(report, settings)
                if pending:
                    report.pivot = pending.origin
                _mark_searched(report)
                status.update(label=f"Done — {len(report.found)} hit(s).", state="complete")
                st.session_state["u_report"] = report
                record_gui_run(
                    report,
                    {
                        "mode": "username",
                        "pivot": bool(pending),
                        "include_nsfw": nsfw,
                        "only_categories": sorted(only) if only else [],
                        "exclude_categories": sorted(exclude) if exclude else [],
                        "timeout": runtime_timeout,
                        "request_concurrency": int(runtime_concurrency),
                        "per_domain_rate": float(runtime_per_domain_rate),
                        "exit": _gui_exit("username").label, "fallback_exit": _gui_fallback_label(),
                    },
                )
            except ValueError as e:
                status.update(label=str(e), state="error")
                st.error(str(e))
                return

    if "u_report" in st.session_state:
        render_results(
            st.session_state["u_report"],
            show_misses=st.session_state.get("u_misses", False),
            show_errors=st.session_state.get("u_errors", False),
        )
        render_pivot_suggestions(st.session_state["u_report"])


def _email_mode() -> None:
    theme.page_header(
        "Email lookup",
        "Gravatar, MX provider, breach data, optional deep account discovery.",
    )

    with st.form("e_form"):
        target = st.text_input("Email", placeholder="someone@example.com", key="e_target")
        c1, c2, c3 = st.columns(3)
        deep = c1.checkbox(
            "Deep mode (probe ~115 sites)",
            value=False,
            help="Slower (~30–60s). Only run on emails you own — sends real probes to each site's sign-up and sign-in systems.",
            key="e_deep",
        )
        c2.checkbox("Show misses", value=False, key="e_misses")
        c3.checkbox("Show errors", value=False, key="e_errors")
        own_email = st.checkbox(
            "I own this email or have consent",
            value=False,
            help="Required for deep mode.",
            key="e_own",
        )
        d1, d2 = st.columns(2)
        deep_concurrency = d1.number_input(
            "Deep concurrency", min_value=1, max_value=60, value=20, step=1, key="e_deep_concurrency"
        )
        deep_retry = d2.checkbox("Retry rate-limited probes", value=True, key="e_deep_retry")
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    pending = _take_pending_pivot("email")
    if pending:
        # Consent gate: deep probes only ever run on an email the user typed.
        deep = False
    if (submitted or pending) and target.strip():
        query = pending.value if pending else target.strip()
        if deep and active_investigation() is None:
            st.error("Deep mode requires an active case so consent and evidence are recorded.")
            return
        if deep and not own_email:
            st.error("Deep mode requires ownership or consent confirmation.")
            return
        label = f"Looking up **{query}**…"
        if deep:
            label += " _(deep mode — this can take ~30–60s)_"
        with st.status(label, expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=runtime_timeout,
                    max_concurrency=int(runtime_concurrency),
                    proxy=_gui_exit("email").proxy,
                ) as client:
                    r = await search_email(query, client, settings)
                if deep:
                    for hit in await deep_email_probes(
                        query,
                        timeout=runtime_timeout,
                        max_concurrency=int(deep_concurrency),
                        proxy=_gui_exit("email").proxy,
                        retry=deep_retry,
                        show_progress=False,
                    ):
                        r.add(hit)
                    r.finish()
                return r

            try:
                report = asyncio.run(run())
                append_registry_gate_hits(report, settings)
                if pending:
                    report.pivot = pending.origin
                _mark_searched(report)
                status.update(label=f"Done — {len(report.found)} hit(s).", state="complete")
                st.session_state["e_report"] = report
                record_gui_run(
                    report,
                    {
                        "mode": "email",
                        "pivot": bool(pending),
                        "deep": deep,
                        "ownership_or_consent_confirmed": own_email,
                        "deep_concurrency": int(deep_concurrency),
                        "deep_retry": deep_retry,
                        "timeout": runtime_timeout,
                        "request_concurrency": int(runtime_concurrency),
                        "exit": _gui_exit("email").label,
                    },
                )
            except ValueError as e:
                status.update(label=str(e), state="error")
                st.error(str(e))
                return

    if "e_report" in st.session_state:
        render_results(
            st.session_state["e_report"],
            show_misses=st.session_state.get("e_misses", False),
            show_errors=st.session_state.get("e_errors", False),
        )
        render_pivot_suggestions(st.session_state["e_report"])


def _phone_mode() -> None:
    theme.page_header(
        "Phone lookup",
        "Parse, classify, emit clickable manual-pivot links, and (deep mode) build a passive search-engine footprint.",
    )

    regions = ["GB", "US", "IE", "FR", "DE", "ES", "IT", "NL", "AU", "CA", "NZ", "JP"]
    with st.form("p_form"):
        target = st.text_input(
            "Phone number",
            placeholder="+447826916903 or 07826 916903",
            help="International (+44…) is preferred. National format works if you set the region.",
            key="p_target",
        )
        c1, c2, c3 = st.columns(3)
        region = c1.selectbox("Default region", regions, index=0, key="p_region")
        c2.checkbox("Show misses", value=False, key="p_misses")
        c3.checkbox("Show errors", value=False, key="p_errors")
        d1, d2 = st.columns([2, 1])
        deep = d1.checkbox(
            "Deep footprint (passive search-engine OSINT)",
            value=False,
            key="p_deep",
            help="Query DuckDuckGo across number formats + site dorks (socials, classifieds, "
                 "paste sites). Passive — reads public results only. Slower (~10–20s).",
        )
        deep_concurrency = d2.number_input(
            "Deep concurrency", min_value=1, max_value=10, value=4, step=1, key="p_deep_concurrency"
        )
        consent = st.checkbox(
            "I own this number or have consent",
            value=False,
            key="p_consent",
            help="Required for deep mode.",
        )
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    if submitted and target.strip():
        if deep and not consent:
            st.error("Deep mode requires ownership or consent confirmation.")
            return
        label = f"Looking up **{target}**…"
        if deep:
            label += " _(deep mode — this can take ~10–20s)_"
        with st.status(label, expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=runtime_timeout,
                    max_concurrency=int(runtime_concurrency),
                    proxy=_gui_exit("phone").proxy,
                ) as client:
                    return await search_phone(
                        target.strip(),
                        client,
                        settings,
                        default_region=region,
                        deep=deep,
                        deep_concurrency=int(deep_concurrency),
                    )

            try:
                report = asyncio.run(run())
                append_registry_gate_hits(report, settings)
                status.update(label="Done.", state="complete")
                st.session_state["p_report"] = report
                record_gui_run(
                    report,
                    {
                        "mode": "phone",
                        "default_region": region,
                        "deep": deep,
                        "ownership_or_consent_confirmed": consent,
                        "deep_concurrency": int(deep_concurrency),
                        "timeout": runtime_timeout,
                        "request_concurrency": int(runtime_concurrency),
                        "exit": _gui_exit("phone").label,
                    },
                )
            except Exception as e:
                status.update(label=str(e), state="error")
                st.error(str(e))
                return

    if "p_report" in st.session_state:
        render_results(
            st.session_state["p_report"],
            show_misses=st.session_state.get("p_misses", False),
            show_errors=st.session_state.get("p_errors", False),
        )


def _domain_mode() -> None:
    theme.page_header(
        "Domain profile",
        "Ownership, DNS, email infrastructure, web surface, passive subdomains, and company pivots.",
    )

    with st.form("d_form"):
        target = st.text_input("Domain or URL", placeholder="example.com or https://www.example.com", key="d_target")
        c1, c2, c3 = st.columns(3)
        c1.checkbox("Show misses", value=False, key="d_misses")
        c2.checkbox("Show errors", value=False, key="d_errors")
        validate_subs = c3.checkbox("Validate subdomains", value=True, key="d_validate_subs")
        only = st.text_input(
            "Only categories",
            placeholder="ownership,network,email,web,subs,companies,wayback",
            key="d_only",
        )
        exclude = st.text_input("Exclude categories", placeholder="wayback,companies", key="d_exclude")
        bruteforce = st.checkbox(
            "Active subdomain bruteforce",
            value=False,
            help="Sends DNS queries from a wordlist against the target. Requires authorisation.",
            key="d_bruteforce",
        )
        b1, b2, b3 = st.columns(3)
        wordlist_label = b1.selectbox(
            "Wordlist",
            ["small (1k)", "medium (5k)", "big (20k)"],
            index=1,
            key="d_wordlist",
        )
        wordlist = wordlist_label.split(" ", 1)[0]
        brute_concurrency = b2.number_input("Bruteforce concurrency", min_value=1, max_value=200, value=25, step=1, key="d_brute_concurrency")
        brute_rate = b3.number_input("Bruteforce rate", min_value=1, max_value=100, value=10, step=1, key="d_brute_rate")
        authorised = st.checkbox(
            "I am authorised to run active subdomain bruteforce",
            value=False,
            key="d_authorised",
        )
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    if submitted and target.strip():
        if bruteforce and not authorised:
            st.error("Active subdomain bruteforce requires authorisation confirmation.")
            return
        only_set = {c.strip().lower() for c in only.split(",") if c.strip()} or None
        exclude_set = {c.strip().lower() for c in exclude.split(",") if c.strip()} or None
        with st.status(f"Profiling **{target}**…", expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=runtime_timeout,
                    max_concurrency=int(runtime_concurrency),
                    proxy=_gui_exit("domain").proxy,
                ) as client:
                    return await search_domain(
                        target.strip(),
                        client,
                        settings,
                        only_categories=only_set,
                        exclude_categories=exclude_set,
                        bruteforce=bruteforce,
                        authorised=authorised,
                        bruteforce_wordlist=wordlist,
                        bruteforce_concurrency=int(brute_concurrency),
                        bruteforce_rate=int(brute_rate),
                        validate_subs=validate_subs,
                    )

            try:
                report = asyncio.run(run())
                append_registry_gate_hits(report, settings)
                status.update(label=f"Done — {len(report.found)} finding(s).", state="complete")
                st.session_state["d_report"] = report
                record_gui_run(
                    report,
                    {
                        "mode": "domain",
                        "only_categories": sorted(only_set) if only_set else [],
                        "exclude_categories": sorted(exclude_set) if exclude_set else [],
                        "validate_subs": validate_subs,
                        "bruteforce": bruteforce,
                        "i_am_authorised": authorised,
                        "bruteforce_wordlist": wordlist,
                        "bruteforce_concurrency": int(brute_concurrency),
                        "bruteforce_rate": int(brute_rate),
                        "timeout": runtime_timeout,
                        "request_concurrency": int(runtime_concurrency),
                        "exit": _gui_exit("domain").label,
                    },
                )
            except ValueError as e:
                status.update(label=str(e), state="error")
                st.error(str(e))
                return

    if "d_report" in st.session_state:
        render_domain_summary(st.session_state["d_report"])
        render_results(
            st.session_state["d_report"],
            show_misses=st.session_state.get("d_misses", False),
            show_errors=st.session_state.get("d_errors", False),
        )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def render_topbar(current: str) -> None:
    """vantage-style topbar: where you are, then what this run will use."""
    module = current.lower() if current in ("Username", "Email", "Phone", "Domain") else "username"
    inv = active_investigation()
    chips = [
        theme.chip("case", inv["name"], "ok", title=f"Runs are saved to {inv['name']}")
        if inv
        else theme.chip("case", "none", "warn", title="No active case: runs are not saved"),
        theme.chip("exit", _gui_exit(module).label, "accent", title=f"{module} traffic leaves via this exit"),
    ]
    fallback = _gui_fallback_label()
    if fallback and module == "username":
        chips.append(theme.chip("fallback", fallback, title="Bot-walled username probes retry through"))
    chips.append(
        theme.chip(
            "keys", f"{active_count} active", "ok" if active_count else "",
            title=f"{active_count} providers active, {gated_count} Pro gated",
        )
    )
    chips.append(theme.chip("pro", "on" if has_pro_entitlement() else "off", "ok" if has_pro_entitlement() else ""))
    group = MODE_GROUP.get(current, "Search")
    theme.topbar([group, current] if group != current else [current], chips)


render_topbar(mode)

if mode == "Investigations":
    _investigations_mode()
elif mode == "API Keys":
    _api_keys_mode()
elif mode == "Username":
    _username_mode()
elif mode == "Email":
    _email_mode()
elif mode == "Phone":
    _phone_mode()
else:
    _domain_mode()
