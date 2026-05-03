"""Streamlit GUI for recce — three modes (username / email / phone) on top
of the same async modules the CLI uses.

Run via the `recce-gui` console script, which invokes:
    streamlit run recce/gui/app.py
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

import pandas as pd
import streamlit as st

from recce import __version__
from recce.config import Settings
from recce.core.http import http_client
from recce.core.result import Report, Status
from recce.modules.email import search_email
from recce.modules.email_deep import deep_email_probes
from recce.modules.phone import search_phone
from recce.modules.username import search_username, site_count

# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="recce",
    page_icon="🔍",
    layout="wide",
    menu_items={
        "Get help": "https://github.com/foldedarrow/recce",
        "About": f"recce {__version__} — personal OSINT toolkit",
    },
)

# Reduce Streamlit chrome a touch — chunky on small windows.
st.markdown(
    """
    <style>
    .block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
    [data-testid="stSidebar"] {min-width: 240px; max-width: 280px;}
    </style>
    """,
    unsafe_allow_html=True,
)

settings = Settings.load()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("# 🔍 **recce**")
    st.caption(f"v{__version__} — personal OSINT")
    st.divider()

    mode = st.radio(
        "Mode",
        ["Username", "Email", "Phone"],
        horizontal=False,
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("API keys")
    keys = [
        ("HIBP", settings.hibp_api_key, "haveibeenpwned.com/API/Key"),
        ("Hunter", settings.hunter_api_key, "hunter.io/api"),
        ("NumVerify", settings.numverify_api_key, "numverify.com"),
        ("EmailRep", settings.emailrep_api_key, "emailrep.io"),
    ]
    for label, val, url in keys:
        glyph = ":green[✓]" if val else ":red[✗]"
        st.markdown(f"{glyph} **{label}** _{url}_")

    st.divider()
    st.caption("Sites")
    n_default = site_count(include_nsfw=False)
    n_nsfw = site_count(include_nsfw=True) - n_default
    st.markdown(f"**{n_default}** loaded · **{n_nsfw}** NSFW gated")

    if st.button("Refresh WMN data", use_container_width=True):
        from recce.modules.username import refresh_wmn_data

        async def _refresh():
            async with http_client(
                user_agent=settings.user_agent,
                timeout=30.0,
                max_concurrency=2,
            ) as client:
                return await refresh_wmn_data(client)

        with st.spinner("Fetching latest from WhatsMyName…"):
            try:
                before, after = asyncio.run(_refresh())
                st.success(f"WMN refreshed: {before} → {after}")
                st.rerun()
            except Exception as e:  # noqa: BLE001
                st.error(f"Update failed: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STATUS_GLYPH = {
    Status.FOUND: "✅",
    Status.NOT_FOUND: "·",
    Status.UNKNOWN: "❔",
    Status.SKIPPED: "⏸️",
    Status.ERROR: "❌",
}


def report_to_df(report: Report) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for h in report.hits:
        rows.append(
            {
                "": STATUS_GLYPH.get(h.status, ""),
                "Source": h.source,
                "Category": h.category,
                "Status": h.status.value,
                "URL": h.url or "",
                "Notes": h.summary or h.error or "",
                "Confidence": round(h.confidence, 2),
                "ms": h.elapsed_ms or 0,
            }
        )
    return pd.DataFrame(rows)


def render_results(report: Report, *, show_misses: bool, show_errors: bool) -> None:
    found = report.found
    errors = report.errors

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sources checked", len(report.hits))
    c2.metric("Hits", len(found), delta=None)
    c3.metric("Errors", len(errors))
    c4.metric("Elapsed", _elapsed_str(report))

    if found:
        st.subheader("Confirmed hits")
        for h in found:
            with st.container(border=True):
                cols = st.columns([3, 7])
                cols[0].markdown(f"**{h.source}**  \n_{h.category}_")
                detail = ""
                if h.url:
                    detail += f"[{h.url}]({h.url})  \n"
                if h.summary:
                    detail += h.summary
                cols[1].markdown(detail or "_(no detail)_")
    else:
        st.info("No confirmed hits. Try toggling 'Show misses' or 'Show errors' below for the full audit.")

    df = report_to_df(report)
    if not show_misses:
        df = df[df["Status"] != Status.NOT_FOUND.value]
    if not show_errors:
        df = df[df["Status"] != Status.ERROR.value]

    if not df.empty:
        st.subheader("All results")
        st.dataframe(
            df,
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
    dc1.download_button("⬇️ CSV", csv, file_name=f"{base}.csv", mime="text/csv", use_container_width=True)
    dc2.download_button("⬇️ JSON", js, file_name=f"{base}.json", mime="application/json", use_container_width=True)


def _elapsed_str(report: Report) -> str:
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

def _username_mode() -> None:
    st.markdown("## Username search")
    st.caption("Hunt a username across hundreds of platforms in parallel.")

    with st.form("u_form"):
        target = st.text_input("Username", placeholder="e.g. foldedarrow", key="u_target")
        c1, c2, c3 = st.columns(3)
        nsfw = c1.checkbox("Include NSFW sites", value=False, key="u_nsfw")
        show_misses = c2.checkbox("Show misses", value=False, key="u_misses")
        show_errors = c3.checkbox("Show errors", value=False, key="u_errors")
        cats = st.text_input(
            "Filter categories (comma-separated; leave blank for all)",
            placeholder="coding,social,gaming",
            help="Match WMN categories. See sidebar for total counts.",
            key="u_cats",
        )
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    if submitted and target.strip():
        only = {c.strip() for c in cats.split(",") if c.strip()} or None
        n_sites = site_count(include_nsfw=nsfw)
        with st.status(f"Hunting **{target}** across {n_sites} sites…", expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=settings.timeout,
                    max_concurrency=settings.max_concurrency,
                ) as client:
                    return await search_username(
                        target.strip(), client,
                        only_categories=only,
                        include_nsfw=nsfw,
                        show_progress=False,
                    )

            try:
                report = asyncio.run(run())
                status.update(label=f"Done — {len(report.found)} hit(s).", state="complete")
                st.session_state["u_report"] = report
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


def _email_mode() -> None:
    st.markdown("## Email lookup")
    st.caption("Gravatar, MX provider, breach data, optional deep account discovery.")

    with st.form("e_form"):
        target = st.text_input("Email", placeholder="someone@example.com", key="e_target")
        c1, c2, c3 = st.columns(3)
        deep = c1.checkbox(
            "Deep mode (probe ~140 sites)",
            value=False,
            help="Slower (~30–60s). Only run on emails you own — sends real probes to each site's account-recovery system.",
            key="e_deep",
        )
        show_misses = c2.checkbox("Show misses", value=False, key="e_misses")
        show_errors = c3.checkbox("Show errors", value=False, key="e_errors")
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    if submitted and target.strip():
        label = f"Looking up **{target}**…"
        if deep:
            label += " _(deep mode — this can take ~30–60s)_"
        with st.status(label, expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=settings.timeout,
                    max_concurrency=settings.max_concurrency,
                ) as client:
                    r = await search_email(target.strip(), client, settings)
                if deep:
                    for hit in await deep_email_probes(target.strip(), timeout=settings.timeout, show_progress=False):
                        r.add(hit)
                return r

            try:
                report = asyncio.run(run())
                status.update(label=f"Done — {len(report.found)} hit(s).", state="complete")
                st.session_state["e_report"] = report
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


def _phone_mode() -> None:
    st.markdown("## Phone lookup")
    st.caption("Parse, classify, and emit clickable manual-pivot links (WhatsApp, Truecaller, Sync.me, Google web search).")

    REGIONS = ["GB", "US", "IE", "FR", "DE", "ES", "IT", "NL", "AU", "CA", "NZ", "JP"]
    with st.form("p_form"):
        target = st.text_input(
            "Phone number",
            placeholder="+447826916903 or 07826 916903",
            help="International (+44…) is preferred. National format works if you set the region.",
            key="p_target",
        )
        c1, c2, c3 = st.columns(3)
        region = c1.selectbox("Default region", REGIONS, index=0, key="p_region")
        show_misses = c2.checkbox("Show misses", value=False, key="p_misses")
        show_errors = c3.checkbox("Show errors", value=False, key="p_errors")
        submitted = st.form_submit_button("Run", type="primary", use_container_width=True)

    if submitted and target.strip():
        with st.status(f"Looking up **{target}**…", expanded=False) as status:
            async def run() -> Report:
                async with http_client(
                    user_agent=settings.user_agent,
                    timeout=settings.timeout,
                    max_concurrency=settings.max_concurrency,
                ) as client:
                    return await search_phone(target.strip(), client, settings, default_region=region)

            try:
                report = asyncio.run(run())
                status.update(label="Done.", state="complete")
                st.session_state["p_report"] = report
            except Exception as e:  # noqa: BLE001
                status.update(label=str(e), state="error")
                st.error(str(e))
                return

    if "p_report" in st.session_state:
        render_results(
            st.session_state["p_report"],
            show_misses=st.session_state.get("p_misses", False),
            show_errors=st.session_state.get("p_errors", False),
        )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

if mode == "Username":
    _username_mode()
elif mode == "Email":
    _email_mode()
else:
    _phone_mode()
