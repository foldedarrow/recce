# SPDX-License-Identifier: AGPL-3.0-or-later
"""The GUI's look: vantage's "Gotham" console theme, carried over to Streamlit.

Dark, minimal, typography-forward. Near-black blue-slate, hairline structure,
one reserved steel-blue accent, semantic colour kept for status only. The
token values are vantage's (webui/static/vantage.css) so the two consoles on
the same box read as one family.

Streamlit draws its own widgets, so this is one stylesheet aimed at their
`data-testid` hooks plus a few HTML helpers (brand, topbar, headings, cards).
The launcher passes the matching base theme (THEME_FLAGS) so the parts CSS
can't reach -- the canvas-drawn data grids -- use the same colours.

Every helper that takes text escapes it: hit summaries and URLs come from
the sites being searched.
"""

from __future__ import annotations

from html import escape
from typing import Literal

import streamlit as st

BG = "#0b0f14"
PANEL = "#12181f"
FG = "#c7d1db"
ACCENT = "#6ea8d8"

# `streamlit run` flags for the base theme (all exist in Streamlit 1.40).
THEME_FLAGS: tuple[str, ...] = (
    "--theme.base", "dark",
    "--theme.primaryColor", ACCENT,
    "--theme.backgroundColor", BG,
    "--theme.secondaryBackgroundColor", PANEL,
    "--theme.textColor", FG,
)

Tone = Literal["", "ok", "warn", "crit", "accent"]

CSS = """
:root {
  --bg: #0b0f14; --bg-inset: #080b10; --panel: #12181f; --panel-2: #161d26;
  --sidebar: #0d1219;
  --line: #1e2831; --line-2: #26333f;
  --fg: #c7d1db; --fg-strong: #e6edf3; --muted: #64727f; --faint: #45505b;
  --accent: #6ea8d8; --accent-2: #8fc0e8; --accent-dim: #3a5f7d; --accent-line: #33506b;
  --accent-bg: rgba(110,168,216,.09); --accent-bg-2: rgba(110,168,216,.16);
  --crit: #e5484d; --high: #f0883e; --med: #d6a531; --ok: #3fb37f;
  --crit-bg: rgba(229,72,77,.12); --high-bg: rgba(240,136,62,.12); --ok-bg: rgba(63,179,127,.12);
  --sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "SFMono-Regular", "SF Mono", "JetBrains Mono", Menlo, Consolas, "Roboto Mono", monospace;
  --radius: 5px; --radius-sm: 3px;
}

/* ---- base ---------------------------------------------------------------- */
.stApp { background: var(--bg); color: var(--fg); }
/* Material icons are text in an icon font (stIconMaterial, stExpanderIconCheck, ...,
   all translate="no"); a font override on them prints the icon's name instead. */
.stApp :is(p, li, label, span, div, button, input, textarea, a, td, th):not([data-testid*="Icon"]):not([translate="no"]) {
  font-family: var(--sans);
}
.stApp :is(code, kbd, pre, input, textarea, .r-mono, .r-chip, .r-pill),
.stApp :is(code, kbd, pre) * { font-family: var(--mono) !important; }
.stApp p, .stApp li { font-size: 13.5px; line-height: 1.55; }
.stApp a { color: var(--accent); text-decoration: none; }
.stApp a:hover { color: var(--accent-2); }
::selection { background: var(--accent-bg-2); color: var(--fg-strong); }
* { scrollbar-width: thin; scrollbar-color: #223040 transparent; }
.stApp code { background: var(--bg-inset); border: 1px solid var(--line); border-radius: 3px;
  padding: 1px 5px; color: var(--accent-2); font-size: 12px; }

/* Streamlit chrome: keep the header (it holds the sidebar toggle), lose the rest */
[data-testid="stHeader"] { background: transparent; height: 2.5rem; }
[data-testid="stDecoration"], [data-testid="stAppDeployButton"], .stDeployButton { display: none; }
[data-testid="stMainBlockContainer"], .block-container {
  max-width: 1240px; padding: 1rem 1.7rem 4rem;
}
[data-testid="stVerticalBlock"] { gap: .75rem; }

/* ---- sidebar rail ---------------------------------------------------------- */
[data-testid="stSidebar"] { background: var(--sidebar); border-right: 1px solid var(--line);
  min-width: 248px; max-width: 248px; }
[data-testid="stSidebarHeader"] { height: 2.25rem; padding: .25rem .75rem 0; margin: 0; }
[data-testid="stSidebarContent"] { padding-left: 0; padding-right: 0; }
[data-testid="stSidebarUserContent"] { padding: 0 .65rem 1.5rem; }
[data-testid="stSidebar"] hr { margin: .6rem 0; border-color: var(--line); }

.r-brand { display: flex; align-items: center; gap: 9px; padding: 2px 8px 14px;
  margin: 0 -.65rem 4px; padding-left: calc(8px + .65rem); padding-right: calc(8px + .65rem);
  border-bottom: 1px solid var(--line); }
.r-brand .mark { width: 22px; height: 22px; flex: 0 0 22px; position: relative;
  border: 1px solid var(--accent-line); border-radius: var(--radius-sm); background: var(--accent-bg); }
.r-brand .mark::before { content: ""; position: absolute; inset: 5px; border-radius: 50%;
  border: 2px solid var(--accent); }
.r-brand .mark::after { content: ""; position: absolute; width: 5px; height: 2px; right: 2px; bottom: 4px;
  background: var(--accent); transform: rotate(45deg); }
.r-brand .name { font-weight: 600; letter-spacing: .14em; text-transform: uppercase; font-size: 13px;
  color: var(--fg-strong); }
.r-brand .ver { font-family: var(--mono); font-size: 10px; color: var(--faint); margin-left: auto; }

.r-group { color: var(--faint); font-size: 10px; letter-spacing: .13em; text-transform: uppercase;
  padding: 14px 10px 6px; }
.r-foot { color: var(--faint); font-size: 11px; padding: 12px 6px 0; margin-top: 10px;
  border-top: 1px solid var(--line); }

/* the Mode radio, drawn as vantage's nav list (group labels hang off item 2 and 6) */
.st-key-mode [role="radiogroup"] { gap: 1px; padding-top: 2px; }
.st-key-mode [role="radiogroup"] > label {
  position: relative; margin: 0; padding: 7px 10px; border-radius: var(--radius-sm);
  border: 1px solid transparent; transition: background .12s, color .12s; cursor: pointer; width: 100%;
}
.st-key-mode [role="radiogroup"] > label > div:first-child { display: none; }  /* the dot */
.st-key-mode [role="radiogroup"] > label p { color: var(--muted); font-size: 13px; letter-spacing: .01em; }
.st-key-mode [role="radiogroup"] > label [data-testid="stIconMaterial"] { font-size: 16px;
  margin-right: 6px; opacity: .8; }
.st-key-mode [role="radiogroup"] > label:hover { background: var(--panel); }
.st-key-mode [role="radiogroup"] > label:hover p { color: var(--fg); }
.st-key-mode [role="radiogroup"] > label:has(input:checked) {
  background: var(--accent-bg); border-color: var(--accent-line); }
.st-key-mode [role="radiogroup"] > label:has(input:checked) p { color: var(--accent-2); }
.st-key-mode [role="radiogroup"] > label:nth-child(2),
.st-key-mode [role="radiogroup"] > label:nth-child(6) { margin-top: 30px; }
.st-key-mode [role="radiogroup"] > label:nth-child(2)::before,
.st-key-mode [role="radiogroup"] > label:nth-child(6)::before {
  position: absolute; left: 10px; top: -22px; color: var(--faint); font-size: 10px;
  letter-spacing: .13em; text-transform: uppercase; pointer-events: none;
}
.st-key-mode [role="radiogroup"] > label:nth-child(2)::before { content: "Search"; }
.st-key-mode [role="radiogroup"] > label:nth-child(6)::before { content: "System"; }

/* ---- topbar ---------------------------------------------------------------- */
.r-topbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  margin: -.25rem 0 18px; padding: 0 5.5rem 12px 0; border-bottom: 1px solid var(--line); }
.r-topbar .crumb { font-size: 13px; color: var(--fg-strong); letter-spacing: .01em; margin-right: auto; }
.r-topbar .crumb .sep { color: var(--faint); margin: 0 8px; }
.r-topbar .crumb .grp { color: var(--muted); }
.r-chip { display: inline-flex; align-items: center; gap: 7px; font-size: 11px; color: var(--muted);
  border: 1px solid var(--line); border-radius: 20px; padding: 4px 11px; background: var(--panel);
  white-space: nowrap; max-width: 320px; overflow: hidden; text-overflow: ellipsis; }
.r-chip .dot { width: 7px; height: 7px; flex: 0 0 7px; border-radius: 50%; background: var(--muted); }
.r-chip b { color: var(--fg); font-weight: 500; }
.r-chip.ok .dot { background: var(--ok); }
.r-chip.accent .dot { background: var(--accent); }
.r-chip.warn { color: var(--high); border-color: rgba(240,136,62,.35); }
.r-chip.warn .dot { background: var(--high); }

/* ---- headings ------------------------------------------------------------- */
.r-h1 { font-size: 20px; font-weight: 600; letter-spacing: .01em; color: var(--fg-strong); margin: 0 0 4px; }
.r-sub { color: var(--muted); font-size: 13px; margin: 0 0 8px; }
.r-h2 { font-size: 12px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase;
  color: var(--muted); margin: 22px 0 2px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
.r-h2 .n { font-family: var(--mono); color: var(--faint); letter-spacing: 0; margin-left: 8px; font-weight: 400; }
.r-meta { display: flex; flex-wrap: wrap; gap: 6px 14px; color: var(--muted); font-size: 11.5px;
  font-family: var(--mono); }
.r-meta .k { color: var(--faint); text-transform: uppercase; letter-spacing: .08em; font-size: 10px;
  font-family: var(--sans); margin-right: 6px; }
[data-testid="stCaptionContainer"], .stCaption { color: var(--muted) !important; }
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p { font-size: 11.5px; }
[data-testid="stHeadingWithActionElements"] h3 { font-size: 14px; color: var(--fg-strong); }

/* ---- stats (st.metric) ----------------------------------------------------- */
[data-testid="stMetric"] { padding: 2px 0; }
[data-testid="stMetricLabel"] p { font-size: 10px !important; letter-spacing: .1em; text-transform: uppercase;
  color: var(--faint) !important; }
[data-testid="stMetricValue"] > div, [data-testid="stMetricValue"] { font-family: var(--mono) !important;
  font-size: 20px !important; font-weight: 600; color: var(--fg-strong); line-height: 1.15; }

/* ---- cards ---------------------------------------------------------------- */
.r-card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 12px 16px; margin: 0 0 6px; transition: border-color .14s, background .14s; }
.r-card:hover { border-color: var(--line-2); background: var(--panel-2); }
.r-card.accent { border-left: 2px solid var(--accent); }
.r-card .hd { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.r-card .src { font-size: 14px; font-weight: 600; color: var(--fg-strong); }
.r-card .url { display: block; font-family: var(--mono); font-size: 12px; margin-top: 6px;
  word-break: break-all; }
.r-card .sum { color: var(--fg); font-size: 13px; margin-top: 5px; line-height: 1.55; word-break: break-word; }
.r-card .sig { color: var(--muted); font-size: 12px; margin-top: 4px; }
.r-card .sig::before { content: "\\2014"; color: var(--faint); margin-right: 7px; }
.r-pill { display: inline-flex; align-items: center; gap: 5px; font-size: 10.5px; letter-spacing: .04em;
  text-transform: uppercase; padding: 2px 8px; border-radius: 3px; border: 1px solid var(--line-2);
  color: var(--muted); background: var(--panel-2); }
.r-pill.accent { color: var(--accent); border-color: var(--accent-line); }
.r-pill.ok { color: var(--ok); border-color: rgba(63,179,127,.45); background: var(--ok-bg); }
.r-pill.warn { color: var(--high); border-color: rgba(240,136,62,.45); background: var(--high-bg); }
.r-pill.crit { color: var(--crit); border-color: rgba(229,72,77,.45); background: var(--crit-bg); }

/* bordered st.container */
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) {
  border-color: var(--line) !important; border-radius: var(--radius); }
[data-testid="stForm"] { border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--panel); padding: 14px 18px 16px; }

/* ---- buttons ----------------------------------------------------------------- */
.stApp button[data-testid^="stBaseButton"] { border-radius: var(--radius-sm); font-size: 12.5px;
  font-weight: 500; letter-spacing: .02em; transition: .12s; min-height: 36px; }
.stApp button[data-testid^="stBaseButton-secondary"] { color: var(--fg); background: var(--panel-2);
  border: 1px solid var(--line-2); }
.stApp button[data-testid^="stBaseButton-secondary"]:hover { background: #1c2530; color: var(--fg-strong);
  border-color: var(--line-2); }
.stApp button[data-testid^="stBaseButton-primary"] { color: var(--accent-2); background: var(--accent-bg);
  border: 1px solid var(--accent-line); }
.stApp button[data-testid^="stBaseButton-primary"]:hover { background: var(--accent-bg-2);
  color: var(--accent-2); border-color: var(--accent-line); }
.stApp button[data-testid^="stBaseButton"] p { font-size: 12.5px; font-weight: 500; }
.stApp button[data-testid^="stBaseButton"]:focus:not(:active) { border-color: var(--accent-line);
  box-shadow: 0 0 0 1px var(--accent-line); color: inherit; }
[data-testid="stDownloadButton"] button { color: var(--fg); }

/* ---- inputs ------------------------------------------------------------------ */
.stApp [data-baseweb="input"], .stApp [data-baseweb="base-input"], .stApp [data-baseweb="textarea"],
.stApp [data-baseweb="select"] > div {
  background: var(--bg-inset) !important; border-color: var(--line) !important; border-radius: var(--radius-sm); }
.stApp [data-baseweb="input"]:focus-within, .stApp [data-baseweb="textarea"]:focus-within,
.stApp [data-baseweb="select"] > div:focus-within {
  border-color: var(--accent-line) !important; box-shadow: 0 0 0 1px var(--accent-line); }
.stApp input, .stApp textarea { color: var(--fg) !important; font-size: 13px !important; background: transparent !important; }
.stApp input::placeholder, .stApp textarea::placeholder { color: var(--faint) !important; }
.stApp [data-baseweb="select"] div { font-size: 13px; }
.stApp [data-testid="stWidgetLabel"] p { font-size: 11px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--muted); }
.stApp [data-testid="stCheckbox"] [data-testid="stWidgetLabel"] p,
.stApp [data-testid="stCheckbox"] label p { text-transform: none; letter-spacing: 0; font-size: 13px; color: var(--fg); }
[data-testid="stNumberInputContainer"] button { background: var(--panel-2); border-color: var(--line); }

/* ---- alerts: vantage callouts --------------------------------------------- */
[data-testid="stAlertContainer"] { background: var(--panel) !important; border: 1px solid var(--line);
  border-left: 2px solid var(--accent); border-radius: var(--radius); color: var(--fg); padding: 10px 14px; }
[data-testid="stAlertContainer"] p { color: var(--fg); font-size: 13px; }
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]) { border-left-color: var(--ok); }
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]) { border-left-color: var(--high); }
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]) { border-left-color: var(--crit); }
[data-testid="stAlertContainer"] [data-testid="stIconMaterial"] { color: var(--muted); }

/* ---- expanders: vantage's collapsible sections ---------------------------- */
[data-testid="stExpander"] details { background: var(--panel); border: 1px solid var(--line);
  border-radius: var(--radius); }
[data-testid="stExpander"] summary { padding: 9px 14px; }
[data-testid="stExpander"] summary p { font-size: 10.5px; letter-spacing: .13em; text-transform: uppercase;
  color: var(--muted); }
[data-testid="stExpander"] details[open] > summary { border-bottom: 1px solid var(--line); }
[data-testid="stExpander"] details[open] > summary p { color: var(--fg); }
[data-testid="stSidebar"] [data-testid="stExpander"] details { background: transparent; }
[data-testid="stSidebar"] [data-testid="stForm"] { border: 0; background: transparent; padding: 0; }
[data-testid="stSidebar"] [data-testid="stExpanderDetails"] { padding: 8px 10px 12px; }

/* ---- tables --------------------------------------------------------------- */
[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: var(--radius); }
.stApp [data-testid="stTable"] table, .stApp .stMarkdown table { font-family: var(--mono); font-size: 12.5px; }

/* toasts */
[data-testid="stToast"] { background: var(--panel-2); border: 1px solid var(--line-2); }

@media (max-width: 820px) {
  [data-testid="stMainBlockContainer"], .block-container { padding: .75rem 1rem 3rem; }
  .r-topbar { padding: 0 2.5rem 12px 0; }
  .r-topbar .crumb { flex-basis: 100%; padding-left: 2.25rem; }  /* clear the sidebar toggle */
}
"""


def apply() -> None:
    """Inject the stylesheet. Call once per run, right after set_page_config."""
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


def _t(text: object) -> str:
    """Escaped, on one line. A blank line inside st.markdown's raw HTML would end the
    HTML block and hand the rest of a site's text to the markdown parser."""
    return escape(" ".join(str(text).split()))


def html(markup: str) -> None:
    """Render trusted markup built by these helpers (they escape their inputs)."""
    st.markdown(markup, unsafe_allow_html=True)


def brand(version: str) -> None:
    html(
        '<div class="r-brand"><span class="mark"></span><span class="name">recce</span>'
        f'<span class="ver">v{escape(version)}</span></div>'
    )


def group(label: str) -> None:
    """A small uppercase sidebar group label (vantage's `.nav .group`)."""
    html(f'<div class="r-group">{escape(label)}</div>')


def foot(text: str) -> None:
    html(f'<div class="r-foot">{escape(text)}</div>')


def chip(label: str, value: str = "", tone: Tone = "", title: str = "") -> str:
    """One topbar status chip: a dot, a bold label, then a value."""
    value_html = f" · {_t(value)}" if value else ""
    tip = title or (f"{label} · {value}" if value else label)
    return (
        f'<span class="r-chip {tone}" title="{_t(tip)}">'
        f'<span class="dot"></span><b>{_t(label)}</b>{value_html}</span>'
    )


def topbar(crumbs: list[str], chips: list[str]) -> None:
    """Breadcrumb on the left, status chips on the right (chips come from `chip`)."""
    parts = [f'<span class="grp">{_t(c)}</span>' for c in crumbs[:-1]] + [_t(crumbs[-1])]
    crumb = '<span class="sep">/</span>'.join(parts)
    html(f'<div class="r-topbar"><span class="crumb">{crumb}</span>{"".join(chips)}</div>')


def page_header(title: str, sub: str = "") -> None:
    sub_html = f'<div class="r-sub">{_t(sub)}</div>' if sub else ""
    html(f'<div class="r-h1">{_t(title)}</div>{sub_html}')


def section(title: str, count: int | None = None) -> None:
    """Uppercase section label with a hairline under it (vantage's h2)."""
    n = f'<span class="n">{count}</span>' if count is not None else ""
    html(f'<div class="r-h2">{_t(title)}{n}</div>')


def meta(items: list[tuple[str, str]]) -> None:
    """A line of `KEY value` pairs in mono."""
    body = "".join(f'<span><span class="k">{_t(k)}</span>{_t(v)}</span>' for k, v in items if v)
    if body:
        html(f'<div class="r-meta">{body}</div>')


def pill(text: str, tone: Tone = "") -> str:
    return f'<span class="r-pill {tone}">{_t(text)}</span>'


def safe_url(url: str | None) -> str | None:
    """`url` if it is http(s) with no whitespace, else None -- never put another scheme
    (javascript:, data:) in an href."""
    if url and url.lower().startswith(("http://", "https://")) and not any(c.isspace() for c in url):
        return url
    return None


def link(url: str | None, text: str | None = None) -> str:
    href = safe_url(url)
    label = _t(text if text is not None else (url or ""))
    if href is None:
        return f'<span class="r-mono">{label}</span>'
    return f'<a href="{escape(href)}" target="_blank" rel="noopener noreferrer">{label}</a>'


def card(
    title: str,
    *,
    pills: list[str] | None = None,
    url: str | None = None,
    body: str | None = None,
    signals: list[str] | None = None,
    accent: bool = False,
) -> str:
    """A result card's markup. `pills` are pre-rendered (from `pill`); everything else is
    escaped here. Join a list of them into one `html` call: one element per card is slow
    on runs with hundreds of hits."""
    head = f'<span class="src">{_t(title)}</span>' + "".join(pills or [])
    url_html = f'<span class="url">{link(url)}</span>' if url else ""
    body_html = f'<div class="sum">{_t(body)}</div>' if body else ""
    sig_html = "".join(f'<div class="sig">{_t(s)}</div>' for s in signals or [])
    cls = "r-card accent" if accent else "r-card"
    return f'<div class="{cls}"><div class="hd">{head}</div>{url_html}{body_html}{sig_html}</div>'
