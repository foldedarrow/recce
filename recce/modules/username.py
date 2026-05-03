"""Username search across many platforms.

Two site sources are merged at load time:

1. **WhatsMyName** (`wmn-data.json`) — the canonical community-maintained
   list (~700+ sites). The schema defines paired-marker detection via
   `e_code` + `e_string` + `m_code` + `m_string`: an account *exists* iff
   `status == e_code AND e_string in body AND m_string NOT in body`.
   Live updates fetched via `recce update` land in `~/.cache/recce/`.

2. **recce custom sites** (`custom_sites.json`) — a small bespoke list of
   probes that don't fit the WMN schema (multi-instance Mastodon, Bluesky's
   AT-Proto API, redirect-marker detection for Bandcamp/Substack/Wordpress,
   HEAD-request quirks for Kaggle/Dailymotion). Custom entries override
   WMN ones with the same name.

Detection methods supported:
- ``wmn``           paired markers (FOUND iff e_code + e_string ∧ ¬m_string)
- ``status``        HTTP status code list
- ``absent``        body must NOT contain a marker
- ``present``       body MUST contain a marker
- ``redirect_match`` Location header substring
- ``post_json``     JSON POST + body marker
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from importlib import resources
from pathlib import Path
from typing import Any

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..core.http import HttpClient
from ..core.output import console
from ..core.result import Hit, Report, Status

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,38}$")
NSFW_CAT_RE = re.compile(r"\bnsfw\b", re.IGNORECASE)

CACHE_DIR = Path.home() / ".cache" / "recce"
CACHED_WMN = CACHE_DIR / "wmn-data.json"


def _format(value: str, username: str) -> str:
    return value.replace("{u}", username)


# ---------------------------------------------------------------------------
# Site loading
# ---------------------------------------------------------------------------

def _wmn_to_recce(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Translate a WhatsMyName site entry into recce's internal schema."""
    if entry.get("valid") is False:
        return None
    uri_check = entry.get("uri_check")
    if not uri_check:
        return None
    probe = uri_check.replace("{account}", "{u}")
    pretty = (entry.get("uri_pretty") or uri_check).replace("{account}", "{u}")
    site: dict[str, Any] = {
        "name": entry["name"],
        "category": entry.get("cat", "misc"),
        "url": pretty,
        "probe": probe,
        "method": "wmn",
        "e_code": entry.get("e_code"),
        "e_string": entry.get("e_string"),
        "m_code": entry.get("m_code"),
        "m_string": entry.get("m_string"),
    }
    if entry.get("headers"):
        site["headers"] = entry["headers"]
    if entry.get("post_body"):
        post = entry["post_body"]
        try:
            parsed_post = json.loads(post) if isinstance(post, str) else post
        except json.JSONDecodeError:
            parsed_post = post
        if isinstance(parsed_post, dict):
            site["post_body"] = parsed_post
            site["method"] = "wmn_post"
    if entry.get("known"):
        site["known"] = entry["known"]
    if entry.get("strip_bad_char"):
        site["strip_bad_char"] = entry["strip_bad_char"]
    return site


def _load_wmn_sites() -> list[dict[str, Any]]:
    """Load WMN sites — prefer the user's cached refresh over the bundled snapshot."""
    if CACHED_WMN.exists():
        raw = CACHED_WMN.read_text()
    else:
        raw = resources.files("recce.data").joinpath("wmn-data.json").read_text()
    data = json.loads(raw)
    out: list[dict[str, Any]] = []
    for entry in data.get("sites", []):
        translated = _wmn_to_recce(entry)
        if translated is not None:
            out.append(translated)
    return out


def _load_custom_sites() -> list[dict[str, Any]]:
    raw = resources.files("recce.data").joinpath("custom_sites.json").read_text()
    data = json.loads(raw)
    return list(data.get("sites", []))


def _load_sites(*, include_nsfw: bool = False) -> list[dict[str, Any]]:
    """Merge WMN + recce custom sites. Custom entries override by `name`."""
    wmn_sites = _load_wmn_sites()
    custom_sites = _load_custom_sites()
    custom_names = {s["name"] for s in custom_sites}
    merged = [s for s in wmn_sites if s["name"] not in custom_names] + custom_sites

    if not include_nsfw:
        merged = [s for s in merged if not NSFW_CAT_RE.search(s.get("category", ""))]

    return merged


def site_count(*, include_nsfw: bool = False) -> int:
    return len(_load_sites(include_nsfw=include_nsfw))


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def _classify(
    site: dict[str, Any],
    status_code: int,
    body: str,
    username: str,
    location: str = "",
) -> tuple[Status, str | None]:
    method = site["method"]

    if method in ("wmn", "wmn_post"):
        e_code = site.get("e_code")
        m_code = site.get("m_code")
        e_string = site.get("e_string") or ""
        m_string = site.get("m_string") or ""
        e_match = (e_code is None or status_code == e_code) and (
            not e_string or e_string in body
        )
        m_match = (m_code is None or status_code == m_code) and (
            not m_string or m_string in body
        )
        # Strict: account exists iff existence signal AND not missing signal.
        if e_match and not m_match:
            return Status.FOUND, None
        if m_match and not e_match:
            return Status.NOT_FOUND, None
        if e_match and m_match:
            return Status.UNKNOWN, "ambiguous markers"
        if status_code in (404, 410):
            return Status.NOT_FOUND, None
        return Status.UNKNOWN, f"HTTP {status_code}"

    if method == "status":
        if status_code in site.get("found", [200]):
            return Status.FOUND, None
        if status_code in site.get("missing", [404]):
            return Status.NOT_FOUND, None
        return Status.UNKNOWN, f"HTTP {status_code}"

    if method == "absent":
        marker = _format(site["marker"], username)
        if status_code >= 500:
            return Status.UNKNOWN, f"HTTP {status_code}"
        if status_code in (404, 410):
            return Status.NOT_FOUND, None
        if marker.lower() in body.lower():
            return Status.NOT_FOUND, None
        if status_code in (200, 301, 302):
            return Status.FOUND, None
        return Status.UNKNOWN, f"HTTP {status_code}"

    if method == "present":
        marker = _format(site["marker"], username)
        if status_code >= 400:
            return Status.NOT_FOUND, None
        haystack = body.lower() if site.get("case_insensitive") else body
        needle = marker.lower() if site.get("case_insensitive") else marker
        if needle in haystack:
            return Status.FOUND, None
        return Status.NOT_FOUND, None

    if method == "post_json":
        marker = _format(site["marker"], username)
        if status_code >= 400:
            return Status.NOT_FOUND, None
        if marker in body:
            return Status.FOUND, None
        return Status.NOT_FOUND, None

    if method == "redirect_match":
        missing_marker = _format(site.get("missing_location", ""), username)
        if status_code in (404, 410):
            return Status.NOT_FOUND, None
        if missing_marker and missing_marker in location:
            return Status.NOT_FOUND, None
        if status_code in (200, 301, 302, 303, 307, 308):
            return Status.FOUND, None
        return Status.UNKNOWN, f"HTTP {status_code}"

    return Status.UNKNOWN, f"unknown method '{method}'"


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

async def _check_site(client: HttpClient, site: dict[str, Any], username: str) -> Hit:
    if site.get("strip_bad_char"):
        for ch in site["strip_bad_char"]:
            username = username.replace(ch, "")
    profile_url = _format(site["url"], username)
    probe_url = _format(site.get("probe", site["url"]), username)
    headers = site.get("headers")
    method = site["method"]
    follow_redirects = not site.get("no_redirect", False)
    use_head = site.get("head_request", False)
    started = time.perf_counter()

    try:
        if method == "wmn_post":
            payload = json.loads(_format(json.dumps(site["post_body"]), username))
            resp = await client.post(probe_url, json=payload, headers=headers,
                                     follow_redirects=follow_redirects)
        elif method == "post_json":
            payload = json.loads(_format(json.dumps(site["post"]), username))
            resp = await client.post(probe_url, json=payload, headers=headers,
                                     follow_redirects=follow_redirects)
        elif use_head:
            resp = await client.head(probe_url, headers=headers,
                                     follow_redirects=follow_redirects)
        else:
            resp = await client.get(probe_url, headers=headers,
                                    follow_redirects=follow_redirects)
    except Exception as e:  # noqa: BLE001
        return Hit(
            source=site["name"],
            category=site.get("category", "general"),
            status=Status.ERROR,
            url=profile_url,
            error=str(e)[:120],
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return Hit(
            source=site["name"],
            category=site.get("category", "general"),
            status=Status.ERROR,
            url=profile_url,
            error="network error / timeout",
            elapsed_ms=elapsed_ms,
        )

    needs_body = method not in ("status", "redirect_match")
    body = resp.text if needs_body else ""
    location = resp.headers.get("Location", "")
    status, note = _classify(site, resp.status_code, body, username, location=location)
    confidence = {
        Status.FOUND: 0.85,
        Status.NOT_FOUND: 0.9,
        Status.UNKNOWN: 0.3,
        Status.ERROR: 0.0,
    }.get(status, 0.5)

    return Hit(
        source=site["name"],
        category=site.get("category", "general"),
        status=status,
        url=profile_url,
        summary=note,
        confidence=confidence,
        elapsed_ms=elapsed_ms,
    )


async def search_username(
    username: str,
    client: HttpClient,
    *,
    only_categories: set[str] | None = None,
    exclude_categories: set[str] | None = None,
    include_nsfw: bool = False,
    show_progress: bool = True,
) -> Report:
    if not USERNAME_RE.match(username):
        raise ValueError(
            "Username must be 1–39 chars, start alphanumeric, and contain only letters, digits, '.', '_' or '-'."
        )

    sites = _load_sites(include_nsfw=include_nsfw)
    if only_categories:
        sites = [s for s in sites if s.get("category", "general") in only_categories]
    if exclude_categories:
        sites = [s for s in sites if s.get("category", "general") not in exclude_categories]

    report = Report(query=username, query_type="username")

    if not show_progress:
        results = await asyncio.gather(*(_check_site(client, s, username) for s in sites))
        for r in results:
            report.add(r)
        return report

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[bold]{task.completed}/{task.total}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Hunting [bold]{username}[/] across {len(sites)} sites…",
            total=len(sites),
        )

        async def runner(site: dict[str, Any]) -> Hit:
            hit = await _check_site(client, site, username)
            progress.advance(task)
            return hit

        results = await asyncio.gather(*(runner(s) for s in sites))
        for r in results:
            report.add(r)

    return report


# ---------------------------------------------------------------------------
# Update command
# ---------------------------------------------------------------------------

WMN_REMOTE = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"


async def refresh_wmn_data(client: HttpClient) -> tuple[int, int]:
    """Fetch the latest wmn-data.json from upstream and cache it.

    Returns (site_count_before, site_count_after).
    """
    before = len(_load_wmn_sites())
    resp = await client.get(WMN_REMOTE)
    if resp is None or resp.status_code != 200:
        code = "?" if resp is None else resp.status_code
        raise RuntimeError(f"WMN download failed (HTTP {code})")
    payload = resp.text
    # Validate it parses cleanly before writing.
    parsed = json.loads(payload)
    if "sites" not in parsed or not isinstance(parsed["sites"], list):
        raise RuntimeError("WMN response is not in the expected shape")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHED_WMN.write_text(payload)
    after = len([s for s in parsed["sites"] if s.get("valid", True) is not False])
    return before, after
