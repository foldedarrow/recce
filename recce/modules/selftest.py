# SPDX-License-Identifier: AGPL-3.0-or-later
"""Site definition health: `recce selftest`.

Every username site definition is probed twice through the same
`_check_site` path a real search uses: once with a ``known`` account (WMN
ships these; custom sites carry their own or borrow WMN's for the same
platform) and once with a random canary username. The pair classifies the
definition:

- ``healthy``         known account FOUND, canary NOT_FOUND
- ``false_positive``  canary FOUND — the site "finds" any username
- ``false_negative``  known account NOT_FOUND — detection is broken
- ``blocked``         401/403/429 or a bot-challenge page. Depends on the
                      egress IP, so it is recorded but never treated as broken
- ``error``           transport errors, 5xx, ambiguous markers
- ``unverified``      no known account; the canary came back clean

Results persist to ``~/.cache/recce/selftest.json``. Username searches read
that file and skip definitions whose last selftest was a false positive (see
`search_flags`), unless overridden with ``--flagged-sites`` or
``RECCE_FLAGGED_SITES``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..core.http import HttpClient, ImpersonatingClient, impersonation_available
from ..core.result import Hit, Status
from .username import (
    CACHE_DIR,
    DEFAULT_PER_DOMAIN_RATE,
    GUARDED_HTTP_STATUSES,
    PerDomainThrottle,
    _canary_username,
    _check_site,
    _load_sites,
    _load_wmn_sites,
)

SELFTEST_PATH = CACHE_DIR / "selftest.json"
SCHEMA_VERSION = 1

HEALTHY = "healthy"
FALSE_POSITIVE = "false_positive"
FALSE_NEGATIVE = "false_negative"
BLOCKED = "blocked"
ERROR = "error"
UNVERIFIED = "unverified"
STATUSES = (HEALTHY, FALSE_POSITIVE, FALSE_NEGATIVE, BLOCKED, ERROR, UNVERIFIED)

# A flag older than this is ignored by searches: the weekly timer should have
# refreshed it, and a stale verdict shouldn't hide a site forever.
FLAG_MAX_AGE = timedelta(days=30)
# How many `known` accounts to try before calling a site a false negative
# (accounts get deleted or renamed; one miss shouldn't condemn a definition).
MAX_KNOWN_TRIES = 2

FLAGGED_POLICIES = ("skip", "mark", "off")
FLAGGED_ENV = "RECCE_FLAGGED_SITES"

EGRESS_SOURCES = ("https://ipinfo.io/json", "https://api.ipify.org?format=json")


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def site_fingerprint(site: dict[str, Any]) -> str:
    """Short hash of a definition. A WMN refresh that changes a definition
    changes its fingerprint, which invalidates any flag from an older run."""
    body = {k: v for k, v in site.items() if k != "known"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:12]


def _is_blocked(hit: Hit) -> bool:
    return bool(hit.extra.get("challenge")) or hit.extra.get("status_code") in GUARDED_HTTP_STATUSES


def _probe_summary(hit: Hit | None, username: str | None) -> dict[str, Any] | None:
    if hit is None:
        return None
    out: dict[str, Any] = {"username": username, "status": hit.status.value}
    if hit.extra.get("status_code") is not None:
        out["http"] = hit.extra["status_code"]
    note = hit.error or hit.summary
    if note:
        out["note"] = note
    if hit.extra.get("challenge"):
        out["challenge"] = hit.extra["challenge"]
    return out


def classify(known: Hit | None, canary: Hit) -> tuple[str, str]:
    """Return (health status, one-line detail) for a known/canary probe pair."""
    if canary.status is Status.FOUND:
        return FALSE_POSITIVE, "reports a made-up username as existing"
    if known is not None and known.status is Status.NOT_FOUND:
        return FALSE_NEGATIVE, "reports a known account as missing"
    probes = [p for p in (known, canary) if p is not None]
    blocked = [p for p in probes if _is_blocked(p)]
    if blocked:
        p = blocked[0]
        reason = p.extra.get("challenge") or f"HTTP {p.extra.get('status_code')}"
        return BLOCKED, f"{reason} (egress-dependent)"
    bad = [p for p in probes if p.status in (Status.ERROR, Status.UNKNOWN)]
    if bad:
        p = bad[0]
        return ERROR, p.error or p.summary or p.status.value
    if known is None:
        return UNVERIFIED, "no known account; canary not found"
    return HEALTHY, ""


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def _wmn_known_by_name() -> dict[str, list[str]]:
    return {s["name"].lower(): s["known"] for s in _load_wmn_sites() if s.get("known")}


def select_sites(
    *,
    categories: set[str] | None = None,
    names: set[str] | None = None,
    include_nsfw: bool = False,
) -> list[dict[str, Any]]:
    """The definitions a search would use, narrowed by category and/or name
    (both case-insensitive), each with a `known` list where one exists."""
    sites = _load_sites(include_nsfw=include_nsfw or bool(names))
    if categories:
        sites = [s for s in sites if s.get("category", "general").lower() in categories]
    if names:
        sites = [s for s in sites if s["name"].lower() in names]
    wmn_known = _wmn_known_by_name()
    out = []
    for site in sites:
        if not site.get("known") and site["name"].lower() in wmn_known:
            # A custom definition for a platform WMN also covers: its known
            # accounts exist regardless of which definition probes them.
            site = {**site, "known": wmn_known[site["name"].lower()]}
        out.append(site)
    return out


async def egress_info(client: Any) -> dict[str, Any]:
    """Where probes appear to come from. Blocks depend on it (VPN exits are
    often on bot-wall deny lists), so every report records it."""
    for url in EGRESS_SOURCES:
        try:
            resp = await client.get(url)
        except Exception:
            continue
        if resp is None or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if data.get("ip"):
            return {k: data[k] for k in ("ip", "country", "org") if data.get(k)}
    return {"ip": None}


async def check_site_health(
    client: Any,
    site: dict[str, Any],
    canary: str,
    *,
    throttle: PerDomainThrottle | None = None,
) -> dict[str, Any]:
    known_user: str | None = None
    known_hit: Hit | None = None
    for candidate in (site.get("known") or [])[:MAX_KNOWN_TRIES]:
        known_user = candidate
        known_hit = await _check_site(client, site, candidate, throttle=throttle)
        if known_hit.status is not Status.NOT_FOUND:
            break
    canary_hit = await _check_site(client, site, canary, throttle=throttle)
    status, detail = classify(known_hit, canary_hit)
    return {
        "status": status,
        "detail": detail,
        "category": site.get("category", "general"),
        "fingerprint": site_fingerprint(site),
        "known": _probe_summary(known_hit, known_user),
        "canary": _probe_summary(canary_hit, canary),
        "checked_at": _now().isoformat(timespec="seconds"),
    }


async def run_selftest(
    client: HttpClient,
    sites: list[dict[str, Any]],
    *,
    impersonate: bool = True,
    per_domain_rate: float = DEFAULT_PER_DOMAIN_RATE,
    on_progress: Any = None,
) -> dict[str, Any]:
    """Probe every site and return a report dict (see `save_report`)."""
    egress = await egress_info(client)
    probe_client: Any = client
    browser = None
    if impersonate and impersonation_available():
        browser = probe_client = ImpersonatingClient.from_client(client)
    canary = _canary_username()
    throttle = PerDomainThrottle(rate_per_second=per_domain_rate)
    started = _now()

    async def one(site: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        result = await check_site_health(probe_client, site, canary, throttle=throttle)
        if on_progress is not None:
            on_progress(site["name"], result["status"])
        return site["name"], result

    try:
        results = dict(await asyncio.gather(*(one(s) for s in sites)))
    finally:
        if browser is not None:
            await browser.aclose()

    return {
        "version": SCHEMA_VERSION,
        "recce_version": __version__,
        "ran_at": started.isoformat(timespec="seconds"),
        "duration_s": round((_now() - started).total_seconds(), 1),
        "egress": egress,
        "impersonate": browser is not None,
        "canary": canary,
        "summary": summarise(results),
        "sites": results,
    }


def summarise(results: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(STATUSES, 0)
    for entry in results.values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_state(path: Path | None = None) -> dict[str, Any] | None:
    path = path or SELFTEST_PATH
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("sites"), dict):
        return None
    return data


def save_report(report: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    """Merge `report` into the stored state and write it atomically.

    A filtered run (``--only``/``--category``) updates just those sites and
    keeps everyone else's last verdict. Returns the run's changes against the
    previous verdicts: ``[{"site", "from", "to"}]``.
    """
    path = path or SELFTEST_PATH
    previous = load_state(path) or {"sites": {}}
    changes = diff_results(previous["sites"], report["sites"])
    merged_sites = {**previous["sites"], **report["sites"]}
    state = {
        **{k: v for k, v in report.items() if k != "sites"},
        "changes": changes,
        "summary": summarise(merged_sites),
        "run_summary": report["summary"],
        "run_sites": len(report["sites"]),
        "sites": dict(sorted(merged_sites.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, suffix=".tmp") as fh:
        json.dump(state, fh, indent=1)
        tmp = Path(fh.name)
    tmp.replace(path)
    return changes


def diff_results(
    old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    changes = []
    for name, entry in sorted(new.items()):
        before = old.get(name, {}).get("status")
        if before != entry["status"]:
            changes.append({"site": name, "from": before, "to": entry["status"]})
    return changes


# ---------------------------------------------------------------------------
# Search integration
# ---------------------------------------------------------------------------

def flagged_policy(policy: str | None = None) -> str:
    """skip (default): don't probe last-known false positives; mark: probe but
    downgrade them; off: ignore selftest results."""
    value = (policy or os.environ.get(FLAGGED_ENV) or "skip").strip().lower()
    if value not in FLAGGED_POLICIES:
        raise ValueError(f"flagged-sites policy must be one of {', '.join(FLAGGED_POLICIES)}")
    return value


def search_flags(
    sites: list[dict[str, Any]],
    *,
    path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Selftest verdicts that should change how a search treats a site: the
    site's last result was a false positive or false negative, the result is
    fresh, and the definition hasn't changed since."""
    state = load_state(path)
    if not state:
        return {}
    now = now or _now()
    out: dict[str, dict[str, Any]] = {}
    for site in sites:
        entry = state["sites"].get(site["name"])
        if not entry or entry.get("status") not in (FALSE_POSITIVE, FALSE_NEGATIVE):
            continue
        if entry.get("fingerprint") != site_fingerprint(site):
            continue
        try:
            checked = datetime.fromisoformat(entry["checked_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if now - checked > FLAG_MAX_AGE:
            continue
        out[site["name"]] = entry
    return out


def skipped_hit(site: dict[str, Any], entry: dict[str, Any], username: str) -> Hit:
    when = str(entry.get("checked_at", ""))[:10]
    return Hit(
        source=site["name"],
        category=site.get("category", "general"),
        status=Status.SKIPPED,
        url=site["url"].replace("{u}", username),
        summary=f"skipped — selftest {when} found it reports made-up usernames as existing",
        confidence=0.0,
        extra={"selftest": {"status": entry["status"], "checked_at": entry.get("checked_at")}},
    )


def annotate_hit(hit: Hit, entry: dict[str, Any]) -> None:
    """Downgrade a hit from a definition the last selftest flagged."""
    when = str(entry.get("checked_at", ""))[:10]
    hit.extra["selftest"] = {"status": entry["status"], "checked_at": entry.get("checked_at")}
    if entry["status"] == FALSE_POSITIVE and hit.status is Status.FOUND:
        hit.status = Status.UNKNOWN
        hit.summary = f"low confidence — selftest {when} found this site reports made-up usernames"
        hit.confidence = min(hit.confidence, 0.2)
    elif entry["status"] == FALSE_NEGATIVE and hit.status is Status.NOT_FOUND:
        hit.summary = f"unreliable miss — selftest {when} found this site misses known accounts"
        hit.confidence = min(hit.confidence, 0.3)


def last_run_summary(path: Path | None = None) -> dict[str, Any] | None:
    state = load_state(path)
    if not state:
        return None
    return {
        "ran_at": state.get("ran_at"),
        "egress": state.get("egress") or {},
        "summary": state.get("summary") or summarise(state["sites"]),
        "path": str(path or SELFTEST_PATH),
    }


def _now() -> datetime:
    return datetime.now(timezone.utc)
