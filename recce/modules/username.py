# SPDX-License-Identifier: AGPL-3.0-or-later
"""Username search across many platforms.

Three site sources are merged at load time:

1. **WhatsMyName** (`wmn-data.json`) — the canonical community-maintained
   list (~700+ sites). The schema defines paired-marker detection via
   `e_code` + `e_string` + `m_code` + `m_string`: an account *exists* iff
   `status == e_code AND e_string in body AND m_string NOT in body`.
   Live updates fetched via `recce update` land in `~/.cache/recce/`.

2. **recce custom sites** (`custom_sites.json`) — a small bespoke list of
   probes that don't fit the WMN schema (multi-instance Mastodon, Bluesky's
   AT-Proto API, redirect-marker detection for Bandcamp/Substack/Wordpress,
   JSON endpoints for SPAs such as ArtStation). Custom entries override
   WMN ones with the same name.

3. **Maigret** (`maigret-data.json.xz`, see `maigret.py`) — ~6,800 more
   sites, mostly forums, minus any whose domain WMN or the custom list
   already covers. Searches only run the ones `recce selftest` has verified
   (``--maigret``, ``RECCE_MAIGRET``).

Detection methods supported:
- ``wmn``           paired markers (FOUND iff e_code + e_string ∧ ¬m_string)
- ``status``        HTTP status code list
- ``absent``        body must NOT contain a marker
- ``present``       body MUST contain a marker
- ``redirect_match`` Location header substring
- ``post_json``     JSON POST + body marker
- ``maigret``       Maigret's status_code / message / response_url checks
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import secrets
import string
import tempfile
import time
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..config import Settings
from ..core.egress import Exit, ExitChain, exit_label, fallback_exits
from ..core.http import HttpClient, ImpersonatingClient, impersonation_available
from ..core.output import console
from ..core.result import Hit, Report, Status
from .page_meta import apply_page_meta, extract_page_meta

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,38}$")
NSFW_CAT_RE = re.compile(r"\bnsfw\b", re.IGNORECASE)

CACHE_DIR = Path.home() / ".cache" / "recce"
CACHED_WMN = CACHE_DIR / "wmn-data.json"
GUARDED_HTTP_STATUSES = {401, 403, 429}
DEFAULT_PER_DOMAIN_RATE = 1.5
DEFAULT_GUARDED_BACKOFF_SECONDS = 3.0
DEFAULT_THROTTLE_JITTER_SECONDS = 0.25
# Bot-wall interstitials. Specific to challenge/block pages: generic words such
# as "captcha" also appear on ordinary profile pages. A challenge served with
# HTTP 200 must not read as "account exists".
CHALLENGE_MARKERS = {
    "_cf_chl_opt": "Cloudflare challenge",
    "<title>Just a moment...</title>": "Cloudflare challenge",
    "Attention Required! | Cloudflare": "Cloudflare block",
    "AwsWafIntegration": "AWS WAF challenge",
    "captcha-delivery.com": "DataDome challenge",
    "px-captcha": "PerimeterX challenge",
    "/_Incapsula_Resource": "Imperva challenge",
    "sgcaptcha": "SiteGround captcha",
    "<title>Client Challenge</title>": "Fastly challenge",
    "/_fs-ch-": "Fastly challenge",
}
# Status precedence when several site definitions point at the same profile.
_STATUS_RANK = {Status.FOUND: 0, Status.NOT_FOUND: 1, Status.UNKNOWN: 2, Status.ERROR: 3, Status.SKIPPED: 4}


class PerDomainThrottle:
    """Small per-host token bucket for username probes.

    Recce still relies on the HTTP client's global semaphore for total
    concurrency. This layer spaces requests to the same host so one domain with
    several probes cannot be hit in a burst.
    """

    def __init__(
        self,
        *,
        rate_per_second: float = DEFAULT_PER_DOMAIN_RATE,
        guarded_backoff_seconds: float = DEFAULT_GUARDED_BACKOFF_SECONDS,
        jitter_seconds: float = DEFAULT_THROTTLE_JITTER_SECONDS,
        sleep=asyncio.sleep,
        monotonic=time.monotonic,
    ) -> None:
        self._min_interval = 0.0 if rate_per_second <= 0 else 1.0 / rate_per_second
        self._guarded_backoff_seconds = max(0.0, guarded_backoff_seconds)
        self._jitter_seconds = max(0.0, jitter_seconds)
        self._sleep = sleep
        self._monotonic = monotonic
        self._locks: dict[str, asyncio.Lock] = {}
        self._next_allowed_at: dict[str, float] = {}

    async def wait(self, url: str) -> None:
        if self._min_interval <= 0:
            return
        key = _throttle_key(url)
        if not key:
            return
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            now = self._monotonic()
            wait_for = max(0.0, self._next_allowed_at.get(key, now) - now)
            if wait_for > 0:
                await self._sleep(wait_for + self._jitter())
                now = self._monotonic()
            self._next_allowed_at[key] = max(now, self._next_allowed_at.get(key, now)) + self._min_interval

    def backoff(self, url: str) -> None:
        key = _throttle_key(url)
        if not key or self._guarded_backoff_seconds <= 0:
            return
        until = self._monotonic() + self._guarded_backoff_seconds + self._jitter()
        self._next_allowed_at[key] = max(self._next_allowed_at.get(key, 0.0), until)

    def _jitter(self) -> float:
        if self._jitter_seconds <= 0:
            return 0.0
        return random.uniform(0, self._jitter_seconds)


def _throttle_key(url: str) -> str:
    hostname = (urlparse(url).hostname or "").lower().strip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _format(value: str, username: str) -> str:
    return value.replace("{u}", username)


def _detect_challenge(body: str) -> str | None:
    for marker, label in CHALLENGE_MARKERS.items():
        if marker in body:
            return label
    return None


def _load_bundled_wmn_raw() -> str:
    return resources.files("recce.data").joinpath("wmn-data.json").read_text()


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
    """Load WMN sites — prefer the user's cached refresh over the bundled snapshot.

    A corrupt cache should not break recce entirely. If the cached update cannot
    be parsed, fall back to the bundled snapshot and let `doctor` surface the
    stale/corrupt cache state.
    """
    if CACHED_WMN.exists():
        try:
            raw = CACHED_WMN.read_text()
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            data = json.loads(_load_bundled_wmn_raw())
    else:
        data = json.loads(_load_bundled_wmn_raw())
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


def _load_sites(*, include_nsfw: bool = False, maigret: bool = False) -> list[dict[str, Any]]:
    """Merge WMN + recce custom sites. Custom entries override by `name`.

    With `maigret`, every importable Maigret site whose domain the first two
    don't cover is appended, verified or not (selftest needs them all;
    searches gate them with `search_sites`)."""
    wmn_sites = _load_wmn_sites()
    custom_sites = _load_custom_sites()
    # An exact name match is a deliberate override of the WMN entry. A match
    # that differs only in case ("Tumblr" / "tumblr") is an accidental
    # duplicate: keep WMN's actively maintained definition and drop ours, or
    # both run and double-report.
    custom_names = {s["name"] for s in custom_sites}
    wmn_kept = [s for s in wmn_sites if s["name"] not in custom_names]
    wmn_lower = {s["name"].lower() for s in wmn_kept}
    merged = wmn_kept + [s for s in custom_sites if s["name"].lower() not in wmn_lower]
    if maigret:
        from . import maigret as maigret_db

        merged += maigret_db.merge(merged, maigret_db.load_sites())

    if not include_nsfw:
        merged = [s for s in merged if not NSFW_CAT_RE.search(s.get("category", ""))]

    return merged


def site_source(site: dict[str, Any]) -> str:
    """wmn, custom or maigret."""
    if site.get("source"):
        return site["source"]
    return "wmn" if str(site.get("method", "")).startswith("wmn") else "custom"


def search_sites(*, include_nsfw: bool = False, maigret: str | None = None) -> list[dict[str, Any]]:
    """The definitions a username search runs. Maigret sites come in per the
    `maigret` policy (default $RECCE_MAIGRET, then "verified"): "verified"
    keeps only those the last selftest found healthy, "all" keeps every one,
    "off" none."""
    from . import maigret as maigret_db

    chosen = maigret_db.policy(maigret)
    sites = _load_sites(include_nsfw=include_nsfw, maigret=chosen != "off")
    if chosen == "verified":
        from .selftest import maigret_verified

        verified = maigret_verified([s for s in sites if site_source(s) == maigret_db.SOURCE])
        sites = [s for s in sites if site_source(s) != maigret_db.SOURCE or s["name"] in verified]
    return sites


def _regex_allows(pattern: str, username: str) -> bool:
    try:
        return re.search(pattern, username) is not None
    except re.error:
        return False


def site_count(*, include_nsfw: bool = False, maigret: str | None = None) -> int:
    return len(search_sites(include_nsfw=include_nsfw, maigret=maigret))


def category_counts(*, include_nsfw: bool = False, maigret: str | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for site in search_sites(include_nsfw=include_nsfw, maigret=maigret):
        category = site.get("category", "general")
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def cache_status() -> dict[str, Any]:
    if not CACHED_WMN.exists():
        return {"path": str(CACHED_WMN), "exists": False, "valid": None, "sites": None}
    try:
        data = json.loads(CACHED_WMN.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {
            "path": str(CACHED_WMN),
            "exists": True,
            "valid": False,
            "sites": None,
            "error": str(e)[:120],
        }
    sites = data.get("sites")
    return {
        "path": str(CACHED_WMN),
        "exists": True,
        "valid": isinstance(sites, list),
        "sites": len(sites) if isinstance(sites, list) else None,
    }


def clear_wmn_cache() -> bool:
    if not CACHED_WMN.exists():
        return False
    CACHED_WMN.unlink()
    return True


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
        if status_code in GUARDED_HTTP_STATUSES:
            return Status.UNKNOWN, f"HTTP {status_code} (blocked/rate-limited)"
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
        if status_code in (404, 410):
            return Status.NOT_FOUND, None
        if status_code >= 400:
            return Status.UNKNOWN, f"HTTP {status_code}"
        haystack = body.lower() if site.get("case_insensitive") else body
        needle = marker.lower() if site.get("case_insensitive") else marker
        if needle in haystack:
            return Status.FOUND, None
        return Status.NOT_FOUND, None

    if method == "post_json":
        marker = _format(site["marker"], username)
        if status_code in (404, 410):
            return Status.NOT_FOUND, None
        if status_code >= 400:
            return Status.UNKNOWN, f"HTTP {status_code}"
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

    if method == "maigret":
        return _classify_maigret(site, status_code, body)

    return Status.UNKNOWN, f"unknown method '{method}'"


def _classify_maigret(site: dict[str, Any], status_code: int, body: str) -> tuple[Status, str | None]:
    """Maigret's `process_site_result` + `detect_error_page`: a refusal is
    "could not check", never "not found"."""
    for flag, message in (site.get("errors") or {}).items():
        if body and flag in body:
            return Status.UNKNOWN, str(message)
    if status_code in GUARDED_HTTP_STATUSES and not (status_code == 403 and site.get("ignore403")):
        return Status.UNKNOWN, f"HTTP {status_code} (blocked/rate-limited)"
    if status_code == 999 or status_code >= 500:
        return Status.UNKNOWN, f"HTTP {status_code}"
    presence = site.get("presence") or []
    present = bool(body) and (not presence or any(marker in body for marker in presence))
    check = site.get("check")
    if check == "message":
        absent = any(marker in body for marker in site.get("absence") or [])
        return (Status.FOUND if present and not absent else Status.NOT_FOUND), None
    if check == "status_code":
        return (Status.FOUND if 200 <= status_code < 300 else Status.NOT_FOUND), None
    if check == "response_url":
        return (Status.FOUND if 200 <= status_code < 300 and present else Status.NOT_FOUND), None
    return Status.UNKNOWN, f"unknown Maigret check '{check}'"


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

async def _check_site(
    client: HttpClient,
    site: dict[str, Any],
    username: str,
    *,
    throttle: PerDomainThrottle | None = None,
    collect_meta: bool = False,
) -> Hit:
    """Probe one site. FOUND hits (and every probe with `collect_meta`) keep
    the page's meta tags in `extra["page_meta"]` for `apply_page_meta`."""
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
        if throttle is not None:
            await throttle.wait(probe_url)
        kwargs: dict[str, Any] = {"headers": headers, "follow_redirects": follow_redirects}
        if method == "wmn_post":
            kwargs["json"] = json.loads(_format(json.dumps(site["post_body"]), username))
            verb = "POST"
        elif method == "post_json":
            kwargs["json"] = json.loads(_format(json.dumps(site["post"]), username))
            verb = "POST"
        else:
            verb = "HEAD" if use_head else "GET"
        resp, transport_error = await _send(client, verb, probe_url, **kwargs)
    except Exception as e:
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
            error=transport_error or "network error / timeout",
            elapsed_ms=elapsed_ms,
        )

    needs_body = collect_meta or method not in ("status", "redirect_match") or resp.status_code in (
        200, 202, 403, 429, 503,
    )
    body = (resp.text or "") if needs_body else ""
    location = resp.headers.get("Location", "")
    if throttle is not None and resp.status_code in GUARDED_HTTP_STATUSES:
        throttle.backoff(probe_url)
    challenge = _detect_challenge(body) if body else None
    if challenge:
        status, note = Status.UNKNOWN, f"{challenge} (HTTP {resp.status_code})"
    else:
        status, note = _classify(site, resp.status_code, body, username, location=location)
    extra = {
        "method": method,
        "probe_url": probe_url,
        "status_code": resp.status_code,
        "final_url": str(resp.url),
    }
    if location:
        extra["location"] = location
    if challenge:
        extra["challenge"] = challenge
    if body and (status is Status.FOUND or collect_meta):
        page_meta = extract_page_meta(body, str(resp.url))
        if page_meta:
            extra["page_meta"] = page_meta
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
        extra=extra,
        elapsed_ms=elapsed_ms,
    )


async def _send(client: Any, verb: str, url: str, **kwargs: Any) -> tuple[Any, str | None]:
    """Send via `request_detailed` when the client has it (so failures carry a
    reason such as "DNS lookup failed"), else fall back to get/post/head."""
    detailed = getattr(client, "request_detailed", None)
    if detailed is not None:
        return await detailed(verb, url, **kwargs)
    resp = await getattr(client, verb.lower())(url, **kwargs)
    return resp, None


def _canary_username() -> str:
    """A username that almost certainly does not exist anywhere."""
    alphabet = string.ascii_lowercase + string.digits
    return "q" + "".join(secrets.choice(alphabet) for _ in range(11))


async def _verify_found(
    client: HttpClient,
    sites_by_name: dict[str, dict[str, Any]],
    hits: list[Hit],
    throttle: PerDomainThrottle | None,
    exit_clients: dict[str, Any] | None = None,
    username: str = "",
) -> None:
    """Re-probe every FOUND site with a made-up username. A site that also
    "finds" the made-up account reports existence for any input, so the hit
    is unverifiable and is downgraded (Maigret-style false-positive check).

    A hit found through a fallback exit is re-probed through that same exit
    (`exit_clients`, keyed by exit label), since the primary one is walled."""
    canary = _canary_username()
    found = [hit for hit in hits if hit.status is Status.FOUND and hit.source in sites_by_name]
    exit_clients = exit_clients or {}

    async def check(hit: Hit) -> None:
        via = exit_clients.get(hit.extra.get("exit", ""), client)
        probe = await _check_site(
            via, sites_by_name[hit.source], canary, throttle=throttle, collect_meta=True
        )
        hit.extra["canary"] = {"username": canary, "status": probe.status.value}
        if probe.status is Status.FOUND:
            hit.status = Status.UNKNOWN
            hit.summary = "unverifiable — site also reports a made-up username as existing"
            hit.confidence = 0.2
        elif username:
            # Whatever the canary's page shares with this one is site boilerplate.
            apply_page_meta(hit, username, probe.extra.get("page_meta"))

    await asyncio.gather(*(check(hit) for hit in found))


def _is_blocked(hit: Hit) -> bool:
    return hit.status is Status.UNKNOWN and hit.extra.get("status_code") in GUARDED_HTTP_STATUSES


async def _retry_blocked(
    fallback: Any,
    label: str,
    sites_by_name: dict[str, dict[str, Any]],
    hits: list[Hit],
    username: str,
    throttle: PerDomainThrottle | None,
    only: set[str] | None = None,
) -> None:
    """Re-probe bot-walled sites (just those named in `only`, if given) through
    the fallback exit, in place."""

    async def retry(index: int) -> None:
        blocked = hits[index]
        site = sites_by_name.get(blocked.source)
        if site is None:
            return
        attempt = await _check_site(fallback, site, username, throttle=throttle)
        record = {
            "exit": label,
            "status": attempt.status.value,
            "detail": attempt.summary or attempt.error,
            "primary": blocked.extra.get("fallback", {}).get("primary", blocked.summary),
        }
        # Every exit tried so far, in order (a chain retries via several).
        tried = [*blocked.extra.get("fallback_attempts", []), record]
        if attempt.status in (Status.FOUND, Status.NOT_FOUND):
            attempt.extra["exit"] = label
            attempt.extra["fallback"] = record
            attempt.extra["fallback_attempts"] = tried
            attempt.summary = f"{attempt.summary or attempt.status.value} · via {label}"
            hits[index] = attempt
        else:
            blocked.extra["fallback"] = record
            blocked.extra["fallback_attempts"] = tried

    await asyncio.gather(*(retry(i) for i, hit in enumerate(hits) if _is_blocked(hit) and (only is None or hit.source in only)))


def _client_for_exit(client: Any, exit_: Exit, *, browser: bool) -> Any:
    """A client like `client` that leaves through `exit_`."""
    if browser:
        return ImpersonatingClient(
            timeout=client.timeout, max_concurrency=client.max_concurrency, proxy=exit_.proxy, ipv4=exit_.ipv4
        )
    return HttpClient(
        user_agent=client.user_agent,
        timeout=client.timeout,
        max_concurrency=client.max_concurrency,
        proxy=exit_.proxy,
    )


def _profile_key(hit: Hit) -> str:
    url = (hit.url or "").lower().split("://", 1)[-1].removeprefix("www.").rstrip("/")
    return url or hit.source.lower()


def _dedupe_by_profile(hits: list[Hit]) -> list[Hit]:
    """Collapse several definitions of the same profile (e.g. "GitHub" and
    "GitHub (User)") into one hit, keeping the most decisive status."""
    groups: dict[str, list[Hit]] = {}
    for hit in hits:
        groups.setdefault(_profile_key(hit), []).append(hit)
    out: list[Hit] = []
    for group in groups.values():
        best = min(group, key=lambda h: (_STATUS_RANK.get(h.status, 9), -h.confidence))
        others = sorted({h.source for h in group if h is not best})
        if others:
            best.extra["also_checked_as"] = others
        out.append(best)
    return out


async def search_username(
    username: str,
    client: HttpClient,
    *,
    only_categories: set[str] | None = None,
    exclude_categories: set[str] | None = None,
    include_nsfw: bool = False,
    show_progress: bool = True,
    per_domain_rate: float = DEFAULT_PER_DOMAIN_RATE,
    guarded_backoff_seconds: float = DEFAULT_GUARDED_BACKOFF_SECONDS,
    verify_found: bool = True,
    impersonate: bool = True,
    settings: Settings | None = None,
    skip_provider_ids: set[str] | None = None,
    flagged_sites: str | None = None,
    attribute_hits: bool = True,
    fallback_exit: Exit | ExitChain | None = None,
    maigret: str | None = None,
) -> Report:
    """Probe every site for `username`, then run username providers.

    With `impersonate` (default) and curl_cffi installed, site probes go out
    with a real Chrome fingerprint, which gets past far more bot walls than
    httpx. API providers (e.g. GitHub identity) always use `client`, recce's
    honest client. Providers run only when `settings` is given.

    `flagged_sites` says what to do with definitions the last `recce selftest`
    caught reporting made-up usernames: "skip" (default), "mark" (probe, then
    downgrade), or "off". Defaults to $RECCE_FLAGGED_SITES, then "skip".

    `maigret` picks which Maigret sites run (see `search_sites`): "verified"
    (default, only those the last selftest found healthy), "all" or "off".

    With `attribute_hits` (default), FOUND hits are clustered by corroborating
    profile data (see `attribution.py`), fetching avatars through `client`.

    With `fallback_exit`, probes the primary exit gets bot-walled on (HTTP
    401/403/429) are retried through that exit -- or, for an ExitChain,
    through each exit in order, each only for probes still blocked. A
    decisive answer replaces the blocked one and records `extra["exit"]`.
    """
    kwargs: dict[str, Any] = dict(
        only_categories=only_categories, exclude_categories=exclude_categories,
        include_nsfw=include_nsfw, show_progress=show_progress, per_domain_rate=per_domain_rate,
        guarded_backoff_seconds=guarded_backoff_seconds, verify_found=verify_found,
        flagged_sites=flagged_sites, maigret=maigret,
    )
    use_browser = impersonate and impersonation_available()
    opened: list[Any] = []
    try:
        probe_client = client
        if use_browser:
            probe_client = ImpersonatingClient.from_client(client)
            opened.append(probe_client)
        fallbacks = []
        for exit_ in fallback_exits(fallback_exit):
            fallback = _client_for_exit(client, exit_, browser=use_browser)
            opened.append(fallback)
            fallbacks.append((fallback, exit_.label))
        if fallbacks:
            kwargs["fallback"] = fallbacks
        report = await _search_username(username, probe_client, **kwargs)
    finally:
        for opened_client in opened:
            await opened_client.aclose()
    report.exit = exit_label(getattr(client, "proxy", None))

    if settings is not None:
        from ..providers import query_registered_providers

        for hit in await query_registered_providers(
            username, "username", client, settings, skip_provider_ids=skip_provider_ids
        ):
            report.add(hit)
        from ..providers.wayback_profiles import mark_deleted

        mark_deleted(report)
        report.finish()
    if attribute_hits:
        from .attribution import attribute

        await attribute(report, client)
    return report


async def _search_username(
    username: str,
    client: Any,
    *,
    only_categories: set[str] | None,
    exclude_categories: set[str] | None,
    include_nsfw: bool,
    show_progress: bool,
    per_domain_rate: float,
    guarded_backoff_seconds: float,
    verify_found: bool,
    flagged_sites: str | None = None,
    fallback: list[tuple[Any, str]] | tuple[Any, str] | None = None,
    maigret: str | None = None,
) -> Report:
    if not USERNAME_RE.match(username):
        raise ValueError(
            "Username must be 1–39 chars, start alphanumeric, and contain only letters, digits, '.', '_' or '-'."
        )

    sites = search_sites(include_nsfw=include_nsfw, maigret=maigret)
    # Maigret's regexCheck: the site can't hold this username at all.
    sites = [s for s in sites if not s.get("regex") or _regex_allows(s["regex"], username)]
    if only_categories:
        sites = [s for s in sites if s.get("category", "general") in only_categories]
    if exclude_categories:
        sites = [s for s in sites if s.get("category", "general") not in exclude_categories]

    from . import selftest

    policy = selftest.flagged_policy(flagged_sites)
    flags = selftest.search_flags(sites) if policy != "off" else {}
    skipped: list[Hit] = []
    if policy == "skip":
        for site in sites:
            entry = flags.get(site["name"])
            if entry and entry["status"] == selftest.FALSE_POSITIVE:
                skipped.append(selftest.skipped_hit(site, entry, username))
        skipped_names = {h.source for h in skipped}
        sites = [s for s in sites if s["name"] not in skipped_names]

    report = Report(query=username, query_type="username")
    throttle = PerDomainThrottle(
        rate_per_second=per_domain_rate,
        guarded_backoff_seconds=guarded_backoff_seconds,
    )

    sites_by_name = {s["name"]: s for s in sites}

    async def finalise(results: list[Hit]) -> Report:
        verify_clients: dict[str, Any] = {}
        chain = [fallback] if isinstance(fallback, tuple) else (fallback or [])
        verify_clients.update({label: fallback_client for fallback_client, label in chain})
        # Each site tries the exits in its own order (selftest learns which work
        # for it); round N retries, per exit, the sites whose Nth choice it is.
        order = selftest.exit_order(sites, [label for _, label in chain]) if policy != "off" else {
            name: [label for _, label in chain] for name in sites_by_name
        }
        for rnd in range(len(chain)):
            for fallback_client, label in chain:
                names = {n for n, o in order.items() if rnd < len(o) and o[rnd] == label}
                if names:
                    await _retry_blocked(
                        fallback_client, label, sites_by_name, results, username, throttle, only=names
                    )
        for hit in results:
            if chain and _is_blocked(hit) and not order.get(hit.source) and "fallback" not in hit.extra:
                hit.extra["fallback_skipped"] = "selftest: every fallback exit is walled for this site"
        if verify_found:
            await _verify_found(
                client, sites_by_name, results, throttle, verify_clients, username=username
            )
        for hit in results:
            if hit.status is Status.FOUND:
                apply_page_meta(hit, username)  # no-op if verification already did
            else:
                hit.extra.pop("page_meta", None)
        for hit in results:
            if hit.source in flags:
                selftest.annotate_hit(hit, flags[hit.source])
        for r in _dedupe_by_profile(results) + skipped:
            report.add(r)
        report.finish()
        return report

    if not show_progress:
        results = await asyncio.gather(*(_check_site(client, s, username, throttle=throttle) for s in sites))
        return await finalise(list(results))

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
            hit = await _check_site(client, site, username, throttle=throttle)
            progress.advance(task)
            return hit

        results = await asyncio.gather(*(runner(s) for s in sites))
        if verify_found:
            progress.update(task, description="Verifying hits against a made-up username…")
        return await finalise(list(results))


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
    with tempfile.NamedTemporaryFile("w", dir=CACHE_DIR, delete=False) as fh:
        fh.write(payload)
        tmp_path = Path(fh.name)
    tmp_path.replace(CACHED_WMN)
    after = len([s for s in parsed["sites"] if s.get("valid", True) is not False])
    return before, after
