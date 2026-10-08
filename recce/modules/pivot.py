# SPDX-License-Identifier: AGPL-3.0-or-later
"""Recursive pivoting: turn identifiers named in hits into follow-up searches.

Hits carry pivot material in `extra`: `usernames` (GitHub identity's linked X
handle, GitHub commit logins), `emails` (commit identities with a real email),
`username` (the email local-part pivot) and `accounts` (Gravatar's linked
profile URLs). This module collects those, de-duplicates them against what was
already searched, and runs the follow-ups breadth-first.

Follow-ups are always the passive search only. `pivot_search` never calls the
consent-gated `--deep` email probes, and domains are not pivoted at all, so a
discovered identifier can never trigger active recon nobody consented to.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..config import Settings
from ..core.http import HttpClient
from ..core.investigations import describe_origin, pivot_edge
from ..core.result import PivotOrigin, Report
from .email import EMAIL_RE

MAX_DEPTH = 3
DEFAULT_MAX_PER_LEVEL = 10
PIVOT_KINDS = ("username", "email")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
_NOREPLY_DOMAINS = ("users.noreply.github.com",)

# Profile URL → username, for hosts whose profile path is unambiguous.
# Value is the path prefix before the username ("" = first segment).
_PROFILE_HOSTS = {
    "twitter.com": "",
    "x.com": "",
    "github.com": "",
    "gitlab.com": "",
    "instagram.com": "",
    "facebook.com": "",
    "twitch.tv": "",
    "pinterest.com": "",
    "soundcloud.com": "",
    "keybase.io": "",
    "linkedin.com": "in/",
    "reddit.com": "user/",
    "tiktok.com": "@",
    "youtube.com": "@",
    "medium.com": "@",
}
_RESERVED_SEGMENTS = {
    "intent", "share", "home", "i", "search", "explore", "login", "settings",
    "about", "hashtag", "profile.php", "pages", "groups", "orgs", "sponsors",
}

# extra field → identifier kind
_LIST_FIELDS = {"usernames": "username", "emails": "email"}
_SCALAR_FIELDS = {"username": "username"}


@dataclass(frozen=True)
class Pivot:
    """An identifier discovered in a hit, and where it came from."""

    kind: str
    value: str
    origin: PivotOrigin

    @property
    def key(self) -> tuple[str, str]:
        return pivot_key(self.kind, self.value)

    @property
    def command(self) -> str:
        return f"recce {self.kind} {self.value}"


@dataclass
class PivotRun:
    """The outcome of following pivots from one root report."""

    root: Report
    reports: list[Report] = field(default_factory=list)
    pending: list[Pivot] = field(default_factory=list)

    def chain(self) -> list[dict[str, Any]]:
        return [pivot_edge(r.model_dump(mode="json")) for r in self.reports if r.pivot]


__all__ = [
    "MAX_DEPTH",
    "Pivot",
    "PivotRun",
    "describe_origin",
    "extract_pivots",
    "new_pivots",
    "normalise",
    "pivot_edge",
    "pivot_key",
    "pivot_search",
    "run_pivots",
    "username_from_url",
]

SearchFn = Callable[[str, str], Awaitable[Report]]


def pivot_key(kind: str, value: str) -> tuple[str, str]:
    return (kind, value.strip().lower())


def normalise(kind: str, raw: Any) -> str | None:
    """Clean a raw identifier, or return None when it isn't searchable."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if kind == "username":
        value = value.lstrip("@")
        return value if USERNAME_RE.match(value) else None
    if kind == "email":
        value = value.lower()
        if not EMAIL_RE.match(value):
            return None
        local, domain = value.rsplit("@", 1)
        if domain.endswith(_NOREPLY_DOMAINS) or local in {"noreply", "no-reply"}:
            return None
        return value
    return None


def username_from_url(url: Any) -> str | None:
    """Extract the username from a profile URL on a known host."""
    if not isinstance(url, str) or not url.strip():
        return None
    parsed = urlparse(url.strip() if "://" in url else f"https://{url.strip()}")
    host = (parsed.hostname or "").lower()
    for prefix in ("www.", "m.", "mobile."):
        host = host.removeprefix(prefix)
    prefix = _PROFILE_HOSTS.get(host)
    if prefix is None:
        return None
    path = parsed.path.lstrip("/")
    if prefix == "user/" and path.startswith("u/"):
        path = "user/" + path[2:]
    if not path.startswith(prefix):
        return None
    segment = path[len(prefix):].split("/", 1)[0]
    if not segment or segment.lower() in _RESERVED_SEGMENTS:
        return None
    return normalise("username", segment)


def extract_pivots(report: Report, *, depth: int = 1) -> list[Pivot]:
    """Identifiers named by the report's FOUND hits, minus the query itself."""
    own = pivot_key(report.query_type, report.query)
    found: dict[tuple[str, str], Pivot] = {}

    def add(kind: str, raw: Any, hit_source: str, field_name: str, hit_url: str | None) -> None:
        value = normalise(kind, raw)
        if value is None:
            return
        key = pivot_key(kind, value)
        if key == own or key in found:
            return
        origin = PivotOrigin(
            from_query=report.query,
            from_type=report.query_type,
            source=hit_source,
            field=field_name,
            hit_url=hit_url,
            depth=depth,
        )
        found[key] = Pivot(kind=kind, value=value, origin=origin)

    for hit in report.found:
        extra = hit.extra or {}
        for name, kind in _LIST_FIELDS.items():
            for raw in _as_list(extra.get(name)):
                add(kind, raw, hit.source, name, hit.url)
        for name, kind in _SCALAR_FIELDS.items():
            if name in extra:
                add(kind, extra[name], hit.source, name, hit.url)
        for url in _as_list(extra.get("accounts")):
            add("username", username_from_url(url), hit.source, "accounts", url)
    return list(found.values())


def new_pivots(
    reports: Iterable[Report], seen: set[tuple[str, str]], *, depth: int = 1
) -> list[Pivot]:
    """Pivots from `reports` not yet in `seen`. Adds what it returns to `seen`."""
    out = []
    for report in reports:
        for pivot in extract_pivots(report, depth=depth):
            if pivot.key in seen:
                continue
            seen.add(pivot.key)
            out.append(pivot)
    return out


async def run_pivots(
    root: Report,
    search: SearchFn,
    *,
    depth: int = 1,
    max_per_level: int = DEFAULT_MAX_PER_LEVEL,
    seen: Iterable[tuple[str, str]] = (),
) -> PivotRun:
    """Follow pivots breadth-first from `root`, up to `depth` levels (max 3).

    Each level runs at most `max_per_level` follow-ups; the rest, and whatever
    the last level discovers, come back as `pending` suggestions.
    """
    depth = max(1, min(int(depth), MAX_DEPTH))
    known = set(seen) | {pivot_key(root.query_type, root.query)}
    result = PivotRun(root=root)
    frontier = [root]
    for level in range(1, depth + 1):
        candidates = new_pivots(frontier, known, depth=level)
        result.pending.extend(candidates[max_per_level:])
        frontier = []
        for pivot in candidates[:max_per_level]:
            try:
                report = await search(pivot.kind, pivot.value)
            except ValueError:
                continue
            report.pivot = pivot.origin
            result.reports.append(report)
            frontier.append(report)
    result.pending.extend(new_pivots(frontier, known, depth=depth + 1))
    return result


def pivot_search(
    client: HttpClient,
    settings: Settings,
    *,
    skip_provider_ids: set[str] | None = None,
    **username_options: Any,
) -> SearchFn:
    """The follow-up search used for discovered identifiers.

    Passive lookups only: never `deep_email_probes`, whatever the root run used.
    """
    from .email import search_email
    from .username import search_username

    async def search(kind: str, value: str) -> Report:
        if kind == "username":
            return await search_username(
                value,
                client,
                settings=settings,
                skip_provider_ids=skip_provider_ids,
                **username_options,
            )
        if kind == "email":
            return await search_email(value, client, settings, skip_provider_ids=skip_provider_ids)
        raise ValueError(f"cannot pivot on {kind!r}")

    return search


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]
