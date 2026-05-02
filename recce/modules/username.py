"""Username search across many social/dev/gaming platforms.

Each site definition lives in `recce/data/sites.json`. We dispatch concurrent
requests through the shared async HTTP client and classify the response into a
Hit using the site's declared detection method.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from importlib import resources
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


def _load_sites() -> list[dict[str, Any]]:
    raw = resources.files("recce.data").joinpath("sites.json").read_text()
    data = json.loads(raw)
    return data["sites"]


def _format(value: str, username: str) -> str:
    return value.replace("{u}", username)


def _classify(
    site: dict[str, Any],
    status_code: int,
    body: str,
    username: str,
    location: str = "",
) -> tuple[Status, str | None]:
    method = site["method"]

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
        # `missing_location` substring in Location header => user not found.
        # Otherwise, 200/3xx with a different Location => found.
        missing_marker = _format(site.get("missing_location", ""), username)
        if status_code in (404, 410):
            return Status.NOT_FOUND, None
        if missing_marker and missing_marker in location:
            return Status.NOT_FOUND, None
        if status_code in (200, 301, 302, 303, 307, 308):
            return Status.FOUND, None
        return Status.UNKNOWN, f"HTTP {status_code}"

    return Status.UNKNOWN, f"unknown method '{method}'"


async def _check_site(client: HttpClient, site: dict[str, Any], username: str) -> Hit:
    profile_url = _format(site["url"], username)
    probe_url = _format(site.get("probe", site["url"]), username)
    headers = site.get("headers")
    method = site["method"]
    started = time.perf_counter()

    follow_redirects = not site.get("no_redirect", False)
    use_head = site.get("head_request", False)
    try:
        if method == "post_json":
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

    body = resp.text if method not in ("status", "redirect_match") else ""
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
        url=profile_url if status is Status.FOUND else (profile_url if status is Status.NOT_FOUND else profile_url),
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
    show_progress: bool = True,
) -> Report:
    if not USERNAME_RE.match(username):
        raise ValueError(
            "Username must be 1–39 chars, start alphanumeric, and contain only letters, digits, '.', '_' or '-'."
        )

    sites = _load_sites()
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
        task = progress.add_task(f"Hunting [bold]{username}[/]…", total=len(sites))

        async def runner(site: dict[str, Any]) -> Hit:
            hit = await _check_site(client, site, username)
            progress.advance(task)
            return hit

        results = await asyncio.gather(*(runner(s) for s in sites))
        for r in results:
            report.add(r)

    return report
