# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wayback Machine CDX lookups shared by the domain and username modules.

archive.org rate-limits hard (and blocks an IP for a while after repeated
429s), so callers keep concurrency low and stop at the first 429. CDX also
answers 503 within seconds when one IP sends requests in parallel, so
`capture` retries a 503 once after a pause.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

CDX = "https://web.archive.org/cdx/search/cdx"
# CDX takes 7-26s for popular profile URLs (measured from the box); recce's
# default 12s request timeout cut most of them off.
CDX_TIMEOUT = 45.0
BUSY_RETRY_DELAY = 4.0


class ArchiveRateLimitError(Exception):
    """archive.org answered 429; stop sending it requests for this run."""


@dataclass(frozen=True)
class Capture:
    timestamp: str
    original: str

    @property
    def date(self) -> str:
        ts = self.timestamp
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"

    @property
    def url(self) -> str:
        return f"https://web.archive.org/web/{self.timestamp}/{self.original}"


def calendar_url(url: str) -> str:
    return f"https://web.archive.org/web/*/{url}"


async def capture(client: Any, url: str, *, latest: bool = False) -> Capture | None:
    """First (or latest) HTTP-200 capture of `url`, None if never archived.

    Raises ArchiveRateLimitError on 429 and RuntimeError on other failures.
    """
    params = {
        "url": url,
        "output": "json",
        "fl": "timestamp,original",
        "filter": "statuscode:200",
        "limit": "-1" if latest else "1",
    }
    if latest:
        params["fastLatest"] = "true"
    resp = await client.get(CDX, params=params, timeout=CDX_TIMEOUT)
    if resp is not None and resp.status_code == 503:
        await asyncio.sleep(BUSY_RETRY_DELAY)
        resp = await client.get(CDX, params=params, timeout=CDX_TIMEOUT)
    if resp is None:
        raise RuntimeError("network")
    if resp.status_code == 429:
        raise ArchiveRateLimitError()
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    try:
        rows = resp.json() if resp.text.strip() else []
    except ValueError as e:
        raise RuntimeError("bad json") from e
    data = [row for row in rows[1:] if isinstance(row, list) and len(row) >= 2]
    if not data:
        return None
    ts, original = data[-1] if latest else data[0]
    return Capture(timestamp=str(ts), original=str(original))
