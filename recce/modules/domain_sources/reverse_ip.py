# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reverse IP: other domains hosted on the domain's first IPv4 address.

Uses HackerTarget's keyless reverse lookup (a small daily quota per IP).
On shared hosting or a CDN the list is long and says little about
ownership, so large results are flagged as weak.
"""

from __future__ import annotations

import time

from recce.core.result import Hit, Status

from .common import dns_lookup
from .registry import SourceContext

SOURCE = "Reverse IP"
SHARED_THRESHOLD = 50
SHOWN = 8


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    records, _ = await dns_lookup(domain, "A")
    if not records:
        return [Hit(source=SOURCE, category="network", status=Status.NOT_FOUND, summary="no A record")]
    ip = records[0]
    started = time.perf_counter()
    resp = await ctx.client.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip})
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return [Hit(source=SOURCE, category="network", status=Status.ERROR, error="network", elapsed_ms=elapsed)]
    text = resp.text.strip()
    if resp.status_code == 429 or "api count exceeded" in text.lower():
        return [
            Hit(source=SOURCE, category="network", status=Status.SKIPPED,
                summary="HackerTarget daily quota used up", elapsed_ms=elapsed)
        ]
    if resp.status_code != 200 or text.lower().startswith("error"):
        return [
            Hit(source=SOURCE, category="network", status=Status.UNKNOWN,
                summary=text[:80] or f"HTTP {resp.status_code}", elapsed_ms=elapsed)
        ]
    hosted = sorted(
        {
            line.strip().lower().rstrip(".")
            for line in text.splitlines()
            if "." in line and " " not in line.strip()
        }
    )
    others = [d for d in hosted if d != domain and not d.endswith(f".{domain}")]
    if not others:
        return [
            Hit(source=SOURCE, category="network", status=Status.NOT_FOUND,
                summary=f"{ip} hosts no other known domains", elapsed_ms=elapsed,
                extra={"ip": ip})
        ]
    shared = len(hosted) >= SHARED_THRESHOLD
    summary = f"{ip} also hosts {len(others)} other domain(s): " + ", ".join(others[:SHOWN])
    if len(others) > SHOWN:
        summary += f", +{len(others) - SHOWN} more"
    if shared:
        summary += " · shared hosting/CDN, weak link"
    return [
        Hit(
            source=SOURCE,
            category="network",
            status=Status.FOUND,
            url=f"https://hackertarget.com/reverse-ip-lookup/?q={ip}",
            summary=summary,
            confidence=0.4 if shared else 0.7,
            elapsed_ms=elapsed,
            extra={"ip": ip, "domains": others[:200], "total": len(others), "shared": shared},
        )
    ]
