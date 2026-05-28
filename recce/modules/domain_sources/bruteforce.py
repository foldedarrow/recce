# SPDX-License-Identifier: AGPL-3.0-or-later
"""Consent-gated active subdomain bruteforce source."""

from __future__ import annotations

import asyncio
import random
from functools import lru_cache
from importlib import resources

from recce.core.result import Hit, Status

from .common import dns_lookup

BRUTEFORCE_WORDLIST_FILES = {
    "small": "subdomains-1000.txt",
    "medium": "subdomains-5000.txt",
    "big": "subdomains-20000.txt",
}
BRUTEFORCE_WORDLIST_COUNTS = {"small": 1000, "medium": 5000, "big": 20000}


async def query(
    domain: str,
    *,
    wordlist: str,
    concurrency: int,
    rate: int,
) -> list[Hit]:
    labels = load_bruteforce_wordlist(wordlist)
    wildcard_label = f"{random.randrange(10**10, 10**11)}-recce-check"
    wildcard_records, _ = await dns_lookup(f"{wildcard_label}.{domain}", "A")
    if wildcard_records:
        return [
            Hit(
                source="Subdomain bruteforce",
                category="subs",
                status=Status.UNKNOWN,
                summary="Wildcard DNS detected; bruteforce results would be noisy.",
                extra={"wildcard_records": wildcard_records},
                confidence=0.4,
            )
        ]
    sem = asyncio.Semaphore(max(1, concurrency))
    delay = 1 / max(1, rate)
    hits: list[str] = []

    async def check(idx: int, label: str) -> None:
        await asyncio.sleep(idx * delay / max(1, concurrency))
        async with sem:
            host = f"{label}.{domain}"
            records, _ = await dns_lookup(host, "A")
            records6, _ = await dns_lookup(host, "AAAA")
            if records or records6:
                hits.append(host)

    await asyncio.gather(*(check(idx, label) for idx, label in enumerate(labels)))
    return [
        Hit(
            source="Subdomain bruteforce",
            category="subs",
            status=Status.FOUND if hits else Status.NOT_FOUND,
            summary=f"{len(hits)} resolving subdomain(s) from {wordlist} wordlist ({len(labels)} labels checked)",
            extra={"subdomains": sorted(hits), "wordlist": wordlist, "labels_checked": len(labels)},
            confidence=0.75,
        )
    ]


@lru_cache(maxsize=3)
def load_bruteforce_wordlist(name: str) -> tuple[str, ...]:
    if name not in BRUTEFORCE_WORDLIST_FILES:
        raise ValueError("bruteforce wordlist must be one of: small, medium, big")
    raw = (
        resources.files("recce.data")
        .joinpath("wordlists")
        .joinpath(BRUTEFORCE_WORDLIST_FILES[name])
        .read_text()
    )
    labels = tuple(
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    expected = BRUTEFORCE_WORDLIST_COUNTS[name]
    if len(labels) != expected:
        raise RuntimeError(f"{name} wordlist has {len(labels)} entries; expected {expected}")
    return labels
