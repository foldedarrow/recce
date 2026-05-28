# SPDX-License-Identifier: AGPL-3.0-or-later
"""DNS and ASN enrichment domain source."""

from __future__ import annotations

import asyncio
import socket
import time

from recce.core.result import Hit, Status

from .common import dns_lookup
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    del ctx
    hits: list[Hit] = []
    for rtype in ("A", "AAAA", "NS", "SOA", "TXT", "CNAME"):
        started = time.perf_counter()
        records, error = await dns_lookup(domain, rtype)
        elapsed = int((time.perf_counter() - started) * 1000)
        if records:
            hits.append(
                Hit(
                    source=f"DNS {rtype}",
                    category="network",
                    status=Status.FOUND,
                    summary=", ".join(records[:6])
                    + (f", +{len(records) - 6} more" if len(records) > 6 else ""),
                    extra={"records": records},
                    confidence=0.9,
                    elapsed_ms=elapsed,
                )
            )
        else:
            status = Status.NOT_FOUND if error in {"NXDOMAIN", "NoAnswer"} else Status.ERROR
            hits.append(Hit(source=f"DNS {rtype}", category="network", status=status, summary=error, elapsed_ms=elapsed))
    ips = []
    for rtype in ("A", "AAAA"):
        records, _ = await dns_lookup(domain, rtype)
        ips.extend(records)
    for ip in ips[:8]:
        ptr_records, _ = await dns_lookup(ip, "PTR")
        asn = await asyncio.to_thread(_cymru_lookup, ip)
        parts = []
        if ptr_records:
            parts.append(f"PTR: {ptr_records[0]}")
        if asn:
            parts.append(f"ASN: {asn.get('asn')} {asn.get('name')}")
        if parts:
            hits.append(
                Hit(
                    source="IP enrichment",
                    category="network",
                    status=Status.FOUND,
                    summary=f"{ip} · " + " · ".join(parts),
                    extra={"ip": ip, "ptr": ptr_records, "asn": asn},
                    confidence=0.75,
                )
            )
    return hits


def _cymru_lookup(ip: str) -> dict[str, str] | None:
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=5) as sock:
            sock.sendall((f" -v {ip}\n").encode())
            text = sock.recv(4096).decode(errors="replace")
    except OSError:
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2 or "|" not in lines[1]:
        return None
    parts = [part.strip() for part in lines[1].split("|")]
    if len(parts) < 7:
        return None
    return {
        "asn": parts[0],
        "prefix": parts[2],
        "cc": parts[3],
        "registry": parts[4],
        "allocated": parts[5],
        "name": parts[6],
    }
