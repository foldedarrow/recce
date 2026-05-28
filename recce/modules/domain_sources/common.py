# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared helpers for domain source adapters."""

from __future__ import annotations

import re
from typing import Any

import dns.asyncresolver
import dns.exception


async def dns_lookup(name: str, rtype: str) -> tuple[list[str], str | None]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 4
    try:
        answers = await resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NoAnswer"
    except dns.resolver.NoNameservers:
        return [], "NoNameservers"
    except dns.exception.DNSException as e:
        return [], str(e)[:120]
    records = []
    for answer in answers:
        if rtype == "MX":
            exchange = str(answer.exchange).rstrip(".") or "."
            records.append(f"{answer.preference} {exchange}")
        elif rtype == "TXT":
            records.append("".join(part.decode(errors="replace") for part in answer.strings))
        else:
            records.append(str(answer).rstrip("."))
    return sorted(set(records)), None


def normalise_subdomain(value: str, domain: str) -> str | None:
    host = value.strip().lower().lstrip("*.").rstrip(".")
    if not host or host == domain or not host.endswith(f".{domain}"):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    return host


def safe_json(resp: Any, default: Any | None = None) -> Any:
    try:
        return resp.json()
    except Exception:
        return {} if default is None else default


def txt_tag(record: str, tag: str) -> str | None:
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}=([^;]+)", record, flags=re.I)
    return match.group(1).strip() if match else None


def xml_tag(text: str, tag: str) -> str | None:
    match = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, flags=re.I | re.S)
    return match.group(1).strip() if match else None
