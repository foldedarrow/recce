# SPDX-License-Identifier: AGPL-3.0-or-later
"""RDAP ownership source."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from recce.core.result import Hit, Status

from .common import safe_json
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> Hit:
    started = time.perf_counter()
    resp = await ctx.client.get(f"https://rdap.org/domain/{domain}")
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return Hit(source="RDAP", category="ownership", status=Status.ERROR, error="network")
    if resp.status_code == 404:
        return Hit(source="RDAP", category="ownership", status=Status.NOT_FOUND, summary="No RDAP record")
    if resp.status_code >= 400:
        return Hit(source="RDAP", category="ownership", status=Status.UNKNOWN, summary=f"HTTP {resp.status_code}")

    data = safe_json(resp)
    created = _rdap_event(data, "registration")
    expires = _rdap_event(data, "expiration")
    updated = _rdap_event(data, "last changed")
    registrar = _rdap_registrar(data)
    org = _rdap_org(data)
    parts = []
    if registrar:
        parts.append(f"registrar: {registrar}")
    if created:
        parts.append(f"created: {created[:10]}")
        age = _domain_age_days(created)
        if age is not None:
            parts.append(f"age: {age // 365}y {age % 365}d")
    if expires:
        parts.append(f"expires: {expires[:10]}")
    if org:
        parts.append(f"org: {org}")
    status = Status.FOUND if parts else Status.UNKNOWN
    return Hit(
        source="RDAP",
        category="ownership",
        status=status,
        url=f"https://rdap.org/domain/{domain}",
        summary=" · ".join(parts) if parts else "RDAP record returned",
        extra={"created": created, "expires": expires, "updated": updated, "registrar": registrar, "org": org},
        confidence=0.9,
        elapsed_ms=elapsed,
    )


def _rdap_event(data: dict[str, Any], action: str) -> str | None:
    for event in data.get("events") or []:
        if str(event.get("eventAction", "")).lower() == action:
            return event.get("eventDate")
    return None


def _rdap_registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        roles = {str(role).lower() for role in entity.get("roles") or []}
        if "registrar" in roles:
            return _vcard_name(entity)
    return None


def _rdap_org(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        roles = {str(role).lower() for role in entity.get("roles") or []}
        if roles & {"registrant", "administrative", "technical"}:
            name = _vcard_name(entity)
            if name and "redacted" not in name.lower():
                return name
    return None


def _vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray") or [None, []]
    entries = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
    for item in entries:
        if item and item[0] in {"fn", "org"} and len(item) > 3:
            value = item[3]
            if isinstance(value, list):
                return " ".join(str(v) for v in value if v)
            return str(value)
    return entity.get("handle")


def _domain_age_days(created: str) -> int | None:
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days
