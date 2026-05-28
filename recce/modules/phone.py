# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phone number lookups: libphonenumber + optional NumVerify."""

from __future__ import annotations

import asyncio
import time

import phonenumbers
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as pn_timezone

from ..config import Settings
from ..core.http import HttpClient
from ..core.result import Hit, Report, Status


def _parse(phone: str, default_region: str | None = None) -> Hit:
    started = time.perf_counter()
    try:
        parsed = phonenumbers.parse(phone, default_region)
    except phonenumbers.NumberParseException as e:
        return Hit(
            source="libphonenumber",
            category="format",
            status=Status.ERROR,
            error=f"parse failed: {e}",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    region = phonenumbers.region_code_for_number(parsed) or "?"
    line_type = phonenumbers.number_type(parsed)
    type_name = {
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "mobile/landline",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium-rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "shared-cost",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
        phonenumbers.PhoneNumberType.PAGER: "pager",
        phonenumbers.PhoneNumberType.UAN: "UAN",
        phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    }.get(line_type, "unknown")

    geo = geocoder.description_for_number(parsed, "en") or "?"
    car = carrier.name_for_number(parsed, "en") or "?"
    tzs = pn_timezone.time_zones_for_number(parsed) or ()

    summary_parts = [
        f"E.164: {e164}",
        f"region: {region}",
        f"type: {type_name}",
    ]
    if geo and geo != "?":
        summary_parts.append(f"area: {geo}")
    if car and car != "?":
        summary_parts.append(f"carrier: {car}")
    if tzs:
        summary_parts.append("tz: " + ", ".join(tzs[:3]))
    if not valid:
        summary_parts.append("⚠ NOT a valid number" + ("" if possible else " (and not even possible)"))

    return Hit(
        source="libphonenumber",
        category="format",
        status=Status.FOUND if valid else Status.UNKNOWN,
        summary=" · ".join(summary_parts),
        extra={
            "e164": e164,
            "international": intl,
            "national": national,
            "region": region,
            "type": type_name,
            "geo": geo,
            "carrier": car,
            "timezones": list(tzs),
            "valid": valid,
            "possible": possible,
        },
        confidence=0.99 if valid else 0.4,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


async def _numverify(e164: str, client: HttpClient, settings: Settings) -> Hit:
    started = time.perf_counter()
    if not settings.provider_integrations_enabled:
        return Hit(
            source="NumVerify",
            category="carrier",
            status=Status.SKIPPED,
            summary="provider integrations disabled",
            elapsed_ms=0,
        )
    if not settings.numverify_api_key:
        return Hit(
            source="NumVerify",
            category="carrier",
            status=Status.SKIPPED,
            summary="set NUMVERIFY_API_KEY in .env (free tier: 100/mo)",
            elapsed_ms=0,
        )
    resp = await client.get(
        "https://apilayer.net/api/validate",
        params={
            "access_key": settings.numverify_api_key,
            "number": e164.lstrip("+"),
            "format": 1,
        },
    )
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None or resp.status_code != 200:
        code = "?" if resp is None else resp.status_code
        return Hit(source="NumVerify", category="carrier", status=Status.UNKNOWN,
                   summary=f"HTTP {code}", elapsed_ms=elapsed)
    try:
        data = resp.json()
    except Exception:
        return Hit(source="NumVerify", category="carrier", status=Status.UNKNOWN,
                   summary="bad json", elapsed_ms=elapsed)
    if data.get("error"):
        return Hit(source="NumVerify", category="carrier", status=Status.ERROR,
                   error=data["error"].get("info", "unknown"), elapsed_ms=elapsed)
    if not data.get("valid"):
        return Hit(source="NumVerify", category="carrier", status=Status.NOT_FOUND,
                   summary="reported as invalid", elapsed_ms=elapsed)
    parts = []
    for k in ("country_name", "location", "carrier", "line_type"):
        if data.get(k):
            parts.append(f"{k.replace('_', ' ')}: {data[k]}")
    return Hit(
        source="NumVerify",
        category="carrier",
        status=Status.FOUND,
        summary=" · ".join(parts),
        extra=data,
        confidence=0.9,
        elapsed_ms=elapsed,
    )


def _pivot_hits(e164: str, intl: str, national: str, region: str) -> list[Hit]:
    """Suggest where to check this number manually. We don't probe these
    automatically — most messaging apps' lookups require an authenticated
    client, and probing them can leak intent to the target.
    """
    import re as _re
    from urllib.parse import quote
    bare = e164.lstrip("+")
    national_digits = _re.sub(r"\D", "", national or "")
    cc = (region or "").lower()
    truecaller_url = (
        f"https://www.truecaller.com/search/{cc}/{national_digits}"
        if cc and national_digits else f"https://www.truecaller.com/search/{bare}"
    )
    google_q = quote(f'"{intl}" OR "{national}"')
    sync_q = quote(e164)
    hits = [
        Hit(
            source="WhatsApp",
            category="pivot",
            status=Status.FOUND,
            url=f"https://wa.me/{bare}",
            summary="opens a chat — visiting alone does NOT notify the number",
            confidence=0.4,
        ),
        Hit(
            source="Google web",
            category="pivot",
            status=Status.FOUND,
            url=f"https://www.google.com/search?q={google_q}",
            summary="search the web for either format of the number (often surfaces forum posts / classified ads)",
            confidence=0.5,
        ),
        Hit(
            source="Truecaller",
            category="pivot",
            status=Status.FOUND,
            url=truecaller_url,
            summary="manual reverse-lookup — first few lookups free, then login wall",
            confidence=0.3,
        ),
        Hit(
            source="Sync.me",
            category="pivot",
            status=Status.FOUND,
            url=f"https://sync.me/search/?number={sync_q}",
            summary="alternative reverse-lookup — free preview, login for full",
            confidence=0.3,
        ),
        Hit(
            source="Telegram / Signal",
            category="pivot",
            status=Status.FOUND,
            summary="no public lookup by phone — must import as a contact in your own app",
            confidence=0.2,
        ),
    ]
    return hits


async def search_phone(
    phone: str,
    client: HttpClient,
    settings: Settings,
    *,
    default_region: str | None = "GB",
) -> Report:
    report = Report(query=phone, query_type="phone")
    parsed_hit = _parse(phone, default_region)
    report.add(parsed_hit)

    e164 = parsed_hit.extra.get("e164") if parsed_hit.is_found else None
    if not e164:
        report.add(
            Hit(
                source="recce",
                category="meta",
                status=Status.ERROR,
                summary="number didn't parse — skipping remote lookups. "
                        "Pass a region (e.g. --region US) or include the country code (e.g. +44...)",
            )
        )
        report.finish()
        return report

    intl = parsed_hit.extra.get("international", e164)
    national = parsed_hit.extra.get("national", e164)
    region = parsed_hit.extra.get("region", default_region or "")
    for h in _pivot_hits(e164, intl, national, region):
        report.add(h)

    rest = await asyncio.gather(
        _numverify(e164, client, settings),
    )
    for h in rest:
        report.add(h)
    report.finish()
    return report
