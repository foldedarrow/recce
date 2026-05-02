"""Phone number lookups: libphonenumber + optional NumVerify."""

from __future__ import annotations

import asyncio
import time

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone

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
    except Exception:  # noqa: BLE001
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


async def _messaging_pivots(e164: str) -> Hit:
    """Suggest where this number could be checked manually (we won't probe these
    automatically — most messaging apps' lookups require an authenticated client
    and probing them violates ToS / can leak intent to the target).
    """
    bare = e164.lstrip("+")
    suggestions = [
        f"WhatsApp:  https://wa.me/{bare}  (opens chat — visiting will *not* notify the number)",
        f"Telegram:  search @username or use a contact-import client",
        f"Signal:    requires the number be in your contacts; no public lookup",
        f"Truecaller: https://www.truecaller.com/search/{e164.replace('+', '')}  (manual; rate-limited)",
    ]
    return Hit(
        source="Manual pivots",
        category="pivot",
        status=Status.FOUND,
        summary="messaging apps don't allow programmatic lookup — try these manually",
        extra={"suggestions": suggestions},
        confidence=0.3,
    )


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
        return report

    rest = await asyncio.gather(
        _numverify(e164, client, settings),
        _messaging_pivots(e164),
    )
    for h in rest:
        report.add(h)
    return report
