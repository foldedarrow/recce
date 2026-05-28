# SPDX-License-Identifier: AGPL-3.0-or-later
"""Email lookups: Gravatar, MX, EmailRep, HIBP, Hunter."""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any

import dns.asyncresolver
import dns.exception

from ..config import Settings
from ..core.http import HttpClient
from ..core.result import Hit, Report, Status
from ..providers import query_registered_providers

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _md5(s: str) -> str:
    return hashlib.md5(s.strip().lower().encode()).hexdigest()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.strip().lower().encode()).hexdigest()


async def _gravatar(email: str, client: HttpClient) -> Hit:
    started = time.perf_counter()
    digest = _sha256(email)
    profile_url = f"https://gravatar.com/{digest}"
    api_url = f"https://gravatar.com/{digest}.json"
    resp = await client.get(api_url)
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return Hit(source="Gravatar", category="profile", status=Status.ERROR, error="network", elapsed_ms=elapsed)
    if resp.status_code == 404:
        return Hit(source="Gravatar", category="profile", status=Status.NOT_FOUND, elapsed_ms=elapsed,
                   summary="No Gravatar registered")
    if resp.status_code != 200:
        return Hit(source="Gravatar", category="profile", status=Status.UNKNOWN,
                   summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)
    try:
        data = resp.json()
        entry = (data.get("entry") or [{}])[0]
    except Exception:
        return Hit(source="Gravatar", category="profile", status=Status.FOUND,
                   url=profile_url, elapsed_ms=elapsed, summary="profile exists (json parse failed)")
    parts = []
    if entry.get("displayName"):
        parts.append(entry["displayName"])
    if entry.get("currentLocation"):
        parts.append(f"📍 {entry['currentLocation']}")
    if entry.get("aboutMe"):
        bio = entry["aboutMe"][:80].replace("\n", " ")
        parts.append(f"“{bio}”")
    accounts = entry.get("accounts") or []
    extra: dict[str, Any] = {"accounts": [a.get("url") for a in accounts if a.get("url")]}
    if accounts:
        parts.append(f"{len(accounts)} linked accounts")
    return Hit(
        source="Gravatar",
        category="profile",
        status=Status.FOUND,
        url=profile_url,
        summary=" · ".join(parts) if parts else "Gravatar exists",
        confidence=0.95,
        extra=extra,
        elapsed_ms=elapsed,
    )


async def _mx(email: str) -> Hit:
    domain = email.split("@", 1)[1]
    started = time.perf_counter()
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 4
    try:
        answers = await resolver.resolve(domain, "MX")
        records = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
        elapsed = int((time.perf_counter() - started) * 1000)
        top = records[0][1] if records else None
        provider = _identify_provider(top or "")
        summary = f"MX → {top}"
        if provider:
            summary += f"  ({provider})"
        return Hit(
            source="DNS / MX",
            category="domain",
            status=Status.FOUND,
            summary=summary,
            extra={"records": [r[1] for r in records], "provider": provider},
            confidence=0.9,
            elapsed_ms=elapsed,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        elapsed = int((time.perf_counter() - started) * 1000)
        return Hit(
            source="DNS / MX",
            category="domain",
            status=Status.NOT_FOUND,
            summary=f"No MX records — {domain} cannot receive mail",
            elapsed_ms=elapsed,
        )
    except (dns.exception.DNSException, Exception) as e:
        elapsed = int((time.perf_counter() - started) * 1000)
        return Hit(source="DNS / MX", category="domain", status=Status.ERROR,
                   error=str(e)[:120], elapsed_ms=elapsed)


def _identify_provider(mx_host: str) -> str | None:
    h = mx_host.lower()
    table = [
        ("google", "Google Workspace / Gmail"),
        ("outlook", "Microsoft 365 / Outlook"),
        ("protection.outlook", "Microsoft 365"),
        ("zoho", "Zoho"),
        ("yahoodns", "Yahoo"),
        ("yandex", "Yandex"),
        ("protonmail", "Proton Mail"),
        ("proton.ch", "Proton Mail"),
        ("fastmail", "Fastmail"),
        ("mailgun", "Mailgun (transactional)"),
        ("sendgrid", "SendGrid (transactional)"),
        ("amazonses", "Amazon SES (transactional)"),
        ("ovh", "OVH"),
        ("ionos", "IONOS"),
        ("hetzner", "Hetzner"),
        ("registrar-servers.com", "Namecheap Private Email"),
        ("forwardemail", "ForwardEmail"),
        ("improvmx", "ImprovMX"),
        ("simplelogin", "SimpleLogin (alias)"),
        ("duck.com", "DuckDuckGo Email Protection (alias)"),
        ("icloud.com", "iCloud (incl. Hide My Email aliases)"),
    ]
    for needle, label in table:
        if needle in h:
            return label
    return None


async def _emailrep(email: str, client: HttpClient, settings: Settings) -> Hit:
    started = time.perf_counter()
    if not settings.provider_integrations_enabled:
        return Hit(
            source="EmailRep",
            category="reputation",
            status=Status.SKIPPED,
            summary="provider integrations disabled",
            elapsed_ms=0,
        )
    headers = {"User-Agent": "recce-osint", "Accept": "application/json"}
    if settings.emailrep_api_key:
        headers["Key"] = settings.emailrep_api_key
    resp = await client.get(f"https://emailrep.io/{email}", headers=headers)
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return Hit(source="EmailRep", category="reputation", status=Status.ERROR,
                   error="network", elapsed_ms=elapsed)
    if resp.status_code == 429:
        return Hit(source="EmailRep", category="reputation", status=Status.SKIPPED,
                   summary="rate-limited (set EMAILREP_API_KEY)", elapsed_ms=elapsed)
    if resp.status_code != 200:
        return Hit(source="EmailRep", category="reputation", status=Status.UNKNOWN,
                   summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)
    try:
        data = resp.json()
    except Exception:
        return Hit(source="EmailRep", category="reputation", status=Status.UNKNOWN,
                   summary="bad json", elapsed_ms=elapsed)

    details = data.get("details", {})
    profiles: list[str] = details.get("profiles", []) or []
    rep = data.get("reputation", "unknown")
    suspicious = data.get("suspicious", False)
    parts = [f"reputation: {rep}"]
    if details.get("first_seen") and details["first_seen"] != "never":
        parts.append(f"first seen {details['first_seen']}")
    if details.get("data_breach"):
        parts.append("⚠ in data breaches")
    if details.get("malicious_activity"):
        parts.append("⚠ malicious activity")
    if profiles:
        parts.append(f"profiles: {', '.join(profiles)}")
    if suspicious:
        parts.append("flagged suspicious")
    return Hit(
        source="EmailRep",
        category="reputation",
        status=Status.FOUND if (profiles or rep != "none") else Status.NOT_FOUND,
        summary=" · ".join(parts),
        extra={"profiles": profiles, "reputation": rep, "details": details},
        confidence=0.8,
        elapsed_ms=elapsed,
    )


async def _hunter(email: str, client: HttpClient, settings: Settings) -> Hit:
    started = time.perf_counter()
    if not settings.provider_integrations_enabled:
        return Hit(
            source="Hunter.io",
            category="verification",
            status=Status.SKIPPED,
            summary="provider integrations disabled",
            elapsed_ms=0,
        )
    if not settings.hunter_api_key:
        return Hit(
            source="Hunter.io",
            category="verification",
            status=Status.SKIPPED,
            summary="set HUNTER_API_KEY in .env to enable verification",
            elapsed_ms=0,
        )
    resp = await client.get(
        "https://api.hunter.io/v2/email-verifier",
        params={"email": email, "api_key": settings.hunter_api_key},
    )
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None or resp.status_code != 200:
        code = "?" if resp is None else resp.status_code
        return Hit(source="Hunter.io", category="verification", status=Status.UNKNOWN,
                   summary=f"HTTP {code}", elapsed_ms=elapsed)
    try:
        data = resp.json()["data"]
    except Exception:
        return Hit(source="Hunter.io", category="verification", status=Status.UNKNOWN,
                   summary="bad json", elapsed_ms=elapsed)
    parts = [
        f"status: {data.get('status', '?')}",
        f"score: {data.get('score', '?')}",
    ]
    if data.get("disposable"):
        parts.append("⚠ disposable")
    if data.get("webmail"):
        parts.append("webmail")
    if data.get("accept_all"):
        parts.append("accept-all domain")
    sources = data.get("sources") or []
    if sources:
        parts.append(f"seen on {len(sources)} site(s)")
    return Hit(
        source="Hunter.io",
        category="verification",
        status=Status.FOUND if data.get("status") in ("valid", "accept_all", "webmail") else Status.NOT_FOUND,
        summary=" · ".join(parts),
        extra={"sources": sources, "raw": data},
        confidence=0.85,
        elapsed_ms=elapsed,
    )


async def _username_pivot(email: str) -> Hit:
    """The local-part of an email is often used as a username elsewhere.

    We don't actually search here — we just emit a Hit suggesting the pivot,
    with the local-part as the suggested username so the CLI can prompt the
    user to run a username search.
    """
    local = email.split("@", 1)[0]
    return Hit(
        source="Username pivot",
        category="pivot",
        status=Status.FOUND,
        summary=f"try `recce username {local}` — local-part is often reused",
        extra={"username": local},
        confidence=0.4,
    )


async def search_email(
    email: str,
    client: HttpClient,
    settings: Settings,
    *,
    skip_provider_ids: set[str] | None = None,
) -> Report:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError(f"'{email}' doesn't look like a valid email address.")

    report = Report(query=email, query_type="email")
    coros = [
        _gravatar(email, client),
        _mx(email),
        _emailrep(email, client, settings),
        _hunter(email, client, settings),
        _username_pivot(email),
    ]
    for hit in await asyncio.gather(*coros):
        report.add(hit)
    for hit in await query_registered_providers(
        email,
        "email",
        client,
        settings,
        skip_provider_ids=skip_provider_ids,
    ):
        report.add(hit)
    report.finish()
    return report
