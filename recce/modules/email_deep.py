# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep email search — wraps the holehe library's signup/reset-endpoint
probes to discover which sites have an account registered to an email.

Holehe 1.61 ships 121 probe modules; after the 2026-10-08 audit about 30
still give real answers (see the skip lists below). We run those
concurrently against a shared HTTP client, convert each module's output into
our Hit type, and re-probe every "found" site with a made-up address at the
same domain, downgrading sites that "find" that too.

Each holehe probe returns a dict with shape::

    {
        "name": "spotify",
        "domain": "spotify.com",
        "method": "register",         # how it probes
        "rateLimit": False,
        "frequent_rate_limit": False, # static hint
        "exists": True | False | None,
        "emailrecovery": "k****@p***.me" | None,
        "phoneNumber": "+44 ****" | None,
        "others": ... | None,
    }
"""

from __future__ import annotations

import asyncio
import secrets
import string
import time
from typing import Any

import httpx
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..core.output import console
from ..core.result import Hit, Status

# Every holehe 1.61 module was audited on 2026-10-08 (roadmap #6): each ran
# against two addresses the operator owns plus made-up ones, from the VM's
# Proton exit, Tor and a residential line; the raw HTTP exchanges were read
# to tell a real "not registered" answer from holehe's silent fall-through to
# `exists: False`. Modules below are skipped. Reassess when holehe (or a
# replacement) ships an update; the per-module table is docs/HOLEHE_AUDIT.md.

# Probes that could alert the address owner: they submit a password, create or
# start an account, or walk a password-reset flow. Never run these, even if a
# future holehe release repairs them.
NOTIFYING_HOLEHE_MODULES: dict[str, str] = {
    "adobe": "password-recovery challenge flow; existing accounts fail there and read as rate-limited",
    "aboutme": "posts a sign-up form (endpoint now 302 -> 404)",
    "devrant": "posts a registration (rejected for the blank username before the email is checked)",
    "discord": "posts a full registration with consent; only the missing date of birth stops it",
    "docker": "posts a sign-up (endpoint 404)",
    "hubspot": "submits a sign-in with a blank password",
    "mail_ru": "password-restore endpoint (and posts the literal text '{email}', so never finds anything)",
    "nutshell": "submits a sign-in with a wrong password (now refused: 'disable your adblocker')",
    "odnoklassniki": "password-recovery flow (the address no longer reaches the recovery page: always false)",
    "parler": "submits a sign-in with a wrong password (API redirects to the app: always false)",
    "pipedrive": "starts a sign-up for addresses that are free (Cloudflare 403 from every exit)",
    "samsung": "walks the resetPassword flow",
    "seoclerks": "submits a full sign-up (refused on captcha: always false)",
    "sevencups": "posts to CreateAccount.php (CloudFront 403)",
    "venmo": "posts a new-user record (crashes on an undefined name first)",
    "vivino": "submits a sign-in with a wrong password (CSRF token fetched from tunefind.com: never works)",
}

# Permanently broken from every exit tested: stale endpoints, dead domains,
# changed sign-up flows, answers that say "not registered" for everything, or
# bot walls that block the VPN, Tor and a residential IP alike.
BROKEN_HOLEHE_MODULES: dict[str, str] = {
    # always "registered"
    "protonmail": "always true: Proton's key server returns a key for made-up Proton-domain addresses",
    # say "not registered" whatever the input
    "amazon": "sign-in POST answers 404: always false",
    "archive": "sign-up check redirects to /signup: always false",
    "armurerieauxerre": "endpoint answers 410 Gone: always false",
    "biotechnologyforums": "MyBB 'authorization code mismatch': always false",
    "blitzortung": "availability check redirects to the forum index: always false",
    "caringbridge": "sign-in POST answers 405: always false",
    "dominosfr": "Akamai 403 read as not registered: always false",
    "envato": "Cloudflare 403 read as not registered: always false",
    "fanpop": "registration closed ('currently unavailable'): always false",
    "flickr": "identity API answers 'cognito error': always false",
    "laposte": "endpoint 404: always false",
    "mybb": "availability check returns the HTML forum page: always false",
    "ndemiccreations": "availability check returns an empty body: always false",
    "taringa": "availability API returns the HTML app shell: always false",
    "tellonym": "API wants a token (403 TOKEN_INVALID): always false",
    # error out, or report every input as rate-limited
    "amocrm": "moved to kommo.com; the check answers 405",
    "atlassian": "login page no longer carries the CSRF token",
    "badeggsonline": "forum answers with PHP warnings instead of a token",
    "bitmoji": "Snapchat's login page changed (v2); token not found",
    "blip": "consistently times out",
    "buymeacoffee": "AttributeError on the response shape",
    "chinaphonearena": "DNS gone",
    "cpahero": "TLS certificate no longer matches the host",
    "cracked_to": "DNS gone",
    "crevado": "site answers 404; IndexError",
    "deliveroo": "DNS gone",
    "ello": "Cloudflare 520 (Ello shut down)",
    "evernote": "login moved to accounts.evernote.com; IndexError",
    "firefox": "account-status API answers 406",
    "freiberg": "forum 404",
    "garmin": "sign-up token missing from the page",
    "github": "sign-up page 403s; IndexError",
    "google": "sign-up moved to the lifecycle flow; token not found",
    "imgur": "email check answers 406/403",
    "instagram": "sign-up page no longer carries the CSRF token",
    "issuu": "check endpoint 503 (no_route)",
    "komoot": "sign-in endpoint 404",
    "nattyornot": "DNS gone",
    "nike": "DNS gone (unite.nike.com)",
    "nocrm": "check endpoint 404",
    "patreon": "email-available API 404",
    "pinterest": "EmailExistsResource 403; JSONDecodeError",
    "pornhub": "check endpoint 404/410",
    "rocketreach": "validateEmail 404; KeyError",
    "snapchat": "login page changed (v2); IndexError",
    "soundcloud": "client id no longer scrapeable; IndexError",
    "strava": "email_unique endpoint 404",
    "teamleader": "availability API returns the HTML app shell",
    "thevapingforum": "domain for sale",
    "tumblr": "API token no longer found in the page",
    "tunefind": "join page 404",
    "voxmedia": "Fastly 'unknown domain'",
    "xing": "sign-up page 404",
    "yahoo": "login page no longer carries acrumb; times out over Tor",
    # bot walls on the Proton exit, Tor and a residential line alike
    "babeshows": "Cloudflare challenge from every exit",
    "blablacar": "DataDome captcha from every exit",
    "blackworldforum": "403 'forbidden by administrative rules' from every exit",
    "bluegrassrivals": "Cloudflare 403 from every exit",
    "cambridgemt": "Cloudflare challenge from every exit",
    "codecademy": "bot check (/errors/browser) from every exit",
    "codeigniter": "Cloudflare challenge from every exit",
    "codepen": "Cloudflare challenge from every exit",
    "cpaelites": "Cloudflare 403 from every exit",
    "demonforums": "Cloudflare challenge from every exit",
    "ebay": "Distil / 403 bot wall from every exit",
    "nimble": "Cloudflare challenge from every exit",
    "quora": "Cloudflare challenge from every exit",
    "smule": "Cloudflare challenge on most requests from every exit",
    "therianguide": "429 'you're a spambot' from every exit",
    "vrbo": "429 'Bot or Not?' from every exit",
    "vsco": "Cloudflare 403 from every exit",
}

SKIPPED_HOLEHE_MODULES: frozenset[str] = frozenset(NOTIFYING_HOLEHE_MODULES) | frozenset(
    BROKEN_HOLEHE_MODULES
)


def _load_modules() -> list[tuple[str, str, Any]]:
    """Return [(category, site_name, callable), …] for every holehe leaf module
    that isn't skipped as notifying or broken."""
    import holehe.modules as root
    from holehe.core import import_submodules

    sites = import_submodules(root)
    out: list[tuple[str, str, Any]] = []
    for module_path, module in sites.items():
        parts = module_path.split(".")
        if len(parts) < 4:
            continue
        category = parts[2]
        site_name = parts[-1]
        if site_name in SKIPPED_HOLEHE_MODULES:
            continue
        fn = getattr(module, site_name, None)
        if fn is None or not callable(fn):
            continue
        out.append((category, site_name, fn))
    return out


def _to_hit(category: str, site_name: str, raw: dict[str, Any], elapsed_ms: int) -> Hit:
    if raw.get("rateLimit"):
        return Hit(
            source=site_name,
            category=f"deep/{category}",
            status=Status.SKIPPED,
            url=f"https://{raw.get('domain', '')}",
            summary="rate-limited",
            elapsed_ms=elapsed_ms,
        )
    exists = raw.get("exists")
    if exists is True:
        bits = []
        if raw.get("emailrecovery"):
            bits.append(f"recovery hint: {raw['emailrecovery']}")
        if raw.get("phoneNumber"):
            bits.append(f"recovery phone: {raw['phoneNumber']}")
        if raw.get("others"):
            bits.append(f"other: {raw['others']}")
        summary = " · ".join(bits) if bits else "account registered"
        return Hit(
            source=site_name,
            category=f"deep/{category}",
            status=Status.FOUND,
            url=f"https://{raw.get('domain', '')}",
            summary=summary,
            extra={k: v for k, v in raw.items() if k not in {"name", "domain"}},
            confidence=0.85,
            elapsed_ms=elapsed_ms,
        )
    if exists is False:
        return Hit(
            source=site_name,
            category=f"deep/{category}",
            status=Status.NOT_FOUND,
            url=f"https://{raw.get('domain', '')}",
            elapsed_ms=elapsed_ms,
        )
    return Hit(
        source=site_name,
        category=f"deep/{category}",
        status=Status.UNKNOWN,
        url=f"https://{raw.get('domain', '')}",
        summary="probe inconclusive",
        elapsed_ms=elapsed_ms,
    )


async def _run_one(
    category: str,
    site_name: str,
    fn: Any,
    email: str,
    client: httpx.AsyncClient,
    per_module_timeout: float,
) -> Hit:
    started = time.perf_counter()
    out: list[dict[str, Any]] = []
    try:
        await asyncio.wait_for(fn(email, client, out), timeout=per_module_timeout)
    except asyncio.TimeoutError:
        return Hit(
            source=site_name,
            category=f"deep/{category}",
            status=Status.SKIPPED,
            summary="timed out",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    except Exception as e:
        return Hit(
            source=site_name,
            category=f"deep/{category}",
            status=Status.ERROR,
            error=f"{type(e).__name__}: {e}"[:140],
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if not out:
        return Hit(
            source=site_name,
            category=f"deep/{category}",
            status=Status.UNKNOWN,
            summary="probe returned no result",
            elapsed_ms=elapsed_ms,
        )
    return _to_hit(category, site_name, out[0], elapsed_ms)


def _is_rate_limited(hit: Hit) -> bool:
    return hit.status is Status.SKIPPED and "rate" in (hit.summary or "").lower()


def _canary_email(email: str) -> str:
    """A made-up address at the target's own domain. Same domain, because some
    probes answer per domain (Proton's key server "knows" every made-up
    @pm.me address) and some sites refuse example.com outright."""
    alphabet = string.ascii_lowercase + string.digits
    local = "q" + "".join(secrets.choice(alphabet) for _ in range(15))
    domain = email.rpartition("@")[2] or "example.com"
    return f"{local}@{domain}"


async def _verify_found(
    modules: list[tuple[str, str, Any]],
    hits: list[Hit],
    client: httpx.AsyncClient,
    timeout: float,
    canary: str,
) -> None:
    """Re-probe every FOUND site with a made-up address. A site that also
    "finds" the made-up one says yes to anything, so the hit is unverifiable
    and is downgraded (mirrors the username canary)."""
    by_name = {name: (cat, fn) for cat, name, fn in modules}
    found = [hit for hit in hits if hit.status is Status.FOUND and hit.source in by_name]

    async def check(hit: Hit) -> None:
        cat, fn = by_name[hit.source]
        probe = await _run_one(cat, hit.source, fn, canary, client, per_module_timeout=timeout)
        hit.extra["canary"] = {"email": canary, "status": probe.status.value}
        if probe.status is Status.FOUND:
            hit.status = Status.UNKNOWN
            hit.summary = "unverifiable — site also reports a made-up address as registered"
            hit.confidence = 0.2

    await asyncio.gather(*(check(hit) for hit in found))


async def deep_email_probes(
    email: str,
    *,
    timeout: float = 12.0,
    max_concurrency: int = 20,
    proxy: str | None = None,
    show_progress: bool = True,
    retry: bool = True,
    retry_wait: float = 15.0,
    verify: bool = True,
) -> list[Hit]:
    """Run every holehe probe module against the given email, concurrently.

    If `retry=True`, modules that came back rate-limited are retried once
    after `retry_wait` seconds — many sites' rate-limit windows are short
    enough that a brief pause turns ~half of those into real hits.

    If `verify=True`, every FOUND site is re-probed with a made-up address at
    the same domain and downgraded to unknown if it "finds" that one too.
    """
    modules = _load_modules()

    # Holehe modules expect an httpx.AsyncClient. They often set their own
    # headers per-request, so we leave the client's defaults alone.
    client_kwargs: dict[str, Any] = {"timeout": timeout, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy
    client = httpx.AsyncClient(**client_kwargs)
    sem = asyncio.Semaphore(max(1, max_concurrency))

    async def run_pass(
        targets: list[tuple[str, str, Any]],
        progress_label: str,
    ) -> list[Hit]:
        async def guarded_run(cat: str, name: str, fn: Any) -> Hit:
            async with sem:
                return await _run_one(cat, name, fn, email, client, per_module_timeout=timeout)

        if not show_progress:
            return list(await asyncio.gather(
                *(guarded_run(c, n, fn) for c, n, fn in targets)
            ))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[bold]{task.completed}/{task.total}[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(progress_label, total=len(targets))

            async def runner(cat: str, name: str, fn: Any) -> Hit:
                hit = await guarded_run(cat, name, fn)
                progress.advance(task)
                return hit

            return list(await asyncio.gather(
                *(runner(c, n, fn) for c, n, fn in targets)
            ))

    async def retry_rate_limited(results: list[Hit]) -> None:
        rl_indices = [i for i, h in enumerate(results) if _is_rate_limited(h)]
        if not rl_indices:
            return

        retry_targets = [modules[i] for i in rl_indices]
        console.print(
            f"[dim]→ {len(retry_targets)} probes were rate-limited. "
            f"Waiting {int(retry_wait)}s and retrying once…[/]"
        )
        await asyncio.sleep(retry_wait)
        retry_results = await run_pass(
            retry_targets, f"Retrying [bold]{len(retry_targets)}[/] rate-limited probes…"
        )
        salvaged = 0
        for orig_idx, retry_hit in zip(rl_indices, retry_results, strict=True):
            if not _is_rate_limited(retry_hit) and retry_hit.status is not Status.ERROR:
                results[orig_idx] = retry_hit
                if retry_hit.is_found:
                    salvaged += 1
        if salvaged:
            console.print(
                f"[dim]→ Retry pass surfaced [bold green]{salvaged}[/] new hit(s).[/]"
            )

    try:
        results = await run_pass(
            modules, f"Probing [bold]{email}[/] across {len(modules)} sites…"
        )
        if retry:
            await retry_rate_limited(results)
        if verify:
            await _verify_found(modules, results, client, timeout, _canary_email(email))
        return results
    finally:
        await client.aclose()
