# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep email search — wraps the holehe library's signup/reset-endpoint
probes to discover which sites have an account registered to an email.

Holehe ships ~140+ probe modules. We run them all concurrently against a
shared HTTP client, convert each module's output into our Hit type, and
emit them on the standard Report.

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

# Holehe modules whose probe is permanently broken (stale endpoints,
# unreachable DNS, response shape changed upstream). Skipping them keeps
# the report focused on signal. Reassess this list when holehe ships an
# update — `git blame` this constant to date the last review.
BROKEN_HOLEHE_MODULES: frozenset[str] = frozenset({
    "blip",          # consistently times out
    "buymeacoffee",  # AttributeError on response shape
    "crevado",       # IndexError
    "deliveroo",     # DNS gone
    "evernote",      # IndexError
    "github",        # IndexError (was email -> commits API; broken)
    "issuu",         # DNS gone
    "lastfm",        # JSONDecodeError
    "pinterest",     # JSONDecodeError
    "rocketreach",   # KeyError
    "samsung",       # IndexError
    "snapchat",      # IndexError
    "soundcloud",    # IndexError
})


def _load_modules() -> list[tuple[str, str, Any]]:
    """Return [(category, site_name, callable), …] for every holehe leaf module
    that isn't on the broken-module blocklist."""
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
        if site_name in BROKEN_HOLEHE_MODULES:
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


async def deep_email_probes(
    email: str,
    *,
    timeout: float = 12.0,
    max_concurrency: int = 20,
    proxy: str | None = None,
    show_progress: bool = True,
    retry: bool = True,
    retry_wait: float = 15.0,
) -> list[Hit]:
    """Run every holehe probe module against the given email, concurrently.

    If `retry=True`, modules that came back rate-limited are retried once
    after `retry_wait` seconds — many sites' rate-limit windows are short
    enough that a brief pause turns ~half of those into real hits.
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

    try:
        results = await run_pass(
            modules, f"Probing [bold]{email}[/] across {len(modules)} sites…"
        )

        if not retry:
            return results

        rl_indices = [i for i, h in enumerate(results) if _is_rate_limited(h)]
        if not rl_indices:
            return results

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
        return results
    finally:
        await client.aclose()
