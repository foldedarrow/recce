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


def _load_modules() -> list[tuple[str, str, Any]]:
    """Return [(category, site_name, callable), …] for every holehe leaf module."""
    from holehe.core import import_submodules
    import holehe.modules as root

    sites = import_submodules(root)
    out: list[tuple[str, str, Any]] = []
    for module_path, module in sites.items():
        # Path looks like 'holehe.modules.<category>.<site>'. Skip category
        # packages whose function is None.
        parts = module_path.split(".")
        if len(parts) < 4:
            continue
        category = parts[2]
        site_name = parts[-1]
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
    except Exception as e:  # noqa: BLE001
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


async def deep_email_probes(
    email: str,
    *,
    timeout: float = 12.0,
    show_progress: bool = True,
) -> list[Hit]:
    """Run every holehe probe module against the given email, concurrently."""
    modules = _load_modules()

    # Holehe modules all expect an httpx.AsyncClient — they often set their
    # own headers per-request, so we use a default client without a
    # browser User-Agent baked in (some probes are picky about this).
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    try:
        if not show_progress:
            tasks = [
                _run_one(cat, name, fn, email, client, per_module_timeout=timeout)
                for cat, name, fn in modules
            ]
            return list(await asyncio.gather(*tasks))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[bold]{task.completed}/{task.total}[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"Probing [bold]{email}[/] across {len(modules)} sites…",
                total=len(modules),
            )

            async def runner(cat: str, name: str, fn: Any) -> Hit:
                hit = await _run_one(cat, name, fn, email, client, per_module_timeout=timeout)
                progress.advance(task)
                return hit

            results = await asyncio.gather(
                *(runner(cat, name, fn) for cat, name, fn in modules)
            )
            return list(results)
    finally:
        await client.aclose()
