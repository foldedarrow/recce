"""Typer-based CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.text import Text

from . import __version__
from .config import Settings
from .core.http import http_client
from .core.output import (
    banner,
    console,
    export_csv,
    export_json,
    render_report,
    render_summary_panel,
)
from .core.result import Report
from .modules.email import search_email
from .modules.email_deep import deep_email_probes
from .modules.phone import search_phone
from .modules.username import refresh_wmn_data, search_username, site_count

app = typer.Typer(
    name="recce",
    help="Personal OSINT toolkit — trace usernames, emails, and phone numbers.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"recce {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Personal OSINT toolkit. Run [bold]recce username[/], [bold]recce email[/], or [bold]recce phone[/]."""


def _maybe_export(reports: list[Report], json_out: Path | None, csv_out: Path | None) -> None:
    if json_out:
        # JSON: one file per report when multiple, else single object.
        if len(reports) == 1:
            export_json(reports[0], json_out)
        else:
            for i, r in enumerate(reports, 1):
                stem = json_out.stem
                p = json_out.with_name(f"{stem}-{i:02d}-{r.query}{json_out.suffix}")
                export_json(r, p)
    if csv_out:
        export_csv(reports, csv_out)


def _read_targets(target: str | None, file: Path | None) -> list[str]:
    """Combine the positional arg + --file into a target list.

    --file: one identifier per line. Blank lines and lines starting with `#` are skipped.
    """
    targets: list[str] = []
    if target:
        targets.append(target.strip())
    if file:
        for raw in file.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    if not targets:
        raise typer.BadParameter("no target supplied (pass an argument or --file)")
    return targets


@app.command("username", help="Hunt a username across hundreds of platforms (WhatsMyName + curated list).")
def cmd_username(
    username: Optional[str] = typer.Argument(None, help="Username to search for, e.g. 'foldedarrow'."),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="File of usernames, one per line. Combinable with the positional arg.",
    ),
    only: Optional[str] = typer.Option(
        None, "--only", help="Comma-separated categories to include (e.g. 'coding,social').",
    ),
    exclude: Optional[str] = typer.Option(
        None, "--exclude", help="Comma-separated categories to skip.",
    ),
    nsfw: bool = typer.Option(
        False, "--nsfw", help="Include adult / NSFW sites (skipped by default).",
    ),
    show_misses: bool = typer.Option(
        False, "--show-misses", help="Print every site checked, including 'not found'.",
    ),
    show_errors: bool = typer.Option(
        False, "--show-errors", help="Show probes that errored out.",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write the report(s) to JSON."),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Write all hits to a CSV."),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Route HTTP through a proxy (e.g. socks5://127.0.0.1:9050).",
    ),
    concurrency: Optional[int] = typer.Option(
        None, "--concurrency", "-c", help="Override max parallel requests.",
    ),
) -> None:
    settings = Settings.load()
    if concurrency:
        settings = Settings(**{**settings.__dict__, "max_concurrency": concurrency})

    only_set = {s.strip() for s in only.split(",")} if only else None
    excl_set = {s.strip() for s in exclude.split(",")} if exclude else None
    targets = _read_targets(username, file)

    n_sites = site_count(include_nsfw=nsfw)
    sub = f"{len(targets)} target(s) · {n_sites} sites" + (" · [yellow]NSFW ON[/]" if nsfw else "")
    banner("recce › username", subtitle=sub)

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
            proxy=proxy,
        ) as client:
            return [
                await search_username(
                    t,
                    client,
                    only_categories=only_set,
                    exclude_categories=excl_set,
                    include_nsfw=nsfw,
                )
                for t in targets
            ]

    try:
        reports = asyncio.run(run())
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    for r in reports:
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("email", help="Look up an email: Gravatar, MX, breaches, reputation, profile pivots.")
def cmd_email(
    email: Optional[str] = typer.Argument(None, help="Email address."),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="File of emails, one per line.",
    ),
    deep: bool = typer.Option(
        False, "--deep", "-d",
        help="Probe ~140 sites' signup/reset endpoints to discover registered accounts. "
             "Slower (~30–60s) and only safe to use on emails you own.",
    ),
    show_misses: bool = typer.Option(False, "--show-misses"),
    show_errors: bool = typer.Option(
        False, "--show-errors", help="Show probes that errored out.",
    ),
    json_out: Optional[Path] = typer.Option(None, "--json"),
    csv_out: Optional[Path] = typer.Option(None, "--csv"),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Route HTTP through a proxy.",
    ),
) -> None:
    settings = Settings.load()
    targets = _read_targets(email, file)

    sub = f"{len(targets)} target(s)" + ("   · deep mode ON" if deep else "")
    banner("recce › email", subtitle=sub)
    _print_key_status(settings, ["hibp_api_key", "emailrep_api_key", "hunter_api_key"])

    async def run_one(addr: str) -> Report:
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
            proxy=proxy,
        ) as client:
            r = await search_email(addr, client, settings)
        if deep:
            for hit in await deep_email_probes(addr, timeout=settings.timeout):
                r.add(hit)
        return r

    try:
        reports = asyncio.run(_run_serial(run_one, targets))
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    for r in reports:
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("phone", help="Look up a phone number: parse, carrier, region, optional NumVerify.")
def cmd_phone(
    phone: Optional[str] = typer.Argument(None, help="Phone number; +country-code form preferred."),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="File of phone numbers, one per line.",
    ),
    region: str = typer.Option("GB", "--region", "-r", help="Default region (ISO-3166 alpha-2)."),
    show_misses: bool = typer.Option(False, "--show-misses"),
    show_errors: bool = typer.Option(False, "--show-errors"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
    csv_out: Optional[Path] = typer.Option(None, "--csv"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
) -> None:
    settings = Settings.load()
    targets = _read_targets(phone, file)
    banner("recce › phone", subtitle=f"{len(targets)} target(s) · default region: {region}")
    _print_key_status(settings, ["numverify_api_key"])

    async def run_one(num: str) -> Report:
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
            proxy=proxy,
        ) as client:
            return await search_phone(num, client, settings, default_region=region)

    reports = asyncio.run(_run_serial(run_one, targets))

    for r in reports:
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("update", help="Refresh the bundled WhatsMyName site database from upstream.")
def cmd_update() -> None:
    settings = Settings.load()
    banner("recce › update", subtitle="fetching latest WhatsMyName data")

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=30.0,
            max_concurrency=2,
        ) as client:
            return await refresh_wmn_data(client)

    try:
        before, after = asyncio.run(run())
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(1) from e
    delta = after - before
    delta_str = f"[green]+{delta}[/]" if delta > 0 else f"[dim]{delta:+d}[/]"
    console.print(
        f"[bold green]✓[/] WMN refreshed: was {before} sites, now [bold]{after}[/] ({delta_str})."
    )


@app.command("doctor", help="Check API keys and network reachability.")
def cmd_doctor() -> None:
    settings = Settings.load()
    banner("recce › doctor", subtitle="checking config")
    keys = {
        "HIBP_API_KEY": settings.hibp_api_key,
        "HUNTER_API_KEY": settings.hunter_api_key,
        "NUMVERIFY_API_KEY": settings.numverify_api_key,
        "EMAILREP_API_KEY": settings.emailrep_api_key,
        "LEAKCHECK_API_KEY": settings.leakcheck_api_key,
    }
    for name, val in keys.items():
        marker = "[green]set[/]" if val else "[dim]unset[/]"
        console.print(f"  {marker:>10}  {name}")
    n_default = site_count(include_nsfw=False)
    n_nsfw = site_count(include_nsfw=True)
    console.print(
        f"\n  [dim]username sites loaded:[/] [bold]{n_default}[/] "
        f"([dim]+{n_nsfw - n_default} NSFW available behind --nsfw[/])"
    )
    console.print(
        "\n[dim]Unset keys mean those sources will be skipped. "
        "See `.env.example` for where to get each.[/]"
    )


def _print_key_status(settings: Settings, keys: list[str]) -> None:
    line = Text("  API keys: ", style="dim")
    for k in keys:
        label = k.replace("_api_key", "").upper()
        if getattr(settings, k):
            line.append(f"[{label} ✓] ", style="green")
        else:
            line.append(f"[{label} ✗] ", style="red dim")
    console.print(line)


async def _run_serial(fn, items: list[str]) -> list[Report]:
    """Run `fn(item)` for each item sequentially. Used when each item creates
    its own short-lived HTTP client."""
    out: list[Report] = []
    for item in items:
        out.append(await fn(item))
    return out


if __name__ == "__main__":
    app()
