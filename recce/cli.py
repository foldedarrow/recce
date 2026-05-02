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
from .core.output import banner, console, export_json, render_report, render_summary_panel
from .modules.email import search_email
from .modules.phone import search_phone
from .modules.username import search_username

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


def _maybe_export(report, json_out: Path | None) -> None:
    if json_out:
        export_json(report, json_out)


@app.command("username", help="Hunt a username across 80+ social, dev, and gaming platforms.")
def cmd_username(
    username: str = typer.Argument(..., help="Username to search for, e.g. 'foldedarrow'."),
    only: Optional[str] = typer.Option(
        None,
        "--only",
        help="Comma-separated categories to include (e.g. 'dev,social').",
    ),
    exclude: Optional[str] = typer.Option(
        None,
        "--exclude",
        help="Comma-separated categories to skip.",
    ),
    show_misses: bool = typer.Option(
        False, "--show-misses", help="Print every site checked, including 'not found'."
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", help="Also write the full report to this JSON file."
    ),
    concurrency: Optional[int] = typer.Option(
        None, "--concurrency", "-c", help="Override max parallel requests."
    ),
) -> None:
    settings = Settings.load()
    if concurrency:
        settings = Settings(**{**settings.__dict__, "max_concurrency": concurrency})

    only_set = {s.strip() for s in only.split(",")} if only else None
    excl_set = {s.strip() for s in exclude.split(",")} if exclude else None

    banner("recce › username", subtitle=f"target: {username}")

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
        ) as client:
            return await search_username(
                username,
                client,
                only_categories=only_set,
                exclude_categories=excl_set,
            )

    try:
        report = asyncio.run(run())
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    render_report(report, show_misses=show_misses)
    render_summary_panel(report)
    _maybe_export(report, json_out)


@app.command("email", help="Look up an email: Gravatar, MX, breaches, reputation, profile pivots.")
def cmd_email(
    email: str = typer.Argument(..., help="Email address, e.g. 'name@example.com'."),
    show_misses: bool = typer.Option(False, "--show-misses"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    settings = Settings.load()
    banner("recce › email", subtitle=f"target: {email}")
    _print_key_status(settings, ["hibp_api_key", "emailrep_api_key", "hunter_api_key"])

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
        ) as client:
            return await search_email(email, client, settings)

    try:
        report = asyncio.run(run())
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    render_report(report, show_misses=show_misses)
    render_summary_panel(report)
    _maybe_export(report, json_out)


@app.command("phone", help="Look up a phone number: parse, carrier, region, optional NumVerify.")
def cmd_phone(
    phone: str = typer.Argument(..., help="Phone number; +country-code form preferred (e.g. +447700900123)."),
    region: str = typer.Option("GB", "--region", "-r", help="Default region if no '+' prefix (ISO-3166 alpha-2)."),
    show_misses: bool = typer.Option(False, "--show-misses"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    settings = Settings.load()
    banner("recce › phone", subtitle=f"target: {phone} (default region: {region})")
    _print_key_status(settings, ["numverify_api_key"])

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
        ) as client:
            return await search_phone(phone, client, settings, default_region=region)

    report = asyncio.run(run())

    render_report(report, show_misses=show_misses)
    render_summary_panel(report)
    _maybe_export(report, json_out)


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


if __name__ == "__main__":
    app()
