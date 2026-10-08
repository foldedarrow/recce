# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typer-based CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import typer
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Settings
from .core.http import http_client
from .core.investigations import INVESTIGATION_STATUSES, InvestigationStore
from .core.output import (
    banner,
    console,
    export_csv,
    export_json,
    render_domain_summary_card,
    render_report,
    render_summary_panel,
)
from .core.result import Report
from .licensing import has_pro_entitlement, pro_licence_path
from .modules.domain import DOMAIN_CATEGORIES, domain_consent_error, search_domain
from .modules.email import search_email
from .modules.email_deep import deep_email_probes
from .modules.phone import search_phone
from .modules.username import (
    DEFAULT_PER_DOMAIN_RATE,
    WMN_REMOTE,
    cache_status,
    category_counts,
    clear_wmn_cache,
    refresh_wmn_data,
    search_username,
    site_count,
)
from .providers import append_registry_gate_hits, provider_status_rows

app = typer.Typer(
    name="recce",
    help="Personal OSINT toolkit — trace usernames, emails, phone numbers, and domains.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
investigations_app = typer.Typer(help="Manage local GUI investigation cases.", no_args_is_help=True)
app.add_typer(investigations_app, name="investigations")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"recce {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool | None = typer.Option(
        None, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Personal OSINT toolkit. Run username, email, phone, or domain lookups."""


def _maybe_export(reports: list[Report], json_out: Path | None, csv_out: Path | None) -> None:
    if json_out:
        # JSON: one file per report when multiple, else single object.
        if len(reports) == 1:
            export_json(reports[0], json_out)
        else:
            for i, r in enumerate(reports, 1):
                stem = json_out.stem
                safe_query = "".join(c if c.isalnum() else "-" for c in r.query)[:60]
                p = json_out.with_name(f"{stem}-{i:02d}-{safe_query}{json_out.suffix}")
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


def _parse_csv_set(raw: str | None) -> set[str] | None:
    values = {s.strip().lower() for s in raw.split(",")} if raw else set()
    return {s for s in values if s} or None


def _parse_investigation_statuses(raw: str | None) -> set[str] | None:
    statuses = _parse_csv_set(raw)
    if statuses is None:
        return None
    invalid = statuses - INVESTIGATION_STATUSES
    if invalid:
        raise typer.BadParameter(f"unknown status: {', '.join(sorted(invalid))}")
    return statuses


def _print_categories(*, include_nsfw: bool) -> None:
    counts = category_counts(include_nsfw=include_nsfw)
    for name, count in counts.items():
        console.print(f"  [bold]{name}[/]  [dim]{count}[/]")


def _investigation_store() -> InvestigationStore:
    return InvestigationStore()


@investigations_app.command("list", help="List local investigation cases.")
def cmd_investigations_list(
    include: str | None = typer.Option(
        None,
        "--include",
        help="Comma-separated extra statuses to include: closed,archived. Default is open only.",
    ),
) -> None:
    include_statuses = _parse_investigation_statuses(include)
    if include_statuses is not None:
        include_statuses.add("open")
    cases = _investigation_store().list_investigations(include_statuses=include_statuses)
    table = Table("ID", "Name", "Ref", "Status", "Runs", "Updated")
    for case in cases:
        table.add_row(
            case["id"],
            case["name"],
            case.get("case_ref") or "-",
            case.get("status") or "-",
            str(case.get("run_count") or 0),
            case.get("updated_at") or "-",
        )
    console.print(table)


@investigations_app.command("close", help="Mark an investigation closed.")
def cmd_investigations_close(
    case_id: str = typer.Argument(..., help="Investigation case ID."),
    reason: str = typer.Option("", "--reason", help="Reason to record in the audit log."),
) -> None:
    case = _investigation_store().close_investigation(case_id, reason=reason)
    console.print(f"[green]closed[/] {case['id']}  [bold]{case['name']}[/]")


@investigations_app.command("archive", help="Archive an investigation.")
def cmd_investigations_archive(
    case_id: str = typer.Argument(..., help="Investigation case ID."),
    reason: str = typer.Option("", "--reason", help="Reason to record in the audit log."),
) -> None:
    case = _investigation_store().archive_investigation(case_id, reason=reason)
    console.print(f"[green]archived[/] {case['id']}  [bold]{case['name']}[/]")


@investigations_app.command("reopen", help="Reopen a closed investigation.")
def cmd_investigations_reopen(
    case_id: str = typer.Argument(..., help="Investigation case ID."),
    reason: str = typer.Option("", "--reason", help="Reason to record in the audit log."),
) -> None:
    case = _investigation_store().reopen_investigation(case_id, reason=reason)
    console.print(f"[green]reopened[/] {case['id']}  [bold]{case['name']}[/]")


@investigations_app.command("unarchive", help="Unarchive an archived investigation.")
def cmd_investigations_unarchive(
    case_id: str = typer.Argument(..., help="Investigation case ID."),
    reason: str = typer.Option("", "--reason", help="Reason to record in the audit log."),
) -> None:
    case = _investigation_store().unarchive_investigation(case_id, reason=reason)
    console.print(f"[green]unarchived[/] {case['id']}  [bold]{case['name']}[/]")


@investigations_app.command("delete", help="Permanently delete an investigation and its runs.")
def cmd_investigations_delete(
    case_id: str = typer.Argument(..., help="Investigation case ID."),
    reason: str = typer.Option("", "--reason", help="Reason to record in the audit tombstone."),
    yes: bool = typer.Option(False, "--yes", help="Required confirmation for permanent deletion."),
) -> None:
    if not yes:
        console.print("[red]error:[/] delete is permanent; re-run with --yes to confirm.")
        raise typer.Exit(2)
    tombstone = _investigation_store().delete_investigation(case_id, reason=reason)
    console.print(
        f"[red]deleted[/] {tombstone['case_id']}  [bold]{tombstone['name']}[/] "
        f"({tombstone['deleted_run_count']} run(s))"
    )


@app.command("username", help="Hunt a username across hundreds of platforms (WhatsMyName + curated list).")
def cmd_username(
    username: str | None = typer.Argument(None, help="Username to search for, e.g. 'foldedarrow'."),
    file: Path | None = typer.Option(
        None, "--file", "-f", help="File of usernames, one per line. Combinable with the positional arg.",
    ),
    only: str | None = typer.Option(
        None, "--only", help="Comma-separated categories to include (e.g. 'dev,social').",
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated categories to skip.",
    ),
    nsfw: bool = typer.Option(
        False, "--nsfw", help="Include adult / NSFW sites (skipped by default).",
    ),
    verify: bool = typer.Option(
        True, "--verify/--no-verify",
        help="Re-check each hit with a made-up username and downgrade sites that 'find' anything.",
    ),
    impersonate: bool = typer.Option(
        True, "--impersonate/--no-impersonate",
        help="Send username probes with a real Chrome TLS fingerprint and User-Agent "
        "(gets past many bot walls). --no-impersonate uses recce's own honest UA.",
    ),
    show_misses: bool = typer.Option(
        False, "--show-misses", help="Print every site checked, including 'not found'.",
    ),
    show_errors: bool = typer.Option(
        False, "--show-errors", help="Show probes that errored out.",
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Write the report(s) to JSON."),
    csv_out: Path | None = typer.Option(None, "--csv", help="Write all hits to a CSV."),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Route HTTP through a proxy (e.g. socks5://127.0.0.1:9050).",
    ),
    concurrency: int | None = typer.Option(
        None, "--concurrency", "-c", help="Override max parallel requests.",
    ),
    target_concurrency: int = typer.Option(
        1, "--target-concurrency", help="How many input usernames to process at once in batch mode.",
    ),
    per_domain_rate: float = typer.Option(
        DEFAULT_PER_DOMAIN_RATE,
        "--per-domain-rate",
        min=0.0,
        help="Max username probes per second to the same domain. Use 0 to disable.",
    ),
    list_categories: bool = typer.Option(
        False, "--list-categories", help="Print available username categories and exit.",
    ),
    no_providers: bool = typer.Option(
        False, "--no-providers", help="Disable optional API provider integrations.",
    ),
    skip_provider: str | None = typer.Option(
        None, "--skip-provider", help="Comma-separated provider IDs to skip.",
    ),
) -> None:
    settings = Settings.load()
    if no_providers:
        settings = settings.without_provider_integrations()
    if concurrency:
        settings = Settings(**{**settings.__dict__, "max_concurrency": concurrency})

    if list_categories:
        banner("recce › username categories")
        _print_categories(include_nsfw=nsfw)
        return

    only_set = _parse_csv_set(only)
    excl_set = _parse_csv_set(exclude)
    skip_provider_ids = _parse_csv_set(skip_provider)
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
            async def run_one(t: str) -> Report:
                return await search_username(
                    t,
                    client,
                    only_categories=only_set,
                    exclude_categories=excl_set,
                    include_nsfw=nsfw,
                    per_domain_rate=per_domain_rate,
                    verify_found=verify,
                    impersonate=impersonate,
                )

            return await _run_bounded(run_one, targets, target_concurrency)

    try:
        reports = asyncio.run(run())
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    for r in reports:
        append_registry_gate_hits(r, settings, skip_provider_ids=skip_provider_ids)
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("email", help="Look up an email: Gravatar, MX, breaches, reputation, profile pivots.")
def cmd_email(
    email: str | None = typer.Argument(None, help="Email address."),
    file: Path | None = typer.Option(
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
    json_out: Path | None = typer.Option(None, "--json"),
    csv_out: Path | None = typer.Option(None, "--csv"),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Route HTTP through a proxy.",
    ),
    batch_concurrency: int = typer.Option(
        1, "--batch-concurrency", help="How many emails to process at once.",
    ),
    deep_concurrency: int = typer.Option(
        20, "--deep-concurrency", help="Max concurrent deep-mode signup/reset probes.",
    ),
    deep_retry: bool = typer.Option(
        True, "--deep-retry/--no-deep-retry", help="Retry rate-limited deep probes once.",
    ),
    deep_retry_wait: float = typer.Option(
        15.0, "--deep-retry-wait", help="Seconds to wait before the deep-mode retry pass.",
    ),
    own_emails: bool = typer.Option(
        False,
        "--i-own-these-emails",
        help="Required for --deep; confirms you own or have consent for the email target(s).",
    ),
    no_providers: bool = typer.Option(
        False, "--no-providers", help="Disable optional API provider integrations.",
    ),
    skip_provider: str | None = typer.Option(
        None, "--skip-provider", help="Comma-separated provider IDs to skip.",
    ),
) -> None:
    settings = Settings.load()
    if no_providers:
        settings = settings.without_provider_integrations()
    skip_provider_ids = _parse_csv_set(skip_provider)
    targets = _read_targets(email, file)
    if deep and not own_emails:
        console.print(
            "[red]error:[/] --deep requires --i-own-these-emails. "
            "Deep mode sends live signup/reset probes; use it only on emails "
            "you own or have explicit consent to investigate. See USAGE.md "
            "section 'recce email <addr>'."
        )
        raise typer.Exit(2)

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
            r = await search_email(addr, client, settings, skip_provider_ids=skip_provider_ids)
        if deep:
            for hit in await deep_email_probes(
                addr,
                timeout=settings.timeout,
                max_concurrency=deep_concurrency,
                proxy=proxy,
                retry=deep_retry,
                retry_wait=deep_retry_wait,
            ):
                r.add(hit)
            r.finish()
        return r

    try:
        reports = asyncio.run(_run_bounded(run_one, targets, batch_concurrency))
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    for r in reports:
        append_registry_gate_hits(r, settings, skip_provider_ids=skip_provider_ids)
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("phone", help="Look up a phone number: parse, carrier, region, optional NumVerify.")
def cmd_phone(
    phone: str | None = typer.Argument(None, help="Phone number; +country-code form preferred."),
    file: Path | None = typer.Option(
        None, "--file", "-f", help="File of phone numbers, one per line.",
    ),
    region: str = typer.Option("GB", "--region", "-r", help="Default region (ISO-3166 alpha-2)."),
    deep: bool = typer.Option(
        False, "--deep", "-d",
        help="Passive footprint: search DuckDuckGo across number formats + site dorks "
             "(socials, classifieds, paste sites). Slower (~10–20s); reads public results only.",
    ),
    show_misses: bool = typer.Option(False, "--show-misses"),
    show_errors: bool = typer.Option(False, "--show-errors"),
    json_out: Path | None = typer.Option(None, "--json"),
    csv_out: Path | None = typer.Option(None, "--csv"),
    proxy: str | None = typer.Option(None, "--proxy"),
    batch_concurrency: int = typer.Option(
        1, "--batch-concurrency", help="How many phone numbers to process at once.",
    ),
    deep_concurrency: int = typer.Option(
        4, "--deep-concurrency", help="Max concurrent deep-mode search queries.",
    ),
    have_consent: bool = typer.Option(
        False, "--i-have-consent",
        help="Required for --deep; confirms you own or have consent to profile the number(s).",
    ),
    no_providers: bool = typer.Option(
        False, "--no-providers", help="Disable optional API provider integrations.",
    ),
    skip_provider: str | None = typer.Option(
        None, "--skip-provider", help="Comma-separated provider IDs to skip.",
    ),
) -> None:
    settings = Settings.load()
    if no_providers:
        settings = settings.without_provider_integrations()
    skip_provider_ids = _parse_csv_set(skip_provider)
    targets = _read_targets(phone, file)
    if deep and not have_consent:
        console.print(
            "[red]error:[/] --deep requires --i-have-consent. "
            "Deep mode builds a search-engine footprint of the number; use it only "
            "on numbers you own or have explicit consent to investigate."
        )
        raise typer.Exit(2)
    sub = f"{len(targets)} target(s) · default region: {region}" + ("   · deep mode ON" if deep else "")
    banner("recce › phone", subtitle=sub)
    _print_key_status(settings, ["numverify_api_key", "vonage_api_key", "vonage_api_secret"])

    async def run_one(num: str) -> Report:
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
            proxy=proxy,
        ) as client:
            return await search_phone(
                num,
                client,
                settings,
                default_region=region,
                skip_provider_ids=skip_provider_ids,
                deep=deep,
                deep_concurrency=deep_concurrency,
            )

    reports = asyncio.run(_run_bounded(run_one, targets, batch_concurrency))

    for r in reports:
        append_registry_gate_hits(r, settings, skip_provider_ids=skip_provider_ids)
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("domain", help="Profile a domain: ownership, network, email, web, subdomains, companies.")
def cmd_domain(
    domain: str | None = typer.Argument(None, help="Domain or URL, e.g. 'example.com'."),
    file: Path | None = typer.Option(
        None, "--file", "-f", help="File of domains/URLs, one per line.",
    ),
    only: str | None = typer.Option(
        None, "--only", help="Comma-separated domain categories to include.",
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated domain categories to skip.",
    ),
    bruteforce: bool = typer.Option(
        False, "--bruteforce", help="Actively resolve common subdomain labels. Requires --i-am-authorised.",
    ),
    authorised: bool = typer.Option(
        False,
        "--i-am-authorised",
        help="Required for --bruteforce; confirms authority to scan the target domain(s).",
    ),
    bruteforce_wordlist: str = typer.Option(
        "medium", "--bruteforce-wordlist", help="small (1k), medium (5k), or big (20k).",
    ),
    bruteforce_concurrency: int = typer.Option(
        25, "--bruteforce-concurrency", min=1, max=200, help="Max active DNS bruteforce lookups.",
    ),
    bruteforce_rate: int = typer.Option(
        10, "--bruteforce-rate", min=1, max=100, help="Approximate DNS bruteforce requests per second.",
    ),
    validate_subs: bool = typer.Option(
        True, "--validate-subs/--no-validate-subs", help="Resolve passive subdomains to mark live/historical.",
    ),
    show_misses: bool = typer.Option(False, "--show-misses"),
    show_errors: bool = typer.Option(False, "--show-errors"),
    json_out: Path | None = typer.Option(None, "--json"),
    csv_out: Path | None = typer.Option(None, "--csv"),
    proxy: str | None = typer.Option(None, "--proxy"),
    batch_concurrency: int = typer.Option(
        1, "--batch-concurrency", help="How many domains to process at once.",
    ),
    list_categories: bool = typer.Option(
        False, "--list-categories", help="Print available domain categories and exit.",
    ),
    no_providers: bool = typer.Option(
        False, "--no-providers", help="Disable optional API provider integrations.",
    ),
    skip_provider: str | None = typer.Option(
        None, "--skip-provider", help="Comma-separated provider IDs to skip.",
    ),
) -> None:
    settings = Settings.load()
    if no_providers:
        settings = settings.without_provider_integrations()
    if list_categories:
        banner("recce › domain categories")
        for name in sorted(DOMAIN_CATEGORIES):
            console.print(f"  [bold]{name}[/]")
        return

    targets = _read_targets(domain, file)
    only_set = _parse_csv_set(only)
    excl_set = _parse_csv_set(exclude)
    skip_provider_ids = _parse_csv_set(skip_provider)
    if bruteforce and not authorised:
        target = targets[0] if len(targets) == 1 else "the target domains"
        console.print(f"[red]error:[/] {domain_consent_error(target)}")
        raise typer.Exit(2)

    sub = f"{len(targets)} target(s)" + (" · [yellow]bruteforce ON[/]" if bruteforce else "")
    banner("recce › domain", subtitle=sub)
    _print_key_status(settings, ["companies_house_key", "shodan_api_key"])

    async def run_one(target: str) -> Report:
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=settings.max_concurrency,
            proxy=proxy,
        ) as client:
            return await search_domain(
                target,
                client,
                settings,
                only_categories=only_set,
                exclude_categories=excl_set,
                bruteforce=bruteforce,
                authorised=authorised,
                bruteforce_wordlist=bruteforce_wordlist,
                bruteforce_concurrency=bruteforce_concurrency,
                bruteforce_rate=bruteforce_rate,
                validate_subs=validate_subs,
                skip_provider_ids=skip_provider_ids,
            )

    try:
        reports = asyncio.run(_run_bounded(run_one, targets, batch_concurrency))
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    for r in reports:
        append_registry_gate_hits(r, settings, skip_provider_ids=skip_provider_ids)
        render_domain_summary_card(r)
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
    _maybe_export(reports, json_out, csv_out)


@app.command("update", help="Refresh the bundled WhatsMyName site database from upstream.")
def cmd_update(
    reset_cache: bool = typer.Option(False, "--reset-cache", help="Delete cached WMN data before updating."),
) -> None:
    settings = Settings.load()
    banner("recce › update", subtitle="fetching latest WhatsMyName data")
    if reset_cache and clear_wmn_cache():
        console.print("[dim]Removed cached WMN data before refresh.[/]")

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=30.0,
            max_concurrency=2,
        ) as client:
            return await refresh_wmn_data(client)

    try:
        before, after = asyncio.run(run())
    except Exception as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(1) from e
    delta = after - before
    delta_str = f"[green]+{delta}[/]" if delta > 0 else f"[dim]{delta:+d}[/]"
    console.print(
        f"[bold green]✓[/] WMN refreshed: was {before} sites, now [bold]{after}[/] ({delta_str})."
    )


@app.command("doctor", help="Check API keys and network reachability.")
def cmd_doctor(
    network: bool = typer.Option(True, "--network/--no-network", help="Run lightweight network checks."),
    proxy: str | None = typer.Option(None, "--proxy", help="Proxy to use for network checks."),
) -> None:
    settings = Settings.load()
    banner("recce › doctor", subtitle="checking config")
    keys = {
        "HIBP_API_KEY": settings.hibp_api_key,
        "HUNTER_API_KEY": settings.hunter_api_key,
        "NUMVERIFY_API_KEY": settings.numverify_api_key,
        "EMAILREP_API_KEY": settings.emailrep_api_key,
        "LEAKCHECK_API_KEY": settings.leakcheck_api_key,
        "COMPANIES_HOUSE_KEY": settings.companies_house_key,
        "SHODAN_API_KEY": settings.shodan_api_key,
        "VIRUSTOTAL_API_KEY": settings.virustotal_api_key,
        "SECURITYTRAILS_API_KEY": settings.securitytrails_api_key,
        "CENSYS_API_TOKEN": settings.censys_api_token,
        "CENSYS_ORG_ID": settings.censys_org_id,
        "GITHUB_TOKEN": settings.github_token,
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
    cache = cache_status()
    if cache["exists"]:
        validity = "valid" if cache["valid"] else "invalid"
        site_text = f" · {cache['sites']} cached sites" if cache.get("sites") is not None else ""
        console.print(f"  [dim]WMN cache:[/] {validity}{site_text}  [dim]{cache['path']}[/]")
    else:
        console.print("  [dim]WMN cache:[/] using bundled snapshot")
    entitlement = "[green]active[/]" if has_pro_entitlement() else "[dim]inactive[/]"
    console.print(f"\n  [dim]Recce Pro entitlement:[/] {entitlement}  [dim]{pro_licence_path()}[/]")
    console.print("\n[dim]Providers:[/]")
    for row in provider_status_rows(settings):
        tier = "Pro" if row["tier"] == "pro" else "Free"
        state = _format_provider_state(row["status"])
        console.print(
            f"  {state:>18}  {tier:<4}  {row['name']}  "
            f"[dim]{row['enriches']} · {row['detail']}[/]"
        )
    if network:
        console.print("\n[dim]Network checks:[/]")
        for name, ok, detail in asyncio.run(_doctor_network(settings, proxy=proxy)):
            marker = "[green]ok[/]" if ok else "[red]fail[/]"
            console.print(f"  {marker:>10}  {name}  [dim]{detail}[/]")
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


def _format_provider_state(state: str) -> str:
    if state == "active":
        return "[green]active[/]"
    if state == "inactive_pro":
        return "[yellow]pro gated[/]"
    if state == "disabled":
        return "[dim]disabled[/]"
    return "[dim]not configured[/]"


async def _run_bounded(fn, items: list[str], limit: int) -> list[Report]:
    """Run `fn(item)` for each item with a small target-level concurrency cap."""
    sem = asyncio.Semaphore(max(1, limit))

    async def runner(item: str) -> Report:
        async with sem:
            return await fn(item)

    return list(await asyncio.gather(*(runner(item) for item in items)))


async def _doctor_network(settings: Settings, proxy: str | None = None) -> list[tuple[str, bool, str]]:
    checks = [
        ("example.com", "https://example.com"),
        ("WhatsMyName data", WMN_REMOTE),
        ("GitHub API", "https://api.github.com/rate_limit"),
        ("crt.sh", "https://crt.sh/?q=example.com&output=json"),
        ("M365 realm", "https://login.microsoftonline.com/getuserrealm.srf?login=anyuser@example.com&xml=1"),
    ]
    out: list[tuple[str, bool, str]] = []
    async with http_client(
        user_agent=settings.user_agent,
        timeout=min(settings.timeout, 8.0),
        max_concurrency=3,
        proxy=proxy,
    ) as client:
        for name, url in checks:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as e:
                out.append((name, False, str(e)[:80]))
                continue
            if resp is None:
                out.append((name, False, "network error / timeout"))
            else:
                out.append((name, resp.status_code < 400, f"HTTP {resp.status_code}"))
    return out


if __name__ == "__main__":
    app()
