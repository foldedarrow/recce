# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typer-based CLI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import typer
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import Settings
from .core.egress import Exit, configured_exits, egress_info, resolve_exit, resolve_fallback
from .core.http import http_client
from .core.investigations import INVESTIGATION_STATUSES, InvestigationStore
from .core.output import (
    banner,
    console,
    export_csv,
    export_json,
    render_clusters,
    render_domain_summary_card,
    render_pivot_chain,
    render_pivot_suggestions,
    render_report,
    render_summary_panel,
)
from .core.result import Report
from .licensing import has_pro_entitlement, pro_licence_path
from .modules.domain import DOMAIN_CATEGORIES, domain_consent_error, search_domain
from .modules.email import search_email
from .modules.email_deep import deep_email_probes
from .modules.ofcom import (
    BUNDLED_INDEX,
    OFCOM_NUMBERING_PAGE,
    clear_ofcom_cache,
    index_status,
    refresh_ofcom_data,
)
from .modules.phone import search_phone
from .modules.pivot import (
    DEFAULT_MAX_PER_LEVEL,
    MAX_DEPTH,
    PivotRun,
    extract_pivots,
    pivot_key,
    pivot_search,
    run_pivots,
)
from .modules.selftest import (
    FLAGGED_POLICIES,
    STATUSES,
    last_run_summary,
    run_selftest,
    save_report,
    select_sites,
)
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


@investigations_app.command(
    "monitor",
    help="Re-run every open case's saved searches; push an ntfy alert when evidence is new.",
)
def cmd_investigations_monitor(
    case: list[str] = typer.Option(None, "--case", help="Only these case IDs (repeatable). Default: all open cases."),
    include_active: bool = typer.Option(
        False,
        "--include-active",
        help="Also re-run deep/bruteforce searches (active probes; consent recorded on the original run still applies).",
    ),
    notify: bool = typer.Option(True, "--notify/--no-notify", help="Send an ntfy alert when there is new evidence."),
    dry_run: bool = typer.Option(False, "--dry-run", help="List what would be re-run without running or saving."),
) -> None:
    from .monitor import monitor_investigations
    from .notify import NtfyConfig, build_alert, case_label, send

    settings = Settings.load()
    store = _investigation_store()
    outcomes = asyncio.run(
        monitor_investigations(store, settings, case_ids=case or None, include_active=include_active, dry_run=dry_run)
    )
    if not outcomes:
        console.print("[dim]No open cases to monitor.[/]")
        return
    table = Table("Case", "Search", "Result", "New")
    for outcome in outcomes:
        for q in outcome.queries:
            result = q.status if not q.note else f"{q.status}: {q.note}"
            table.add_row(case_label(outcome.investigation), f"{q.query_type} {q.query}", result, str(len(q.new)))
    console.print(table)
    total = sum(outcome.new_count for outcome in outcomes)
    console.print(f"[bold]{total}[/] new finding(s) across {len(outcomes)} case(s).")

    if dry_run or not notify:
        return
    config = NtfyConfig.from_env()
    if config is None:
        if total:
            console.print("[yellow]RECCE_NTFY_URL is not set — no alert sent.[/]")
        return
    alert = build_alert(outcomes, detail=config.detail)
    if alert is None:
        return
    try:
        send(config, *alert)
    except Exception as exc:
        console.print(f"[red]ntfy alert failed:[/] {exc}")
        raise typer.Exit(1) from exc
    console.print("[green]ntfy alert sent.[/]")


@investigations_app.command("notify-test", help="Send a test ntfy alert using RECCE_NTFY_URL.")
def cmd_investigations_notify_test() -> None:
    from .notify import NtfyConfig, send

    Settings.load()  # loads ~/.config/recce/.env into the environment
    config = NtfyConfig.from_env()
    if config is None:
        console.print("[red]RECCE_NTFY_URL is not set.[/] Add it to ~/.config/recce/.env.")
        raise typer.Exit(1)
    send(config, "recce: test alert", "Monitoring alerts from recce are working.", tags="white_check_mark")
    console.print(f"[green]sent[/] test alert to {config.url.rsplit('/', 1)[0]}/…")


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


@investigations_app.command("export", help="Export an investigation (Markdown, JSON, or an HTML dossier).")
def cmd_investigations_export(
    case_id: str = typer.Argument(..., help="Investigation case ID."),
    fmt: str = typer.Option("md", "--format", help="md, json, or html (self-contained dossier)."),
    redacted: bool = typer.Option(False, "--redacted", help="Replace subject identifiers with hashes."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write to a file instead of stdout."),
) -> None:
    store = _investigation_store()
    if store.get_investigation(case_id) is None:
        console.print(f"[red]error:[/] no investigation with ID {case_id}")
        raise typer.Exit(2)
    if fmt == "md":
        text = store.export_markdown(case_id, redacted=redacted)
    elif fmt == "json":
        text = store.export_json_bytes(case_id, redacted=redacted).decode()
    elif fmt == "html":
        text = store.export_html(case_id, redacted=redacted)
    else:
        raise typer.BadParameter("--format must be md, json or html")
    if out:
        out.write_text(text)
        console.print(f"[dim]Saved →[/] [cyan]{out}[/]")
    else:
        typer.echo(text)


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
        None, "--proxy", help='Exit for this command: proxy URL (socks5h://, http://), an exit name from RECCE_EXITS, or "direct". Default: RECCE_USERNAME_PROXY, then RECCE_PROXY.',
    ),
    fallback_proxy: str | None = typer.Option(
        None, "--fallback-proxy",
        help="Retry probes the main exit gets bot-walled on (HTTP 401/403/429) through this exit "
        "(URL, RECCE_EXITS name, e.g. 'tor'). Default: RECCE_USERNAME_FALLBACK_PROXY.",
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
    flagged_sites: str | None = typer.Option(
        None, "--flagged-sites",
        help="Sites the last `recce selftest` caught reporting made-up usernames: "
        "skip (default), mark (probe but downgrade hits) or off. Env: RECCE_FLAGGED_SITES.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-R",
        help="Follow usernames/emails found in hits with passive follow-up searches.",
    ),
    depth: int = typer.Option(
        1, "--depth", min=1, max=MAX_DEPTH, help=f"Pivot levels for --recursive (max {MAX_DEPTH}).",
    ),
    max_pivots: int = typer.Option(
        DEFAULT_MAX_PER_LEVEL, "--max-pivots", min=1, max=50,
        help="Most follow-up searches per pivot level; the rest are listed, not run.",
    ),
    case: str | None = typer.Option(
        None, "--case", help="Save this run (and any pivots, with their chain) to an investigation ID.",
    ),
) -> None:
    settings = Settings.load()
    if flagged_sites is not None and flagged_sites.lower() not in FLAGGED_POLICIES:
        raise typer.BadParameter(f"must be one of {', '.join(FLAGGED_POLICIES)}", param_hint="--flagged-sites")
    if no_providers:
        settings = settings.without_provider_integrations()
    _check_case(case)
    exit_ = _exit_for("username", proxy)
    proxy = exit_.proxy
    fallback = _fallback_for(fallback_proxy)
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
    sub += f" · exit: {exit_.label}" + (f" · fallback: {fallback.label}" if fallback else "")
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
                    settings=settings,
                    skip_provider_ids=skip_provider_ids,
                    flagged_sites=flagged_sites,
                    fallback_exit=fallback,
                )

            return await _run_bounded(run_one, targets, target_concurrency)

    try:
        reports = asyncio.run(run())
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    username_options = {
        "only_categories": only_set,
        "exclude_categories": excl_set,
        "include_nsfw": nsfw,
        "per_domain_rate": per_domain_rate,
        "verify_found": verify,
        "impersonate": impersonate,
        "flagged_sites": flagged_sites,
        "fallback_exit": fallback,
    }
    all_reports = _render_and_pivot(
        reports,
        settings,
        recursive=recursive,
        depth=depth,
        max_pivots=max_pivots,
        proxy=proxy,
        skip_provider_ids=skip_provider_ids,
        username_options=username_options,
        show_misses=show_misses,
        show_errors=show_errors,
    )
    _record_to_case(
        case,
        all_reports,
        {
            "mode": "username",
            "source": "cli",
            "include_nsfw": nsfw,
            "only_categories": sorted(only_set or []),
            "exclude_categories": sorted(excl_set or []),
            "per_domain_rate": per_domain_rate,
            "verify": verify,
            "impersonate": impersonate,
            "recursive": recursive,
            "depth": depth if recursive else 0,
            "exit": exit_.label,
            "fallback_exit": fallback.label if fallback else None,
        },
    )
    _maybe_export(all_reports, json_out, csv_out)


@app.command("email", help="Look up an email: Gravatar, MX, breaches, reputation, profile pivots.")
def cmd_email(
    email: str | None = typer.Argument(None, help="Email address."),
    file: Path | None = typer.Option(
        None, "--file", "-f", help="File of emails, one per line.",
    ),
    deep: bool = typer.Option(
        False, "--deep", "-d",
        help="Probe ~30 sites' signup/sign-in endpoints (holehe) to discover registered accounts. "
             "Slower (~30–60s) and only safe to use on emails you own.",
    ),
    show_misses: bool = typer.Option(False, "--show-misses"),
    show_errors: bool = typer.Option(
        False, "--show-errors", help="Show probes that errored out.",
    ),
    json_out: Path | None = typer.Option(None, "--json"),
    csv_out: Path | None = typer.Option(None, "--csv"),
    proxy: str | None = typer.Option(
        None, "--proxy", help='Exit for this command: proxy URL (socks5h://, http://), an exit name from RECCE_EXITS, or "direct". Default: RECCE_EMAIL_PROXY, then RECCE_PROXY.',
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
    deep_verify: bool = typer.Option(
        True, "--deep-verify/--no-deep-verify",
        help="Re-probe deep-mode hits with a made-up address at the same domain; "
             "sites that 'find' it too are downgraded to unknown.",
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
    recursive: bool = typer.Option(
        False, "--recursive", "-R",
        help="Follow usernames/emails found in hits with passive follow-up searches "
        "(never --deep: deep probes only ever run on the emails you typed).",
    ),
    depth: int = typer.Option(
        1, "--depth", min=1, max=MAX_DEPTH, help=f"Pivot levels for --recursive (max {MAX_DEPTH}).",
    ),
    max_pivots: int = typer.Option(
        DEFAULT_MAX_PER_LEVEL, "--max-pivots", min=1, max=50,
        help="Most follow-up searches per pivot level; the rest are listed, not run.",
    ),
    case: str | None = typer.Option(
        None, "--case", help="Save this run (and any pivots, with their chain) to an investigation ID.",
    ),
) -> None:
    settings = Settings.load()
    if no_providers:
        settings = settings.without_provider_integrations()
    _check_case(case)
    exit_ = _exit_for("email", proxy)
    proxy = exit_.proxy
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

    sub = f"{len(targets)} target(s)" + ("   · deep mode ON" if deep else "") + f" · exit: {exit_.label}"
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
                verify=deep_verify,
            ):
                r.add(hit)
            r.finish()
        return r

    try:
        reports = asyncio.run(_run_bounded(run_one, targets, batch_concurrency))
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e

    all_reports = _render_and_pivot(
        reports,
        settings,
        recursive=recursive,
        depth=depth,
        max_pivots=max_pivots,
        proxy=proxy,
        skip_provider_ids=skip_provider_ids,
        username_options={"fallback_exit": _fallback_for(None)},
        show_misses=show_misses,
        show_errors=show_errors,
    )
    _record_to_case(
        case,
        all_reports,
        {
            "mode": "email",
            "source": "cli",
            "deep": deep,
            "ownership_or_consent_confirmed": own_emails,
            "deep_concurrency": deep_concurrency,
            "deep_retry": deep_retry,
            "deep_verify": deep_verify,
            "recursive": recursive,
            "depth": depth if recursive else 0,
        },
    )
    _maybe_export(all_reports, json_out, csv_out)


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
    proxy: str | None = typer.Option(None, "--proxy", help='Exit for this command: proxy URL (socks5h://, http://), an exit name from RECCE_EXITS, or "direct". Default: RECCE_PHONE_PROXY, then RECCE_PROXY.'),
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
    exit_ = _exit_for("phone", proxy)
    proxy = exit_.proxy
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
    sub += f" · exit: {exit_.label}"
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
    proxy: str | None = typer.Option(None, "--proxy", help='Exit for this command: proxy URL (socks5h://, http://), an exit name from RECCE_EXITS, or "direct". Default: RECCE_DOMAIN_PROXY, then RECCE_PROXY.'),
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

    exit_ = _exit_for("domain", proxy)
    proxy = exit_.proxy
    targets = _read_targets(domain, file)
    only_set = _parse_csv_set(only)
    excl_set = _parse_csv_set(exclude)
    skip_provider_ids = _parse_csv_set(skip_provider)
    if bruteforce and not authorised:
        target = targets[0] if len(targets) == 1 else "the target domains"
        console.print(f"[red]error:[/] {domain_consent_error(target)}")
        raise typer.Exit(2)

    sub = f"{len(targets)} target(s)" + (" · [yellow]bruteforce ON[/]" if bruteforce else "")
    sub += f" · exit: {exit_.label}"
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


UPDATE_SOURCES = ("wmn", "ofcom")


@app.command(
    "update",
    help="Refresh the WhatsMyName site database and Ofcom UK numbering data from upstream.",
)
def cmd_update(
    reset_cache: bool = typer.Option(False, "--reset-cache", help="Delete cached data before updating."),
    only: str | None = typer.Option(
        None, "--only", help="Refresh just one source: wmn or ofcom.", case_sensitive=False
    ),
    bundled: bool = typer.Option(
        False,
        "--bundled",
        help="Write the Ofcom index into recce/data/ (maintainers, in a source checkout).",
    ),
) -> None:
    settings = Settings.load()
    sources = UPDATE_SOURCES
    if only:
        if only.lower() not in UPDATE_SOURCES:
            console.print(f"[red]error:[/] --only must be one of: {', '.join(UPDATE_SOURCES)}")
            raise typer.Exit(2)
        sources = (only.lower(),)
    banner("recce › update", subtitle="fetching " + " + ".join(
        {"wmn": "WhatsMyName", "ofcom": "Ofcom numbering"}[s] for s in sources
    ))

    async def run(source: str) -> tuple[int, int]:
        async with http_client(
            user_agent=settings.user_agent,
            timeout=30.0,
            max_concurrency=2,
        ) as client:
            if source == "wmn":
                return await refresh_wmn_data(client)
            return await refresh_ofcom_data(client, dest=BUNDLED_INDEX if bundled else None)

    failed = False
    for source in sources:
        if reset_cache:
            cleared = clear_wmn_cache() if source == "wmn" else clear_ofcom_cache()
            if cleared:
                console.print(f"[dim]Removed cached {source} data before refresh.[/]")
        try:
            before, after = asyncio.run(run(source))
        except Exception as e:
            console.print(f"[red]error ({source}):[/] {e}")
            failed = True
            continue
        delta = after - before
        delta_str = f"[green]+{delta}[/]" if delta > 0 else f"[dim]{delta:+d}[/]"
        if source == "wmn":
            console.print(
                f"[bold green]✓[/] WMN refreshed: was {before} sites, now [bold]{after}[/] ({delta_str})."
            )
        else:
            status = index_status()
            console.print(
                f"[bold green]✓[/] Ofcom numbering refreshed: was {before} blocks, now "
                f"[bold]{after}[/] ({delta_str}); Ofcom files published {status.get('published') or '?'}."
            )
    if failed:
        raise typer.Exit(1)


_HEALTH_STYLE = {
    "healthy": "green",
    "false_positive": "bold red",
    "false_negative": "red",
    "blocked": "yellow",
    "error": "magenta",
    "unverified": "dim",
}


@app.command(
    "selftest",
    help="Check every username site definition against a known account and a made-up one.",
)
def cmd_selftest(
    category: str | None = typer.Option(
        None, "--category", "-C", help="Comma-separated categories to test (e.g. 'dev,social').",
    ),
    only: str | None = typer.Option(
        None, "--only", help="Comma-separated site names to test (case-insensitive).",
    ),
    nsfw: bool = typer.Option(False, "--nsfw", help="Include adult / NSFW sites."),
    json_output: bool = typer.Option(
        False, "--json", help="Print the full report as JSON instead of tables.",
    ),
    show_all: bool = typer.Option(False, "--all", help="List healthy and unverified sites too."),
    save: bool = typer.Option(
        True, "--save/--no-save",
        help="Store results in ~/.cache/recce/selftest.json (username searches read it).",
    ),
    impersonate: bool = typer.Option(
        True, "--impersonate/--no-impersonate", help="Probe with a Chrome fingerprint, as searches do.",
    ),
    proxy: str | None = typer.Option(
        None, "--proxy", help="Exit to test from (URL, RECCE_EXITS name or 'direct'). "
        "Default: the username exit.",
    ),
    concurrency: int | None = typer.Option(
        None, "--concurrency", "-c", help="Override max parallel requests.",
    ),
    per_domain_rate: float = typer.Option(
        DEFAULT_PER_DOMAIN_RATE, "--per-domain-rate", min=0.0,
        help="Max probes per second to the same domain. Use 0 to disable.",
    ),
) -> None:
    settings = Settings.load()
    proxy = _exit_for("username", proxy).proxy
    sites = select_sites(
        categories=_parse_csv_set(category), names=_parse_csv_set(only), include_nsfw=nsfw,
    )
    if not sites:
        console.print("[red]error:[/] no sites match those filters")
        raise typer.Exit(2)
    if not json_output:
        banner("recce › selftest", subtitle=f"{len(sites)} site definitions · known account + canary")

    async def run():
        async with http_client(
            user_agent=settings.user_agent,
            timeout=settings.timeout,
            max_concurrency=concurrency or settings.max_concurrency,
            proxy=proxy,
        ) as client:
            if json_output:
                return await run_selftest(
                    client, sites, impersonate=impersonate, per_domain_rate=per_domain_rate,
                )
            with Progress(
                SpinnerColumn(), TextColumn("{task.description}"), BarColumn(bar_width=None),
                TextColumn("[bold]{task.completed}/{task.total}[/]"), TimeElapsedColumn(),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task("Probing site definitions…", total=len(sites))
                return await run_selftest(
                    client, sites, impersonate=impersonate, per_domain_rate=per_domain_rate,
                    on_progress=lambda _name, _status: progress.advance(task),
                )

    report = asyncio.run(run())
    changes = save_report(report) if save else []
    if json_output:
        print(json.dumps({**report, "changes": changes}, indent=1))
        return
    _render_selftest(report, changes, show_all=show_all, saved=save)


def _render_selftest(report: dict, changes: list[dict], *, show_all: bool, saved: bool) -> None:
    egress = report.get("egress") or {}
    where = " · ".join(str(egress[k]) for k in ("ip", "country", "org") if egress.get(k)) or "unknown"
    console.print(
        f"[dim]egress:[/] {where}   [dim]impersonate:[/] {'on' if report['impersonate'] else 'off'}"
        f"   [dim]canary:[/] {report['canary']}   [dim]took:[/] {report['duration_s']}s"
    )
    rows = [
        (name, e) for name, e in report["sites"].items()
        if show_all or e["status"] not in ("healthy", "unverified")
    ]
    if rows:
        order = {s: i for i, s in enumerate(STATUSES)}
        table = Table(show_header=True, header_style="bold", expand=True)
        for col, style in (
            ("Site", None), ("Category", "dim"), ("Health", None),
            ("Known", "dim"), ("Canary", "dim"), ("Detail", "dim"),
        ):
            table.add_column(col, style=style, overflow="fold")
        for name, e in sorted(rows, key=lambda r: (order.get(r[1]["status"], 9), r[0].lower())):
            style = _HEALTH_STYLE.get(e["status"], "")
            table.add_row(
                name, e["category"], f"[{style}]{e['status']}[/]",
                _probe_cell(e.get("known")), _probe_cell(e.get("canary")), e.get("detail") or "",
            )
        console.print(table)
    summary = Table(show_header=False, box=None, padding=(0, 2))
    for status, count in report["summary"].items():
        summary.add_row(f"[{_HEALTH_STYLE.get(status, '')}]{status}[/]", str(count))
    console.print(summary)
    if changes:
        console.print("\n[bold]Changes since the last run:[/]")
        for c in changes:
            style = _HEALTH_STYLE.get(c["to"], "")
            console.print(f"  {c['site']}: {c['from'] or 'new'} → [{style}]{c['to']}[/]")
    if saved:
        console.print(
            "\n[dim]Saved. Username searches skip false-positive sites "
            "(override: --flagged-sites mark|off).[/]"
        )
    console.print("[dim]'blocked' depends on the egress IP and is not counted as broken.[/]")


def _probe_cell(probe: dict | None) -> str:
    if not probe:
        return "—"
    http = f" {probe['http']}" if probe.get("http") is not None else ""
    return f"{probe['username']}: {probe['status']}{http}"


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
    ofcom = index_status()
    if ofcom["loaded"]:
        where = ofcom["path"] if ofcom["cached"] else "bundled snapshot"
        console.print(
            f"  [dim]Ofcom numbering:[/] {ofcom['blocks']} blocks · published "
            f"{ofcom['published'] or '?'}  [dim]{where}[/]"
        )
    else:
        console.print("  [dim]Ofcom numbering:[/] [yellow]unavailable[/] — run `recce update --only ofcom`")
    selftest_state = last_run_summary()
    if selftest_state:
        counts = selftest_state["summary"]
        ip = selftest_state["egress"].get("ip") or "?"
        console.print(
            f"  [dim]site selftest:[/] {selftest_state['ran_at']} via {ip} · "
            f"{counts.get('healthy', 0)} healthy · {counts.get('false_positive', 0)} false-positive "
            f"(skipped in searches) · {counts.get('false_negative', 0)} false-negative · "
            f"{counts.get('blocked', 0)} blocked"
        )
    else:
        console.print("  [dim]site selftest:[/] never run (`recce selftest`)")
    console.print("\n[dim]Exits:[/]")
    exits = configured_exits()
    ips = asyncio.run(_exit_ips(settings, exits)) if network else {}
    for use, exit_ in exits:
        where = ips.get(exit_.proxy, {})
        seen_as = " · ".join(str(where[k]) for k in ("ip", "country", "org") if where.get(k))
        if network and not seen_as:
            seen_as = "[red]unreachable[/]"
        console.print(f"  {use:>18}  {exit_.label}  [dim]{seen_as}[/]")
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


def _render_and_pivot(
    reports: list[Report],
    settings: Settings,
    *,
    recursive: bool,
    depth: int,
    max_pivots: int,
    proxy: str | None,
    skip_provider_ids: set[str] | None,
    username_options: dict,
    show_misses: bool,
    show_errors: bool,
) -> list[Report]:
    """Render each root report, then its pivots: run them, or suggest them.

    Returns the roots followed by every follow-up report, for export/recording.
    """
    searched = {pivot_key(r.query_type, r.query) for r in reports}

    def render(r: Report) -> None:
        append_registry_gate_hits(r, settings, skip_provider_ids=skip_provider_ids)
        render_report(r, show_misses=show_misses, show_errors=show_errors)
        render_summary_panel(r)
        render_clusters(r)

    out: list[Report] = []
    for root in reports:
        render(root)
        out.append(root)
        if not recursive:
            render_pivot_suggestions(
                [p for p in extract_pivots(root) if p.key not in searched]
            )
            continue
        run = asyncio.run(
            _follow_pivots(
                root,
                settings,
                proxy=proxy,
                depth=depth,
                max_pivots=max_pivots,
                skip_provider_ids=skip_provider_ids,
                username_options=username_options,
                seen=searched,
            )
        )
        searched |= {pivot_key(r.query_type, r.query) for r in run.reports}
        for child in run.reports:
            render(child)
            out.append(child)
        render_pivot_chain(run)
    return out


async def _follow_pivots(
    root: Report,
    settings: Settings,
    *,
    proxy: str | None,
    depth: int,
    max_pivots: int,
    skip_provider_ids: set[str] | None,
    username_options: dict,
    seen: set[tuple[str, str]],
) -> PivotRun:
    async with http_client(
        user_agent=settings.user_agent,
        timeout=settings.timeout,
        max_concurrency=settings.max_concurrency,
        proxy=proxy,
    ) as client:
        search = pivot_search(
            client, settings, skip_provider_ids=skip_provider_ids, **username_options
        )
        return await run_pivots(root, search, depth=depth, max_per_level=max_pivots, seen=seen)


def _exit_for(module: str, proxy: str | None) -> Exit:
    try:
        return resolve_exit(module, proxy)
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e


def _fallback_for(proxy: str | None) -> Exit | None:
    try:
        return resolve_fallback(proxy)
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from e


def _check_case(case_id: str | None) -> None:
    if case_id and _investigation_store().get_investigation(case_id) is None:
        console.print(f"[red]error:[/] no investigation with ID {case_id}")
        raise typer.Exit(2)


def _record_to_case(case_id: str | None, reports: list[Report], root_args: dict) -> None:
    """Save roots with their CLI args; pivots with passive-only args."""
    if not case_id:
        return
    store = _investigation_store()
    for r in reports:
        if r.pivot is None:
            args = root_args
        else:
            args = {"mode": r.query_type, "source": "cli", "pivot": True, "deep": False}
        store.record_run(
            investigation_id=case_id,
            report=r,
            args=args,
            recce_version=__version__,
            wmn_cache=cache_status(),
        )
    console.print(f"[dim]Saved {len(reports)} run(s) to case[/] [cyan]{case_id}[/]")


async def _run_bounded(fn, items: list[str], limit: int) -> list[Report]:
    """Run `fn(item)` for each item with a small target-level concurrency cap."""
    sem = asyncio.Semaphore(max(1, limit))

    async def runner(item: str) -> Report:
        async with sem:
            return await fn(item)

    return list(await asyncio.gather(*(runner(item) for item in items)))


async def _exit_ips(
    settings: Settings, exits: list[tuple[str, Exit]]
) -> dict[str | None, dict]:
    """Public IP (and country/org) each distinct exit appears as."""

    async def probe(proxy: str | None) -> dict:
        try:
            async with http_client(
                user_agent=settings.user_agent,
                timeout=min(settings.timeout, 10.0),
                max_concurrency=2,
                proxy=proxy,
            ) as client:
                return await egress_info(client)
        except Exception:
            return {"ip": None}

    proxies = list(dict.fromkeys(e.proxy for _, e in exits))
    return dict(zip(proxies, await asyncio.gather(*(probe(p) for p in proxies)), strict=True))


async def _doctor_network(settings: Settings, proxy: str | None = None) -> list[tuple[str, bool, str]]:
    checks = [
        ("example.com", "https://example.com"),
        ("WhatsMyName data", WMN_REMOTE),
        ("Ofcom numbering", OFCOM_NUMBERING_PAGE),
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
