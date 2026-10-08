# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rich-based console output for human-friendly reports."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .result import Hit, Report, Status

console = Console()


_STATUS_STYLE = {
    Status.FOUND: "bold green",
    Status.NOT_FOUND: "dim",
    Status.UNKNOWN: "yellow",
    Status.ERROR: "red",
    Status.SKIPPED: "dim cyan",
}

_STATUS_GLYPH = {
    Status.FOUND: "✓",
    Status.NOT_FOUND: "·",
    Status.UNKNOWN: "?",
    Status.ERROR: "✗",
    Status.SKIPPED: "~",
}


def banner(title: str, subtitle: str | None = None) -> None:
    text = Text(title, style="bold cyan")
    if subtitle:
        sub = Text.from_markup(subtitle, style="dim")
        text.append("\n")
        text.append_text(sub)
    console.print(Panel(text, border_style="cyan", padding=(0, 2)))


def _row_visible(h: Hit, show_misses: bool, show_errors: bool) -> bool:
    if h.status is Status.NOT_FOUND:
        return show_misses
    if h.status is Status.ERROR:
        return show_errors
    return True  # FOUND, SKIPPED, UNKNOWN are always shown


def render_report(
    report: Report,
    *,
    show_misses: bool = False,
    show_errors: bool = False,
) -> None:
    found = report.found
    errors = report.errors

    header = Text()
    header.append("Query: ", style="dim")
    header.append(f"{report.query}", style="bold white")
    header.append(f"   ({report.query_type})", style="dim")
    console.print(header)
    error_hint = "" if show_errors else "  [dim](pass --show-errors to inspect)[/dim]"
    console.print(
        f"[dim]Sources checked: {len(report.hits)}   "
        f"Hits: [bold green]{len(found)}[/]   "
        f"Errors: [red]{len(errors)}[/][/dim]{error_hint if errors else ''}"
    )
    if report.exit:
        console.print(f"[dim]Exit: {report.exit}{fallback_note(report)}[/dim]")
    console.print(Rule(style="dim"))

    by_category: dict[str, list[Hit]] = defaultdict(list)
    for h in report.hits:
        by_category[h.category].append(h)

    for category in sorted(by_category):
        cat_hits = by_category[category]
        visible_rows = [h for h in cat_hits if _row_visible(h, show_misses, show_errors)]
        if not visible_rows:
            continue
        cat_found = [h for h in cat_hits if h.is_found]

        table = Table(
            title=f"[bold]{category}[/]   "
                  f"[green]{len(cat_found)}[/]/[dim]{len(cat_hits)}[/]",
            title_justify="left",
            show_lines=False,
            border_style="dim",
            expand=True,
        )
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Source", style="bold", no_wrap=True)
        table.add_column("URL / Detail", overflow="fold")
        table.add_column("Notes", overflow="fold")
        table.add_column("ms", justify="right", style="dim", no_wrap=True)

        rows = sorted(
            visible_rows,
            key=lambda h: (h.status is not Status.FOUND, h.status is Status.ERROR, h.source.lower()),
        )
        for h in rows:
            glyph = _STATUS_GLYPH[h.status]
            style = _STATUS_STYLE[h.status]
            url = h.url or ""
            note = h.summary or h.error or ""
            elapsed = str(h.elapsed_ms) if h.elapsed_ms is not None else ""
            table.add_row(
                Text(glyph, style=style),
                Text(h.source, style=style),
                Text(url, style="link " + style if url else style),
                Text(note, style="dim" if h.status is Status.NOT_FOUND else ""),
                elapsed,
            )

        console.print(table)
        console.print()

    if not found:
        console.print(
            Panel(
                "[yellow]No hits.[/yellow] Either the identifier isn't on the platforms checked, "
                "or every source returned ambiguous results. Try [cyan]--show-misses[/cyan] to "
                "see the full audit trail.",
                border_style="yellow",
            )
        )


def fallback_note(report: Report) -> str:
    retried = [h for h in report.hits if "fallback" in h.extra]
    if not retried:
        return ""
    via = retried[0].extra["fallback"].get("exit")
    answered = sum(1 for h in retried if h.extra.get("exit"))
    return f"   Retried {len(retried)} bot-walled probe(s) via {via}: {answered} answered"


def render_summary_panel(report: Report) -> None:
    found = report.found
    if not found:
        return
    lines: list[Text] = []
    for h in found:
        line = Text()
        line.append(f"  • {h.source}", style="bold green")
        if h.url:
            line.append(f"  {h.url}", style="link cyan")
        if h.summary:
            line.append(f"   — {h.summary}", style="dim")
        lines.append(line)
    console.print(Panel(Group(*lines), title="[bold green]Confirmed hits[/]", border_style="green"))


def render_domain_summary_card(report: Report) -> None:
    from recce.modules.domain_summary import build_domain_summary

    rows = build_domain_summary(report)
    if not rows:
        return
    table = Table.grid(padding=(0, 2))
    table.add_column("Field", style="bold cyan", no_wrap=True)
    table.add_column("Value", style="white", overflow="fold")
    for row in rows:
        table.add_row(row.label, row.value)
    console.print(Panel(table, title="[bold cyan]Domain summary[/]", border_style="cyan"))


def export_json(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, default=str))
    console.print(f"[dim]Saved JSON →[/] [cyan]{path}[/]")


def export_csv(reports: list[Report], path: Path) -> None:
    """Append-friendly CSV. One row per Hit. Multiple reports concatenate."""
    import csv as _csv
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = _csv.writer(fh)
        writer.writerow([
            "query", "query_type", "source", "category", "status",
            "url", "summary", "confidence", "elapsed_ms", "error",
        ])
        for report in reports:
            for h in report.hits:
                writer.writerow([
                    report.query,
                    report.query_type,
                    h.source,
                    h.category,
                    h.status.value,
                    h.url or "",
                    h.summary or "",
                    f"{h.confidence:.2f}",
                    h.elapsed_ms if h.elapsed_ms is not None else "",
                    h.error or "",
                ])
    console.print(f"[dim]Saved CSV →[/] [cyan]{path}[/]")


def render_pivot_suggestions(pivots: list) -> None:
    """Identifiers found in hits, as ready-to-run commands (no --recursive)."""
    if not pivots:
        return
    table = Table(show_header=False, box=None, padding=(0, 1))
    for p in pivots:
        table.add_row(
            Text(p.command, style="bold"),
            Text(f"# from {p.origin.source} ({p.origin.field})", style="dim"),
        )
    console.print(
        Panel(
            table,
            title="[bold cyan]Pivots found[/] [dim]— follow with --recursive[/]",
            border_style="cyan",
        )
    )


def render_pivot_chain(run) -> None:  # type: ignore[no-untyped-def]
    """Tree of follow-up searches: which hit named which identifier."""
    from rich.tree import Tree

    def label(report: Report) -> Text:
        text = Text(f"{report.query_type} ", style="dim")
        text.append(report.query, style="bold")
        text.append(f"  {len(report.found)} hit(s)", style="green" if report.found else "dim")
        return text

    root = Tree(label(run.root))
    nodes = {(run.root.query_type, run.root.query): root}
    for report in run.reports:
        origin = report.pivot
        parent = nodes.get((origin.from_type, origin.from_query), root)
        text = label(report)
        text.append(f"  ← {origin.source} ({origin.field})", style="cyan")
        nodes[(report.query_type, report.query)] = parent.add(text)
    for p in run.pending:
        parent = nodes.get((p.origin.from_type, p.origin.from_query), root)
        parent.add(Text(f"not run: {p.command}  ← {p.origin.source} ({p.origin.field})", style="dim"))
    console.print(Panel(root, title="[bold cyan]Pivot chain[/]", border_style="cyan"))


def render_clusters(report: Report) -> None:
    """Which FOUND hits look like the same person, and why."""
    from ..modules.attribution import uncorroborated_accounts

    if not any("attribution" in h.extra for h in report.found):
        return  # not a username report, or attribution was skipped
    parts: list[Text] = []
    for cluster in report.clusters:
        head = Text()
        head.append(f"Cluster {cluster.id}", style="bold")
        head.append(
            f"  {len(cluster.members)} accounts · confidence {cluster.confidence:.2f}", style="green"
        )
        parts.append(head)
        parts.append(Text("  " + ", ".join(m.source for m in cluster.members), style="cyan"))
        for signal in cluster.signals[:8]:
            parts.append(Text(f"    {signal}", style="dim"))
        if len(cluster.signals) > 8:
            parts.append(Text(f"    +{len(cluster.signals) - 8} more links", style="dim"))
        if cluster.timeline:
            steps = " → ".join(f"{m.source} {m.created_at[:10]}" for m in cluster.timeline if m.created_at)
            parts.append(Text(f"  timeline: {steps}", style="dim"))
    alone = uncorroborated_accounts(report)
    if alone:
        lead = "other " if report.clusters else ""
        parts.append(
            Text(
                f"{alone} {lead}account(s) match on the username only — no profile data "
                "links them to each other.",
                style="yellow",
            )
        )
    console.print(
        Panel(Group(*parts), title="[bold cyan]Likely the same person[/]", border_style="cyan")
    )
