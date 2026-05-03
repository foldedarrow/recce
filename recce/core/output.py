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


def export_json(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, default=str))
    console.print(f"[dim]Saved JSON →[/] [cyan]{path}[/]")
