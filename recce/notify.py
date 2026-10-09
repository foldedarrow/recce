# SPDX-License-Identifier: AGPL-3.0-or-later
"""ntfy push alerts for investigation monitoring.

Configure with:
- `RECCE_NTFY_URL`: full topic URL, e.g. https://ntfy.sh/<long-random-topic>
  or a self-hosted server. Unset means alerts are off.
- `RECCE_NTFY_TOKEN`: optional access token (Bearer) for protected topics.
- `RECCE_NTFY_DETAIL`: set to 1 to include queries and source names.

By default an alert names the case reference and counts only. Topics on the
public ntfy.sh server are readable by anyone who knows the topic name, so
identifiers and findings stay out of the message unless you opt in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from .monitor import CaseOutcome


@dataclass(frozen=True)
class NtfyConfig:
    url: str
    token: str | None = None
    detail: bool = False

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> NtfyConfig | None:
        env = env if env is not None else dict(os.environ)
        url = (env.get("RECCE_NTFY_URL") or "").strip()
        if not url:
            return None
        detail = (env.get("RECCE_NTFY_DETAIL") or "").strip().lower() in {"1", "true", "yes", "on"}
        return cls(url=url, token=(env.get("RECCE_NTFY_TOKEN") or "").strip() or None, detail=detail)


def case_label(case: dict) -> str:
    """How an alert refers to a case: its reference, else a short id.

    The case *name* often names the subject, so it is only used with detail on.
    """
    return case.get("case_ref") or f"case {str(case.get('id', ''))[:8]}"


def build_alert(outcomes: list[CaseOutcome], *, detail: bool = False) -> tuple[str, str] | None:
    """(title, body) for cases with new evidence, or None when nothing is new."""
    hits = [outcome for outcome in outcomes if outcome.new_count]
    if not hits:
        return None
    total = sum(outcome.new_count for outcome in hits)
    title = f"recce: {total} new finding{'s' if total != 1 else ''}"
    lines = []
    for outcome in hits:
        case = outcome.investigation
        label = case_label(case)
        if detail and case.get("name"):
            label = f"{case['name']} ({label})"
        queries = [q for q in outcome.queries if q.new]
        lines.append(f"{label}: {outcome.new_count} new across {len(queries)} search(es)")
        if detail:
            for q in queries:
                sources = ", ".join(sorted({str(hit.get("source")) for hit in q.new}))
                lines.append(f"  {q.query_type} {q.query}: {sources}")
    lines.append("Open the case in recce to review.")
    return title, "\n".join(lines)


# Selftest verdicts that mean a site definition itself is broken. `blocked` and
# `error` flip with the egress IP and flaky sites, so they never alert alone.
BROKEN = ("false_positive", "false_negative")
BLOCKED_JUMP_MIN = 10  # blocked sites gained, at least this many and 20% of the earlier count
MAX_LISTED = 12


def build_health_alert(
    changes: list[dict], previous: dict | None, current: dict | None
) -> tuple[str, str] | None:
    """(title, body) when a selftest run broke site definitions or got the exit walled.

    - Newly broken: a site that was not false_positive/false_negative last run
      and now is (a site seen for the first time is not "new breakage").
    - Exit burned: the count of `blocked` sites rose sharply, which usually means
      the egress IP lost reputation, not that sites changed. Sites tested for
      the first time (a new source, a database refresh) don't count.
    `previous` and `current` are selftest summaries ({status: count}); with no
    previous run there is nothing to compare, so no alert.
    """
    if previous is None:
        return None
    broken = [c for c in changes if c.get("from") and c["to"] in BROKEN and c["from"] not in BROKEN]
    before = (previous or {}).get("blocked", 0)
    first_seen_blocked = sum(1 for c in changes if not c.get("from") and c["to"] == "blocked")
    after = (current or {}).get("blocked", 0) - first_seen_blocked
    jumped = after - before >= max(BLOCKED_JUMP_MIN, before // 5)
    if not broken and not jumped:
        return None
    parts = []
    lines = []
    if broken:
        parts.append(f"{len(broken)} site definition{'s' if len(broken) != 1 else ''} broke")
        lines.append("Newly broken:")
        for c in broken[:MAX_LISTED]:
            lines.append(f"  {c['site']}: {c['from']} -> {c['to']}")
        if len(broken) > MAX_LISTED:
            lines.append(f"  +{len(broken) - MAX_LISTED} more")
    if jumped:
        parts.append("exit walled more")
        lines.append(f"Blocked sites rose from {before} to {after}: the egress IP may have lost reputation.")
    lines.append("Run `recce selftest` or see the journal for the full table.")
    return f"recce: {' and '.join(parts)}", "\n".join(lines)


def send(config: NtfyConfig, title: str, body: str, *, tags: str = "mag", priority: str = "default") -> None:
    """POST one message to the ntfy topic. Raises on HTTP or network failure."""
    headers = {"Title": title, "Tags": tags, "Priority": priority}
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    resp = httpx.post(config.url, content=body.encode(), headers=headers, timeout=15)
    resp.raise_for_status()
