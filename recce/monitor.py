# SPDX-License-Identifier: AGPL-3.0-or-later
"""Re-run saved investigation queries and report genuinely new evidence.

Used by the GUI's "re-run" button and by `recce investigations monitor`
(run on a timer), which pushes an ntfy alert when a re-run turns up found
evidence that *no earlier run* of that query had. Comparing against every
earlier run, not just the last one, keeps a site that was briefly blocked
and then answers again from alerting as "new".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .config import Settings
from .core.egress import Exit, resolve_exit, resolve_fallback
from .core.http import http_client
from .core.investigations import InvestigationStore, _found_hit_map
from .core.result import Report
from .modules.domain import search_domain
from .modules.email import search_email
from .modules.email_deep import deep_email_probes
from .modules.phone import search_phone
from .modules.username import DEFAULT_PER_DOMAIN_RATE, cache_status, search_username

# Saved args that mean the original run sent active probes to third parties
# or the target. A timer must not repeat those unattended unless asked to.
_ACTIVE_FLAGS = ("deep", "bruteforce")


def is_active_run(run: dict[str, Any]) -> bool:
    args = run.get("args") or {}
    return any(bool(args.get(flag)) for flag in _ACTIVE_FLAGS)


async def rerun_saved_query(
    run: dict[str, Any],
    settings: Settings,
    *,
    exit: Exit | None = None,
    fallback_exit: Exit | None = None,
    timeout: float | None = None,
    max_concurrency: int | None = None,
) -> Report:
    """Repeat a saved run with its original arguments.

    Consent evidence recorded with the original run is re-checked: a deep or
    bruteforce run without it refuses to re-run.
    """
    args = run["args"]
    query_type = run["query_type"]
    query = run["query"]
    timeout = float(args.get("timeout", timeout or settings.timeout))
    max_concurrency = int(args.get("request_concurrency", max_concurrency or settings.max_concurrency))
    proxy = (exit or resolve_exit(query_type)).proxy

    async with http_client(
        user_agent=settings.user_agent,
        timeout=timeout,
        max_concurrency=max_concurrency,
        proxy=proxy,
    ) as client:
        if query_type == "username":
            return await search_username(
                query,
                client,
                only_categories=set(args.get("only_categories") or []) or None,
                exclude_categories=set(args.get("exclude_categories") or []) or None,
                include_nsfw=bool(args.get("include_nsfw")),
                per_domain_rate=float(args.get("per_domain_rate") or DEFAULT_PER_DOMAIN_RATE),
                show_progress=False,
                settings=settings,
                fallback_exit=fallback_exit,
            )
        if query_type == "email":
            report = await search_email(query, client, settings)
        elif query_type == "phone":
            if args.get("deep") and not args.get("ownership_or_consent_confirmed"):
                raise ValueError("Saved deep phone run is missing ownership or consent evidence.")
            report = await search_phone(
                query,
                client,
                settings,
                default_region=str(args.get("default_region") or "GB"),
                deep=bool(args.get("deep")),
                deep_concurrency=int(args.get("deep_concurrency") or 4),
            )
        elif query_type == "domain":
            if args.get("bruteforce") and not args.get("i_am_authorised"):
                raise ValueError("Saved domain bruteforce run is missing authorisation evidence.")
            report = await search_domain(
                query,
                client,
                settings,
                only_categories=set(args.get("only_categories") or []) or None,
                exclude_categories=set(args.get("exclude_categories") or []) or None,
                bruteforce=bool(args.get("bruteforce")),
                authorised=bool(args.get("i_am_authorised")),
                bruteforce_wordlist=str(args.get("bruteforce_wordlist") or "medium"),
                bruteforce_concurrency=int(args.get("bruteforce_concurrency") or 25),
                bruteforce_rate=int(args.get("bruteforce_rate") or 10),
                validate_subs=bool(args.get("validate_subs", True)),
            )
        else:
            raise ValueError(f"Cannot re-run saved query type: {query_type}")

    if query_type == "email" and args.get("deep"):
        if not args.get("ownership_or_consent_confirmed"):
            raise ValueError("Saved deep email run is missing ownership or consent evidence.")
        for hit in await deep_email_probes(
            query,
            timeout=timeout,
            max_concurrency=int(args.get("deep_concurrency") or 20),
            proxy=proxy,
            retry=bool(args.get("deep_retry", True)),
            verify=bool(args.get("deep_verify", True)),
            show_progress=False,
        ):
            report.add(hit)
        report.finish()
    return report


def new_evidence(current_run: dict[str, Any], earlier_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Found hits in `current_run` that no earlier run of the query found."""
    seen: set[tuple[str, str, str]] = set()
    for run in earlier_runs:
        seen |= set(_found_hit_map(run["report"].get("hits", [])))
    current = _found_hit_map(current_run["report"].get("hits", []))
    return [current[key] for key in sorted(set(current) - seen)]


@dataclass
class QueryOutcome:
    query_type: str
    query: str
    status: str  # "checked" | "skipped" | "error"
    new: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""


@dataclass
class CaseOutcome:
    investigation: dict[str, Any]
    queries: list[QueryOutcome] = field(default_factory=list)

    @property
    def new_count(self) -> int:
        return sum(len(q.new) for q in self.queries)


def latest_runs_by_query(store: InvestigationStore, investigation_id: str) -> list[dict[str, Any]]:
    """The newest saved run for each distinct (query_type, query) in a case."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for run in store.list_runs(investigation_id, limit=10_000):
        key = (run["query_type"], run["query"])
        if key not in latest or run["created_at"] > latest[key]["created_at"]:
            latest[key] = run
    return sorted(latest.values(), key=lambda run: (run["query_type"], run["query"]))


async def monitor_case(
    store: InvestigationStore,
    investigation: dict[str, Any],
    settings: Settings,
    *,
    include_active: bool = False,
    dry_run: bool = False,
) -> CaseOutcome:
    """Re-run every saved query in one case and collect genuinely new evidence."""
    outcome = CaseOutcome(investigation=investigation)
    fallback = resolve_fallback()
    for run in latest_runs_by_query(store, investigation["id"]):
        query_type, query = run["query_type"], run["query"]
        if is_active_run(run) and not include_active:
            outcome.queries.append(
                QueryOutcome(query_type, query, "skipped", note="active probes (deep/bruteforce) need --include-active")
            )
            continue
        if dry_run:
            outcome.queries.append(QueryOutcome(query_type, query, "checked", note="dry run"))
            continue
        try:
            report = await rerun_saved_query(run, settings, fallback_exit=fallback)
        except Exception as exc:  # one bad query must not stop the sweep
            outcome.queries.append(QueryOutcome(query_type, query, "error", note=str(exc)[:200]))
            continue
        args = {**run["args"], "monitor": True}
        store.record_run(
            investigation_id=investigation["id"],
            report=report,
            args=args,
            recce_version=__version__,
            wmn_cache=cache_status(),
        )
        runs = store.list_runs_for_query(investigation["id"], query_type=query_type, query=query, limit=1_000)
        current, earlier = runs[0], runs[1:]
        found = new_evidence(current, earlier)
        outcome.queries.append(QueryOutcome(query_type, query, "checked", new=found))
    if not dry_run:
        store.append_audit_event(
            investigation["id"],
            "investigation.monitored",
            {
                "queries": len(outcome.queries),
                "checked": sum(q.status == "checked" for q in outcome.queries),
                "skipped": sum(q.status == "skipped" for q in outcome.queries),
                "errors": sum(q.status == "error" for q in outcome.queries),
                "new_evidence": outcome.new_count,
            },
        )
    return outcome


async def monitor_investigations(
    store: InvestigationStore,
    settings: Settings,
    *,
    case_ids: list[str] | None = None,
    include_active: bool = False,
    dry_run: bool = False,
) -> list[CaseOutcome]:
    """Monitor the given cases, or every open case when none are named."""
    if case_ids:
        cases = []
        for case_id in case_ids:
            case = store.get_investigation(case_id)
            if case is None:
                raise ValueError(f"No investigation with id {case_id}")
            cases.append(case)
    else:
        cases = store.list_investigations(include_statuses={"open"})
    return [
        await monitor_case(store, case, settings, include_active=include_active, dry_run=dry_run)
        for case in cases
    ]
