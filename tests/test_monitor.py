# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio

import pytest

import recce.monitor as monitor
from recce.config import Settings
from recce.core.investigations import InvestigationStore
from recce.core.result import Hit, Report, Status
from recce.notify import NtfyConfig, build_alert, send


def _settings() -> Settings:
    return Settings(
        **dict.fromkeys(
            (
                "hibp_api_key",
                "hunter_api_key",
                "numverify_api_key",
                "emailrep_api_key",
                "leakcheck_api_key",
                "companies_house_key",
                "shodan_api_key",
                "virustotal_api_key",
                "securitytrails_api_key",
            )
        ),
        user_agent="recce-test",
        timeout=3.0,
        max_concurrency=2,
    )


def _report(query: str, *urls: str) -> Report:
    report = Report(query=query, query_type="username")
    for url in urls:
        report.add(Hit(source=url.split("/")[2], category="social", status=Status.FOUND, url=url))
    report.finish()
    return report


def _record(store: InvestigationStore, case_id: str, report: Report, **args) -> None:  # type: ignore[no-untyped-def]
    store.record_run(investigation_id=case_id, report=report, args=args, recce_version="test", wmn_cache={})


@pytest.fixture
def store(tmp_path) -> InvestigationStore:  # type: ignore[no-untyped-def]
    return InvestigationStore(db_path=tmp_path / "inv.sqlite3")


def test_new_evidence_ignores_anything_any_earlier_run_found() -> None:
    def run(*urls: str) -> dict:
        return {"report": _report("alice", *urls).model_dump(mode="json")}

    earlier = [run("https://a.test/alice"), run("https://b.test/alice")]  # b was blocked once, back now
    current = run("https://a.test/alice", "https://b.test/alice", "https://c.test/alice")

    assert [hit["url"] for hit in monitor.new_evidence(current, earlier)] == ["https://c.test/alice"]


def test_monitor_case_records_rerun_and_reports_new_evidence(store, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    case = store.create_investigation(name="Alice Example", case_ref="CASE-1")
    _record(store, case["id"], _report("alice", "https://a.test/alice"))

    async def fake_rerun(run, settings, **kwargs):  # type: ignore[no-untyped-def]
        return _report("alice", "https://a.test/alice", "https://new.test/alice")

    monkeypatch.setattr(monitor, "rerun_saved_query", fake_rerun)

    outcome = asyncio.run(monitor.monitor_case(store, case, _settings()))

    assert outcome.new_count == 1
    assert outcome.queries[0].new[0]["url"] == "https://new.test/alice"
    runs = store.list_runs_for_query(case["id"], query_type="username", query="alice")
    assert len(runs) == 2 and runs[0]["args"]["monitor"] is True
    events = [event["event_type"] for event in store.list_audit_events(case["id"])]
    assert "investigation.monitored" in events


def test_monitor_skips_active_runs_unless_asked(store, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    case = store.create_investigation(name="Case", case_ref="CASE-2")
    report = Report(query="alice@example.com", query_type="email")
    report.finish()
    _record(store, case["id"], report, deep=True, ownership_or_consent_confirmed=True)
    calls: list[str] = []

    async def fake_rerun(run, settings, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(run["query"])
        return report

    monkeypatch.setattr(monitor, "rerun_saved_query", fake_rerun)

    skipped = asyncio.run(monitor.monitor_case(store, case, _settings()))
    assert skipped.queries[0].status == "skipped" and calls == []

    asyncio.run(monitor.monitor_case(store, case, _settings(), include_active=True))
    assert calls == ["alice@example.com"]


def test_monitor_only_sweeps_open_cases(store, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    open_case = store.create_investigation(name="Open")
    closed_case = store.create_investigation(name="Closed")
    for case in (open_case, closed_case):
        _record(store, case["id"], _report("alice", "https://a.test/alice"))
    store.close_investigation(closed_case["id"])

    async def fake_rerun(run, settings, **kwargs):  # type: ignore[no-untyped-def]
        return _report("alice", "https://a.test/alice")

    monkeypatch.setattr(monitor, "rerun_saved_query", fake_rerun)

    outcomes = asyncio.run(monitor.monitor_investigations(store, _settings()))

    assert [outcome.investigation["id"] for outcome in outcomes] == [open_case["id"]]


def _outcome_with_new() -> monitor.CaseOutcome:
    query = monitor.QueryOutcome("username", "alice", "checked", new=[{"source": "new.test", "url": "https://new.test/alice"}])
    return monitor.CaseOutcome(investigation={"id": "0123456789", "name": "Alice Example", "case_ref": "CASE-1"}, queries=[query])


def test_alert_defaults_to_case_ref_and_counts_only() -> None:
    title, body = build_alert([_outcome_with_new()])  # type: ignore[misc]

    assert title == "recce: 1 new finding"
    assert "CASE-1: 1 new across 1 search(es)" in body
    for secret in ("Alice Example", "alice", "new.test"):
        assert secret not in body


def test_alert_detail_is_opt_in() -> None:
    _, body = build_alert([_outcome_with_new()], detail=True)  # type: ignore[misc]
    assert "Alice Example (CASE-1)" in body and "username alice: new.test" in body


def test_no_alert_without_new_evidence() -> None:
    quiet = monitor.CaseOutcome(investigation={"id": "x"}, queries=[monitor.QueryOutcome("username", "a", "checked")])
    assert build_alert([quiet]) is None


def test_ntfy_config_and_send(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    assert NtfyConfig.from_env({}) is None
    config = NtfyConfig.from_env({"RECCE_NTFY_URL": "https://ntfy.example/topic", "RECCE_NTFY_TOKEN": "tk", "RECCE_NTFY_DETAIL": "1"})
    assert config == NtfyConfig(url="https://ntfy.example/topic", token="tk", detail=True)
    sent: dict = {}

    class Resp:
        def raise_for_status(self) -> None:
            pass

    def fake_post(url, content, headers, timeout):  # type: ignore[no-untyped-def]
        sent.update(url=url, body=content.decode(), headers=headers)
        return Resp()

    monkeypatch.setattr("recce.notify.httpx.post", fake_post)

    send(config, "t", "b")

    assert sent["url"] == "https://ntfy.example/topic"
    assert sent["headers"]["Title"] == "t" and sent["headers"]["Authorization"] == "Bearer tk"


# --- site-health alerts ----------------------------------------------------------


def test_health_alert_names_newly_broken_sites() -> None:
    from recce.notify import build_health_alert

    changes = [
        {"site": "Kaggle", "from": "healthy", "to": "false_negative"},
        {"site": "Medium", "from": "blocked", "to": "false_positive"},
        {"site": "Old", "from": "false_positive", "to": "false_positive"},  # unchanged: not a change
        {"site": "Flaky", "from": "healthy", "to": "error"},
        {"site": "Walled", "from": "healthy", "to": "blocked"},
        {"site": "Fresh", "from": None, "to": "false_positive"},  # first sighting
    ]
    title, body = build_health_alert(changes, {"blocked": 90}, {"blocked": 91})
    assert title == "recce: 2 site definitions broke"
    assert "Kaggle: healthy -> false_negative" in body and "Medium: blocked -> false_positive" in body
    assert "Flaky" not in body and "Walled" not in body and "Fresh" not in body


def test_health_alert_flags_a_burned_exit_and_ignores_noise() -> None:
    from recce.notify import build_health_alert

    title, body = build_health_alert([], {"blocked": 90}, {"blocked": 140})
    assert "exit walled more" in title and "from 90 to 140" in body
    assert build_health_alert([], {"blocked": 90}, {"blocked": 100}) is None  # under 20%
    assert build_health_alert([], {"blocked": 5}, {"blocked": 12}) is None  # under the minimum
    assert build_health_alert([{"site": "X", "from": "healthy", "to": "error"}], {"blocked": 5}, {"blocked": 5}) is None
    # No earlier run: nothing to compare against.
    assert build_health_alert([{"site": "X", "from": "healthy", "to": "false_positive"}], None, {"blocked": 1}) is None


def test_selftest_sends_a_health_alert_only_when_something_broke(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from typer.testing import CliRunner

    from recce.cli import app
    from recce.modules import selftest

    monkeypatch.setattr(selftest, "SELFTEST_PATH", tmp_path / "selftest.json")
    monkeypatch.setattr("recce.modules.selftest.SELFTEST_PATH", tmp_path / "selftest.json")
    monkeypatch.setenv("RECCE_NTFY_URL", "https://ntfy.example/topic")
    sent: list[tuple] = []
    monkeypatch.setattr("recce.notify.send", lambda config, title, body, **kw: sent.append((title, body)))
    site = {"name": "Kaggle", "category": "dev", "url": "https://k.test/{u}", "method": "status",
            "found": [200], "missing": [404], "known": ["a"]}
    monkeypatch.setattr("recce.cli.select_sites", lambda **kw: [site])
    verdicts = iter(["healthy", "healthy", "false_negative"])

    async def fake_run(client, sites, **kw):  # type: ignore[no-untyped-def]
        status = next(verdicts)
        results = {"Kaggle": {"status": status, "detail": "", "category": "dev", "fingerprint": "x",
                              "known": None, "canary": None, "checked_at": "2026-10-08T00:00:00+00:00"}}
        return {"version": 1, "recce_version": "t", "ran_at": "2026-10-08T00:00:00+00:00", "duration_s": 0,
                "egress": {}, "impersonate": False, "canary": "c", "summary": selftest.summarise(results),
                "sites": results}

    monkeypatch.setattr("recce.cli.run_selftest", fake_run)
    runner = CliRunner()
    for _ in range(2):  # first run: no earlier state; second: still healthy
        assert runner.invoke(app, ["selftest", "--no-exits"]).exit_code == 0
    assert sent == []
    result = runner.invoke(app, ["selftest", "--no-exits"])
    assert result.exit_code == 0, result.output
    assert len(sent) == 1 and "Kaggle: healthy -> false_negative" in sent[0][1]
