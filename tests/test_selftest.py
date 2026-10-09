# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from typer.testing import CliRunner

from recce.core.result import Hit, Status
from recce.modules import selftest
from recce.modules import username as username_mod
from recce.modules.username import _check_site

SITE = {
    "name": "Example",
    "category": "dev",
    "url": "https://example.test/{u}",
    "method": "status",
    "found": [200],
    "missing": [404],
    "known": ["alice", "bob"],
}


class FakeClient:
    """Routes GETs by URL: `pages` maps a URL to (status, body)."""

    def __init__(self, pages: dict[str, tuple[int, str]], default: int = 404) -> None:
        self.pages = pages
        self.default = default
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(url)
        status, body = self.pages.get(url, (self.default, "missing"))
        return httpx.Response(status, text=body, request=httpx.Request("GET", url))


def _hit(status: Status, code: int | None = None, **extra) -> Hit:  # type: ignore[no-untyped-def]
    return Hit(source="Example", status=status, extra={"status_code": code, **extra})


@pytest.mark.parametrize(
    ("known", "canary", "expected"),
    [
        (_hit(Status.FOUND, 200), _hit(Status.NOT_FOUND, 404), selftest.HEALTHY),
        (_hit(Status.FOUND, 200), _hit(Status.FOUND, 200), selftest.FALSE_POSITIVE),
        (None, _hit(Status.FOUND, 200), selftest.FALSE_POSITIVE),
        (_hit(Status.NOT_FOUND, 404), _hit(Status.NOT_FOUND, 404), selftest.FALSE_NEGATIVE),
        (_hit(Status.UNKNOWN, 403), _hit(Status.UNKNOWN, 403), selftest.BLOCKED),
        (_hit(Status.UNKNOWN, 200, challenge="Cloudflare challenge"), _hit(Status.NOT_FOUND, 404), selftest.BLOCKED),
        (_hit(Status.FOUND, 200), _hit(Status.ERROR), selftest.ERROR),
        (_hit(Status.UNKNOWN, 500), _hit(Status.NOT_FOUND, 404), selftest.ERROR),
        (None, _hit(Status.NOT_FOUND, 404), selftest.UNVERIFIED),
    ],
)
def test_classify(known, canary, expected) -> None:  # type: ignore[no-untyped-def]
    status, _detail = selftest.classify(known, canary)
    assert status == expected


@pytest.mark.asyncio
async def test_check_site_health_tries_next_known_account() -> None:
    client = FakeClient({"https://example.test/bob": (200, "bob")})

    result = await selftest.check_site_health(client, SITE, "qcanary")

    assert result["status"] == selftest.HEALTHY
    assert result["known"]["username"] == "bob"
    assert result["canary"] == {"username": "qcanary", "status": "not_found", "http": 404}
    assert client.calls == [
        "https://example.test/alice", "https://example.test/bob", "https://example.test/qcanary",
    ]


@pytest.mark.asyncio
async def test_check_site_health_flags_site_that_finds_everyone() -> None:
    client = FakeClient({}, default=200)

    result = await selftest.check_site_health(client, SITE, "qcanary")

    assert result["status"] == selftest.FALSE_POSITIVE
    assert result["fingerprint"] == selftest.site_fingerprint(SITE)


@pytest.mark.asyncio
async def test_challenge_page_with_http_200_is_not_a_hit() -> None:
    body = "<html><title>Just a moment...</title><script>window._cf_chl_opt={}</script>"
    client = FakeClient({}, default=200)
    client.pages["https://example.test/alice"] = (200, body)

    hit = await _check_site(client, SITE, "alice")

    assert hit.status is Status.UNKNOWN
    assert hit.extra["challenge"] == "Cloudflare challenge"


@pytest.mark.asyncio
async def test_fastly_client_challenge_with_http_200_is_blocked() -> None:
    # Last.fm serves this to some egress IPs (Proton) for every username.
    body = (
        '<html><head><link href="/_fs-ch-1T1wmsGaOgGaSxcX/assets/styles.css" rel="stylesheet" />'
        "<title>Client Challenge</title></head>"
    )
    client = FakeClient({}, default=200)
    client.pages["https://example.test/alice"] = (200, body)
    client.pages["https://example.test/qcanary"] = (200, body)

    hit = await _check_site(client, SITE, "alice")
    canary = await _check_site(client, SITE, "qcanary")

    assert hit.extra["challenge"] == "Fastly challenge"
    assert selftest.classify(hit, canary)[0] == selftest.BLOCKED


@pytest.mark.asyncio
async def test_run_selftest_records_egress_and_summary() -> None:
    client = FakeClient({
        "https://ipinfo.io/json": (200, json.dumps({"ip": "203.0.113.9", "country": "NL", "org": "AS1 VPN"})),
        "https://example.test/alice": (200, "alice"),
    })

    report = await selftest.run_selftest(client, [SITE], impersonate=False)

    assert report["egress"] == {"ip": "203.0.113.9", "country": "NL", "org": "AS1 VPN"}
    assert report["impersonate"] is False
    assert report["sites"]["Example"]["status"] == selftest.HEALTHY
    assert report["summary"][selftest.HEALTHY] == 1


@pytest.mark.asyncio
async def test_egress_falls_back_to_second_source() -> None:
    client = FakeClient({"https://api.ipify.org?format=json": (200, '{"ip": "198.51.100.1"}')})

    assert await selftest.egress_info(client) == {"ip": "198.51.100.1"}


def _entry(status: str, site=SITE, checked_at: datetime | None = None) -> dict:  # type: ignore[no-untyped-def]
    when = checked_at or datetime.now(timezone.utc)
    return {
        "status": status,
        "category": site["category"],
        "fingerprint": selftest.site_fingerprint(site),
        "checked_at": when.isoformat(timespec="seconds"),
    }


def _report(sites: dict) -> dict:
    return {"ran_at": "2026-10-08T00:00:00+00:00", "egress": {}, "summary": selftest.summarise(sites), "sites": sites}


def test_save_report_merges_partial_runs_and_diffs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "selftest.json"
    first = selftest.save_report(
        _report({"A": _entry(selftest.HEALTHY), "B": _entry(selftest.HEALTHY)}), path,
    )
    assert [c["to"] for c in first] == [selftest.HEALTHY, selftest.HEALTHY]

    changes = selftest.save_report(_report({"B": _entry(selftest.FALSE_POSITIVE)}), path)

    assert changes == [{"site": "B", "from": selftest.HEALTHY, "to": selftest.FALSE_POSITIVE}]
    state = selftest.load_state(path)
    assert set(state["sites"]) == {"A", "B"}
    assert state["summary"][selftest.FALSE_POSITIVE] == 1
    assert state["run_sites"] == 1


def test_search_flags_ignore_stale_or_changed_definitions(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "selftest.json"
    changed = {**SITE, "name": "Changed"}
    stale = {**SITE, "name": "Stale"}
    old = datetime.now(timezone.utc) - timedelta(days=45)
    selftest.save_report(_report({
        "Example": _entry(selftest.FALSE_POSITIVE),
        "Changed": _entry(selftest.FALSE_POSITIVE, site={**changed, "missing": [410]}),
        "Stale": _entry(selftest.FALSE_POSITIVE, site=stale, checked_at=old),
    }), path)

    flags = selftest.search_flags([SITE, changed, stale], path=path)

    assert list(flags) == ["Example"]


def test_known_list_does_not_change_fingerprint() -> None:
    assert selftest.site_fingerprint(SITE) == selftest.site_fingerprint({**SITE, "known": ["carol"]})


def test_flagged_policy_reads_env_and_rejects_junk(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    assert selftest.flagged_policy() == "skip"
    monkeypatch.setenv(selftest.FLAGGED_ENV, "mark")
    assert selftest.flagged_policy() == "mark"
    assert selftest.flagged_policy("off") == "off"
    with pytest.raises(ValueError):
        selftest.flagged_policy("maybe")


GOOD = {**SITE, "name": "Good", "url": "https://good.test/{u}"}


async def _search(monkeypatch, policy: str | None):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False, **_: [SITE, GOOD])
    selftest.save_report(_report({"Example": _entry(selftest.FALSE_POSITIVE)}))
    client = FakeClient({}, default=200)
    report = await username_mod._search_username(
        "alice", client, only_categories=None, exclude_categories=None, include_nsfw=False,
        show_progress=False, per_domain_rate=0, guarded_backoff_seconds=0, verify_found=False,
        flagged_sites=policy,
    )
    return client, {h.source: h for h in report.hits}


@pytest.mark.asyncio
async def test_search_skips_false_positive_sites_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client, hits = await _search(monkeypatch, None)

    assert hits["Example"].status is Status.SKIPPED
    assert "made-up usernames" in hits["Example"].summary
    assert hits["Good"].status is Status.FOUND
    assert client.calls == ["https://good.test/alice"]


@pytest.mark.asyncio
async def test_search_mark_policy_probes_and_downgrades(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _client, hits = await _search(monkeypatch, "mark")

    assert hits["Example"].status is Status.UNKNOWN
    assert hits["Example"].confidence <= 0.2
    assert hits["Example"].extra["selftest"]["status"] == selftest.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_search_off_policy_ignores_selftest(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _client, hits = await _search(monkeypatch, "off")

    assert hits["Example"].status is Status.FOUND
    assert "selftest" not in hits["Example"].extra


def test_annotate_marks_misses_from_false_negative_sites() -> None:
    hit = Hit(source="Example", status=Status.NOT_FOUND, confidence=0.9)

    selftest.annotate_hit(hit, _entry(selftest.FALSE_NEGATIVE))

    assert hit.status is Status.NOT_FOUND
    assert hit.confidence == 0.3
    assert "unreliable" in hit.summary


def test_select_sites_borrows_wmn_known_accounts(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    custom = {**SITE, "name": "GitLab"}
    custom.pop("known")
    monkeypatch.setattr(selftest, "_load_sites", lambda include_nsfw=False, **_: [custom, GOOD])
    monkeypatch.setattr(selftest, "_load_wmn_sites", lambda: [{"name": "gitlab", "known": ["skennedy"]}])

    sites = {s["name"]: s for s in selftest.select_sites(names={"gitlab"})}

    assert list(sites) == ["GitLab"]
    assert sites["GitLab"]["known"] == ["skennedy"]


def test_cli_selftest_json(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from recce import cli

    async def fake_run(client, sites, **kwargs):  # type: ignore[no-untyped-def]
        results = {s["name"]: _entry(selftest.FALSE_POSITIVE, site=s) for s in sites}
        return {**_report(results), "canary": "qx", "impersonate": False, "duration_s": 0.1}

    monkeypatch.setattr(cli, "select_sites", lambda **kwargs: [SITE])
    monkeypatch.setattr(cli, "run_selftest", fake_run)

    result = CliRunner().invoke(cli.app, ["selftest", "--only", "example", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["sites"]["Example"]["status"] == selftest.FALSE_POSITIVE
    assert data["changes"] == [{"site": "Example", "from": None, "to": selftest.FALSE_POSITIVE}]
    assert selftest.load_state()["sites"]["Example"]["status"] == selftest.FALSE_POSITIVE


def test_cli_selftest_table(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce import cli

    async def fake_run(client, sites, **kwargs):  # type: ignore[no-untyped-def]
        results = {"Example": {**_entry(selftest.BLOCKED), "detail": "HTTP 403 (egress-dependent)"}}
        return {
            **_report(results), "canary": "qx", "impersonate": True, "duration_s": 1.0,
            "egress": {"ip": "203.0.113.9", "country": "NL"},
        }

    monkeypatch.setattr(cli, "select_sites", lambda **kwargs: [SITE])
    monkeypatch.setattr(cli, "run_selftest", fake_run)

    result = CliRunner().invoke(cli.app, ["selftest", "--no-save"])

    assert result.exit_code == 0, result.output
    assert "203.0.113.9" in result.output
    assert "blocked" in result.output
    assert selftest.load_state() is None
