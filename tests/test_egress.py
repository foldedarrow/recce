# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from recce.cli import app
from recce.core.egress import (
    DIRECT_EXIT,
    Exit,
    configured_exits,
    named_exits,
    parse_exit,
    redact_proxy,
    resolve_exit,
    resolve_fallback,
)
from recce.core.investigations import InvestigationStore
from recce.core.result import Report, Status
from recce.modules import username as username_mod

runner = CliRunner()
TOR = "socks5h://127.0.0.1:9050"
ENV = {
    "RECCE_EXITS": f"tor={TOR}; home=socks5h://kit:s3cret@10.0.0.2:1080",
    "RECCE_PROXY": "home",
    "RECCE_DOMAIN_PROXY": "direct",
    "RECCE_USERNAME_FALLBACK_PROXY": "tor",
}


# --- configuration -----------------------------------------------------------


def test_redact_proxy_masks_passwords_only() -> None:
    assert redact_proxy("socks5h://kit:s3cret@10.0.0.2:1080") == "socks5h://kit:***@10.0.0.2:1080"
    assert redact_proxy(TOR) == TOR
    assert Exit("home", "http://kit:s3cret@proxy.test:3128").label == "home (http://kit:***@proxy.test:3128)"
    assert DIRECT_EXIT.label == "direct"


def test_named_exits_and_parse_exit() -> None:
    exits = named_exits(ENV)
    assert exits == {"tor": TOR, "home": "socks5h://kit:s3cret@10.0.0.2:1080"}
    assert parse_exit("TOR", exits) == Exit("tor", TOR)
    assert parse_exit("direct", exits) == DIRECT_EXIT
    assert parse_exit("http://proxy.test:3128", exits) == Exit("http://proxy.test:3128", "http://proxy.test:3128")
    assert parse_exit("", exits) is None
    with pytest.raises(ValueError, match=r"unknown exit 'vpn2'.*home, tor"):
        parse_exit("vpn2", exits)


def test_resolve_exit_precedence() -> None:
    assert resolve_exit("username", env=ENV).name == "home"  # RECCE_PROXY
    assert resolve_exit("domain", env=ENV) == DIRECT_EXIT  # RECCE_DOMAIN_PROXY wins
    assert resolve_exit("domain", "tor", env=ENV) == Exit("tor", TOR)  # --proxy wins
    assert resolve_exit("email", env={}) == DIRECT_EXIT
    assert resolve_fallback(env=ENV) == Exit("tor", TOR)
    assert resolve_fallback("direct", env=ENV) == DIRECT_EXIT
    assert resolve_fallback(env={}) is None


def test_configured_exits_lists_what_uses_each_exit() -> None:
    rows = [(use, exit_.label) for use, exit_ in configured_exits(ENV)]

    assert rows == [
        ("username", "home (socks5h://kit:***@10.0.0.2:1080)"),
        ("email", "home (socks5h://kit:***@10.0.0.2:1080)"),
        ("phone", "home (socks5h://kit:***@10.0.0.2:1080)"),
        ("domain", "direct"),
        ("username fallback", f"tor ({TOR})"),
    ]


# --- fallback retry ------------------------------------------------------------


def _sites() -> list[dict]:
    def site(name: str, host: str) -> dict:
        return {
            "name": name, "category": "social", "url": f"https://{host}/{{u}}",
            "method": "status", "found": [200], "missing": [404],
        }

    return [site("Walled", "walled.test"), site("Open", "open.test"), site("Fortress", "fortress.test")]


class SiteClient:
    """Answers per host: 'block' → 403, 'know' → 200 for alice / 404 otherwise."""

    def __init__(self, behaviour: dict[str, str], proxy: str | None = None) -> None:
        self.behaviour = behaviour
        self.proxy = proxy
        self.timeout = 3.0
        self.max_concurrency = 4
        self.user_agent = "recce-test"
        self.requests: list[str] = []
        self.closed = False

    async def request_detailed(self, method: str, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append(url)
        host = httpx.URL(url).host
        mode = self.behaviour.get(host, "know")
        code = 403 if mode == "block" else (200 if url.endswith("/alice") else 404)
        return httpx.Response(code, text="", request=httpx.Request(method, url)), None

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        resp, _ = await self.request_detailed("GET", url)
        return resp

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_blocked_probes_are_retried_through_the_fallback_exit(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_EXITS", f"tor={TOR}")
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False, **_: _sites())
    primary = SiteClient({"walled.test": "block", "fortress.test": "block"})
    fallback = SiteClient({"fortress.test": "block"}, proxy=TOR)
    monkeypatch.setattr(username_mod, "_client_for_exit", lambda client, exit_, browser: fallback)

    report = await username_mod.search_username(
        "alice", primary, show_progress=False, impersonate=False, per_domain_rate=0,
        guarded_backoff_seconds=0, flagged_sites="off", attribute_hits=False,
        fallback_exit=Exit("tor", TOR),
    )

    hits = {h.source: h for h in report.hits}
    assert report.exit == "direct"
    walled = hits["Walled"]
    assert walled.status is Status.FOUND
    assert walled.extra["exit"] == f"tor ({TOR})"
    assert walled.extra["fallback"]["primary"] == "HTTP 403"
    assert walled.summary.endswith(f"via tor ({TOR})")
    # The made-up-username check ran through the exit that found the account.
    assert walled.extra["canary"]["status"] == "not_found"
    assert sum("walled.test" in u for u in fallback.requests) == 2
    assert hits["Open"].status is Status.FOUND and "exit" not in hits["Open"].extra
    fortress = hits["Fortress"]
    assert fortress.status is Status.UNKNOWN
    assert fortress.extra["fallback"]["status"] == "unknown"
    assert "exit" not in fortress.extra
    assert not any("open.test" in u for u in fallback.requests)
    assert fallback.closed


@pytest.mark.asyncio
async def test_no_fallback_means_no_retry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False, **_: _sites())
    primary = SiteClient({"walled.test": "block"}, proxy=TOR)
    monkeypatch.setenv("RECCE_EXITS", f"tor={TOR}")

    report = await username_mod.search_username(
        "alice", primary, show_progress=False, impersonate=False, per_domain_rate=0,
        guarded_backoff_seconds=0, flagged_sites="off", attribute_hits=False,
    )

    assert report.exit == f"tor ({TOR})"
    walled = next(h for h in report.hits if h.source == "Walled")
    assert walled.status is Status.UNKNOWN and "fallback" not in walled.extra


# --- surfaces --------------------------------------------------------------------


def test_cli_resolves_exits_and_shows_them(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    for key in list(ENV):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("RECCE_EXITS", f"tor={TOR}")
    monkeypatch.setenv("RECCE_USERNAME_FALLBACK_PROXY", "tor")
    seen: dict = {}

    async def fake_username(name, client, **kwargs):  # type: ignore[no-untyped-def]
        seen["proxy"] = client.proxy
        seen["fallback"] = kwargs["fallback_exit"]
        report = Report(query=name, query_type="username", exit=f"tor ({TOR})")
        report.finish()
        return report

    monkeypatch.setattr("recce.cli.search_username", fake_username)

    result = runner.invoke(app, ["username", "alice", "--proxy", "tor", "--no-providers"])

    assert result.exit_code == 0, result.output
    assert seen == {"proxy": TOR, "fallback": Exit("tor", TOR)}
    assert f"exit: tor ({TOR})" in result.output
    assert f"Exit: tor ({TOR})" in result.output

    bad = runner.invoke(app, ["username", "alice", "--proxy", "nowhere"])
    assert bad.exit_code == 2
    assert "unknown exit 'nowhere'" in bad.output


def test_doctor_lists_exits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)

    result = runner.invoke(app, ["doctor", "--no-network"])

    assert result.exit_code == 0, result.output
    assert "Exits:" in result.output
    assert "username fallback" in result.output
    assert "s3cret" not in result.output


def test_exit_is_in_investigation_exports(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Exit")
    report = Report(query="alice", query_type="username", exit=f"tor ({TOR})")
    report.finish()
    store.record_run(investigation_id=inv["id"], report=report, args={}, recce_version="t", wmn_cache={})

    assert f"- Exit: tor ({TOR})" in store.export_markdown(inv["id"])


def test_fallback_list_becomes_an_ordered_chain() -> None:
    from recce.core.egress import ExitChain, fallback_exits

    env = {**ENV, "RECCE_USERNAME_FALLBACK_PROXY": "tor, home"}
    chain = resolve_fallback(env=env)

    assert isinstance(chain, ExitChain)
    assert [exit_.name for exit_ in fallback_exits(chain)] == ["tor", "home"]
    assert chain.label == f"tor ({TOR}) → home (socks5h://kit:***@10.0.0.2:1080)"
    assert [label for label, _ in configured_exits(env) if label.startswith("username fallback")] == [
        "username fallback 1",
        "username fallback 2",
    ]
    # A single value is still a plain Exit.
    assert resolve_fallback("tor", env=ENV) == Exit("tor", TOR)


@pytest.mark.asyncio
async def test_fallback_chain_retries_only_what_earlier_exits_left_blocked(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce.core.egress import ExitChain
    from recce.core.output import fallback_note

    home_url = "socks5h://127.0.0.1:1080"
    monkeypatch.setenv("RECCE_EXITS", f"tor={TOR};home={home_url}")
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False, **_: _sites())
    primary = SiteClient({"walled.test": "block", "fortress.test": "block"})
    tor = SiteClient({"fortress.test": "block"}, proxy=TOR)  # Tor gets past Walled, not Fortress
    home = SiteClient({}, proxy=home_url)  # home gets past everything
    clients = {TOR: tor, home_url: home}
    monkeypatch.setattr(username_mod, "_client_for_exit", lambda client, exit_, browser: clients[exit_.proxy])

    report = await username_mod.search_username(
        "alice", primary, show_progress=False, impersonate=False, per_domain_rate=0,
        guarded_backoff_seconds=0, flagged_sites="off", attribute_hits=False,
        fallback_exit=ExitChain((Exit("tor", TOR), Exit("home", home_url))),
    )

    hits = {h.source: h for h in report.hits}
    assert hits["Walled"].extra["exit"] == f"tor ({TOR})"
    fortress = hits["Fortress"]
    assert fortress.status is Status.FOUND and fortress.extra["exit"] == f"home ({home_url})"
    assert [a["exit"] for a in fortress.extra["fallback_attempts"]] == [f"tor ({TOR})", f"home ({home_url})"]
    assert fortress.extra["fallback"]["primary"] == "HTTP 403"
    # Home only saw what Tor couldn't answer (plus that hit's canary re-check).
    assert not any("walled.test" in u for u in home.requests)
    assert not any("open.test" in u for u in tor.requests + home.requests)
    assert tor.closed and home.closed
    note = fallback_note(report)
    assert f"1 via tor ({TOR})" in note and f"1 via home ({home_url})" in note and "0 still blocked" in note


def test_ipv4_exits_flag_named_exits() -> None:
    env = {**ENV, "RECCE_IPV4_EXITS": "home", "RECCE_USERNAME_FALLBACK_PROXY": "tor,home"}
    tor, home = resolve_fallback(env=env).exits  # type: ignore[union-attr]

    assert (tor.ipv4, home.ipv4) == (False, True)
    assert resolve_exit("username", env=env).ipv4 is True  # RECCE_PROXY=home
    assert resolve_fallback("tor", env=env) == Exit("tor", TOR)


def test_impersonating_client_forces_ipv4_resolution(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import curl_cffi.requests as cffi_requests

    from recce.core.http import ImpersonatingClient

    seen: dict = {}

    class FakeSession:
        def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
            seen.update(kwargs)

    monkeypatch.setattr(cffi_requests, "AsyncSession", FakeSession)

    ImpersonatingClient(proxy="socks5://127.0.0.1:1080", ipv4=True)
    assert list(seen["curl_options"].values()) == [1]  # CURL_IPRESOLVE_V4

    seen.clear()
    ImpersonatingClient(proxy="socks5://127.0.0.1:1080")
    assert seen["curl_options"] is None
    # curl_cffi's own cap (10 transfers) must not undercut the configured concurrency.
    assert seen["max_clients"] == 30
    seen.clear()
    ImpersonatingClient(max_concurrency=90)
    assert seen["max_clients"] == 90


# --- per-site exit preferences (selftest-learned) -----------------------------------

HOME_URL = "socks5h://127.0.0.1:1080"
TOR_LABEL = f"tor ({TOR})"
HOME_LABEL = f"home ({HOME_URL})"


def _learned(tmp_path: Path, monkeypatch, exits_by_site: dict[str, dict[str, str]]) -> None:  # type: ignore[no-untyped-def]
    """Write a selftest state saying how each exit fared on each (blocked) site."""
    from datetime import datetime, timezone

    from recce.modules import selftest

    sites = {s["name"]: s for s in _sites()}
    state = {"sites": {}}
    for name, verdicts in exits_by_site.items():
        state["sites"][name] = {
            "status": "blocked",
            "fingerprint": selftest.site_fingerprint(sites[name]),
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "exits": {label: {"status": status} for label, status in verdicts.items()},
        }
    path = tmp_path / "selftest.json"
    path.write_text(__import__("json").dumps(state))
    monkeypatch.setattr(selftest, "SELFTEST_PATH", path)


def test_exit_order_puts_working_exits_first_and_drops_walled_ones(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce.modules import selftest

    _learned(tmp_path, monkeypatch, {
        "Walled": {TOR_LABEL: "blocked", HOME_LABEL: "healthy"},
        "Fortress": {TOR_LABEL: "error", HOME_LABEL: "healthy"},
    })
    order = selftest.exit_order(_sites(), [TOR_LABEL, HOME_LABEL])
    assert order["Walled"] == [HOME_LABEL]  # Tor is walled for it: dropped
    assert order["Fortress"] == [HOME_LABEL, TOR_LABEL]
    assert order["Open"] == [TOR_LABEL, HOME_LABEL]  # nothing learned: configured order


def test_exit_order_ignores_stale_or_changed_verdicts(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce.modules import selftest

    _learned(tmp_path, monkeypatch, {"Walled": {TOR_LABEL: "blocked"}})
    changed = [{**_sites()[0], "url": "https://elsewhere.test/{u}"}]
    assert selftest.exit_order(changed, [TOR_LABEL])["Walled"] == [TOR_LABEL]
    later = datetime.now(timezone.utc) + timedelta(days=60)
    assert selftest.exit_order(_sites(), [TOR_LABEL], now=later)["Walled"] == [TOR_LABEL]


@pytest.mark.asyncio
async def test_search_follows_the_learned_exit_order(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce.core.egress import ExitChain

    monkeypatch.setenv("RECCE_EXITS", f"tor={TOR};home={HOME_URL}")
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False, **_: _sites())
    _learned(tmp_path, monkeypatch, {
        "Walled": {TOR_LABEL: "blocked", HOME_LABEL: "healthy"},
        "Fortress": {TOR_LABEL: "blocked", HOME_LABEL: "blocked"},
    })
    primary = SiteClient({"walled.test": "block", "fortress.test": "block"})
    tor = SiteClient({}, proxy=TOR)  # Tor would answer everything, but selftest says it is walled
    home = SiteClient({}, proxy=HOME_URL)
    clients = {TOR: tor, HOME_URL: home}
    monkeypatch.setattr(username_mod, "_client_for_exit", lambda client, exit_, browser: clients[exit_.proxy])

    report = await username_mod.search_username(
        "alice", primary, show_progress=False, impersonate=False, per_domain_rate=0,
        guarded_backoff_seconds=0, flagged_sites="mark", attribute_hits=False,
        fallback_exit=ExitChain((Exit("tor", TOR), Exit("home", HOME_URL))),
    )

    hits = {h.source: h for h in report.hits}
    assert hits["Walled"].status is Status.FOUND and hits["Walled"].extra["exit"] == HOME_LABEL
    assert not any("walled.test" in u for u in tor.requests)
    # Walled on every exit: not retried at all, and the hit says why.
    assert hits["Fortress"].status is Status.UNKNOWN
    assert "fallback_skipped" in hits["Fortress"].extra
    assert not any("fortress.test" in u for u in tor.requests + home.requests)


@pytest.mark.asyncio
async def test_selftest_probes_blocked_sites_through_the_fallback_exits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from recce.modules import selftest

    site = {"name": "Walled", "category": "social", "url": "https://walled.test/{u}",
            "method": "status", "found": [200], "missing": [404], "known": ["alice"]}
    primary = SiteClient({"walled.test": "block"})
    open_exit = SiteClient({}, proxy=TOR)
    monkeypatch.setattr(selftest, "_client_for_exit", lambda client, exit_, browser: open_exit)

    report = await selftest.run_selftest(
        primary, [site], impersonate=False, per_domain_rate=0, fallback_exits=(Exit("tor", TOR),),
    )

    entry = report["sites"]["Walled"]
    assert entry["status"] == selftest.BLOCKED
    assert entry["exits"][TOR_LABEL]["status"] == selftest.HEALTHY
    assert open_exit.closed
