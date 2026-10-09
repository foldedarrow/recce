# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from datetime import datetime, timedelta, timezone
from typing import ClassVar

import httpx
import pytest

from recce.core.result import Status
from recce.modules import maigret, selftest
from recce.modules import username as username_mod
from recce.modules.username import _check_site, _classify

ENGINES = {
    "Forum": {
        "name": "Forum",
        "site": {
            "checkType": "message",
            "url": "{urlMain}{urlSubpath}/members/?username={username}",
            "absenceStrs": ["member cannot be found"],
            "presenseStrs": ["engine-marker"],
            "errors": {"Too many requests": "Rate limited"},
            "ignore403": True,
        },
    }
}


def _entry(**overrides):  # type: ignore[no-untyped-def]
    base = {
        "url": "https://www.example.test/u/{username}",
        "urlMain": "https://www.example.test",
        "checkType": "status_code",
        "usernameClaimed": "alice",
        "usernameUnclaimed": "noonewouldeverusethis7",
        "tags": ["ru", "coding"],
    }
    return {**base, **overrides}


def test_translate_status_code_site() -> None:
    site = maigret.translate("Example", _entry(), ENGINES)

    assert site == {
        "name": "Example",
        "category": "coding",
        "url": "https://www.example.test/u/{u}",
        "method": "maigret",
        "check": "status_code",
        "source": "maigret",
        "known": ["alice"],
    }


def test_translate_applies_engine_like_maigret() -> None:
    entry = {
        "engine": "Forum",
        "urlMain": "https://forum.example.test/",
        "urlSubpath": "/community",
        "absenceStrs": ["site-specific miss"],
        "ignore403": False,
        "usernameClaimed": "bob",
        "tags": ["forum", "discussion", "de"],
    }

    site = maigret.translate("Forum Example", entry, ENGINES)

    assert site is not None
    # Lists concatenate (site first), dicts merge, scalars the site states win.
    assert site["absence"] == ["site-specific miss", "member cannot be found"]
    assert site["presence"] == ["engine-marker"]
    assert site["errors"] == {"Too many requests": "Rate limited"}
    assert "ignore403" not in site
    assert site["check"] == "message"
    # {urlMain}/ + /community collapses its doubled slashes, as Maigret does.
    assert site["url"] == "https://forum.example.test/community/members/?username={u}"
    assert site["category"] == "forum"


@pytest.mark.parametrize(
    "overrides",
    [
        {"disabled": True},
        {"type": "vk_id"},
        {"protocol": "tor"},
        {"requestMethod": "POST", "requestPayload": {"u": "{username}"}},
        {"activation": {"method": "twitter"}},
        {"similarSearch": True},
        {"errorUrl": "https://www.example.test/"},
        {"regexCheck": "^[0-9]+$"},  # numeric IDs: a canary can't verify it
        {"checkType": "something_new"},
        {"url": "{urlMain}/{unknownField}/{username}"},
    ],
)
def test_translate_leaves_out_what_recce_cannot_run(overrides) -> None:  # type: ignore[no-untyped-def]
    assert maigret.translate("Example", _entry(**overrides), ENGINES) is None


def test_translate_keeps_a_regex_the_canary_satisfies() -> None:
    site = maigret.translate("Example", _entry(regexCheck="^[a-z0-9]{3,20}$"), ENGINES)

    assert site is not None and site["regex"] == "^[a-z0-9]{3,20}$"


def test_nsfw_tags_map_to_the_wmn_nsfw_category() -> None:
    site = maigret.translate("Adult", _entry(tags=["us", "webcam"]), ENGINES)

    assert site is not None and site["category"] == maigret.NSFW_CATEGORY


@pytest.mark.parametrize(
    ("site", "status_code", "body", "expected"),
    [
        ({"check": "message", "presence": ["profile-header"], "absence": ["not found"]}, 200,
         "<div class=profile-header>", Status.FOUND),
        ({"check": "message", "presence": ["profile-header"], "absence": ["not found"]}, 200,
         "profile-header ... not found", Status.NOT_FOUND),
        ({"check": "message", "absence": ["not found"]}, 200, "any page", Status.FOUND),
        ({"check": "message", "absence": ["not found"]}, 200, "", Status.NOT_FOUND),
        ({"check": "status_code"}, 200, "", Status.FOUND),
        ({"check": "status_code"}, 404, "", Status.NOT_FOUND),
        ({"check": "status_code"}, 302, "", Status.NOT_FOUND),
        ({"check": "response_url", "presence": ["user"]}, 200, "user page", Status.FOUND),
        ({"check": "response_url"}, 301, "", Status.NOT_FOUND),
        # Refusals are "could not check", never "not found".
        ({"check": "status_code"}, 403, "", Status.UNKNOWN),
        ({"check": "status_code"}, 429, "", Status.UNKNOWN),
        ({"check": "status_code"}, 503, "", Status.UNKNOWN),
        ({"check": "status_code"}, 999, "", Status.UNKNOWN),
        ({"check": "status_code", "ignore403": True}, 403, "", Status.NOT_FOUND),
        ({"check": "status_code", "errors": {"rate limited": "Rate limited"}}, 200,
         "you are rate limited", Status.UNKNOWN),
    ],
)
def test_classify_maigret(site, status_code, body, expected) -> None:  # type: ignore[no-untyped-def]
    status, _note = _classify({"method": "maigret", **site}, status_code, body, "alice")
    assert status is expected


@pytest.mark.asyncio
async def test_response_url_probe_does_not_follow_redirects() -> None:
    calls = []

    class Client:
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(kwargs)
            return httpx.Response(302, headers={"Location": "/"}, request=httpx.Request("GET", url))

    site = maigret.translate("Example", _entry(checkType="response_url"), ENGINES)
    hit = await _check_site(Client(), site, "alice")  # type: ignore[arg-type]

    assert calls[0]["follow_redirects"] is False
    assert hit.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_a_body_that_fails_to_decode_still_classifies() -> None:
    class BadCharsetResponse:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {}
        url = "https://forum.test/u/alice"
        encoding = "utf-8"
        content = "Профиль alice".encode("cp1251")

        @property
        def text(self) -> str:
            return self.content.decode("utf-8")  # raises, as curl_cffi does

    class Client:
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            return BadCharsetResponse()

    site = maigret.translate("Example", _entry(checkType="message", absenceStrs=["no such user"]), ENGINES)
    hit = await _check_site(Client(), site, "alice")  # type: ignore[arg-type]

    assert hit.status is Status.FOUND


@pytest.mark.parametrize(
    ("template", "domain"),
    [
        ("https://www.Example.test/u/{u}", "example.test"),
        ("https://{u}.tumblr.test/", "tumblr.test"),
        ("https://forum.example.test/members/{u}", "forum.example.test"),
        ("http://example.test:8080/{u}", "example.test"),
    ],
)
def test_normalised_domain(template, domain) -> None:  # type: ignore[no-untyped-def]
    assert maigret.normalised_domain(template) == domain


def test_merge_drops_sites_wmn_or_custom_already_cover() -> None:
    existing = [
        {"name": "GitHub", "url": "https://github.test/{u}", "probe": "https://api.github.test/users/{u}"},
        {"name": "Tumblr", "url": "https://{u}.tumblr.test"},
        {"name": "Codeberg", "url": "https://codeberg.test/{u}"},
    ]
    candidates = [
        {"name": "GitHub (Maigret)", "url": "https://www.github.test/{u}"},
        {"name": "Tumblr blogs", "url": "https://tumblr.test/blog/{u}"},
        {"name": "GitHub API", "url": "https://elsewhere.test/{u}", "probe": "https://api.github.test/{u}"},
        {"name": "codeberg", "url": "https://other.test/{u}"},  # name clash
        {"name": "Forum", "url": "https://forum.github.test/u/{u}"},  # a different host: kept
    ]

    kept = [s["name"] for s in maigret.merge(existing, candidates)]

    assert kept == ["Forum"]


def test_translate_all_keeps_one_entry_per_domain() -> None:
    data = {
        "engines": {},
        "sites": {
            "First": _entry(),
            "Second": _entry(url="https://example.test/profile/{username}"),
            "Other": _entry(url="https://other.test/{username}"),
        },
    }

    assert [s["name"] for s in maigret.translate_all(data)] == ["First", "Other"]


def test_bundled_snapshot_loads_and_a_corrupt_cache_falls_back(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    bundled = maigret.load_sites()
    cache = tmp_path / "broken.json"
    cache.write_text("{not json")
    monkeypatch.setattr(maigret, "CACHED_MAIGRET", cache)

    assert len(bundled) > 3000
    assert all(s["method"] == "maigret" and s["source"] == "maigret" for s in bundled)
    assert len(maigret.load_sites()) == len(bundled)


def test_loaded_maigret_sites_never_share_a_domain_with_wmn_or_custom() -> None:
    sites = username_mod._load_sites(maigret=True)
    base = [s for s in sites if username_mod.site_source(s) != "maigret"]
    taken = set().union(*(maigret.site_domains(s) for s in base))
    added = [s for s in sites if username_mod.site_source(s) == "maigret"]

    assert added
    assert not [s["name"] for s in added if maigret.site_domains(s) & taken]


# ---------------------------------------------------------------------------
# Selftest gate
# ---------------------------------------------------------------------------

M_GOOD = {"name": "MGood", "category": "forum", "url": "https://mgood.test/{u}", "method": "maigret",
          "check": "status_code", "source": "maigret", "known": ["alice"]}
M_BAD = {**M_GOOD, "name": "MBad", "url": "https://mbad.test/{u}"}
M_WALLED = {**M_GOOD, "name": "MWalled", "url": "https://mwalled.test/{u}"}
M_NEW = {**M_GOOD, "name": "MNew", "url": "https://mnew.test/{u}"}
WMN = {"name": "Wmn", "category": "dev", "url": "https://wmn.test/{u}", "method": "status",
       "found": [200], "missing": [404]}


def _verdict(site, status, *, exits=None, age=timedelta(0)):  # type: ignore[no-untyped-def]
    entry = {
        "status": status,
        "category": site["category"],
        "source": "maigret",
        "fingerprint": selftest.site_fingerprint(site),
        "checked_at": (datetime.now(timezone.utc) - age).isoformat(timespec="seconds"),
    }
    if exits:
        entry["exits"] = exits
    return entry


def _save(sites: dict) -> None:  # type: ignore[type-arg]
    selftest.save_report({"ran_at": "2026-10-09T00:00:00+00:00", "egress": {},
                          "summary": selftest.summarise(sites), "sites": sites})


def test_maigret_verified_needs_a_fresh_healthy_verdict() -> None:
    stale = {**M_GOOD, "name": "MStale", "url": "https://mstale.test/{u}"}
    changed = {**M_GOOD, "name": "MChanged", "url": "https://mchanged.test/{u}"}
    _save({
        "MGood": _verdict(M_GOOD, selftest.HEALTHY),
        "MBad": _verdict(M_BAD, selftest.FALSE_POSITIVE),
        "MWalled": _verdict(M_WALLED, selftest.BLOCKED, exits={"tor": {"status": selftest.HEALTHY}}),
        "MStale": _verdict(stale, selftest.HEALTHY, age=timedelta(days=45)),
        "MChanged": _verdict({**changed, "check": "message"}, selftest.HEALTHY),
    })

    verified = selftest.maigret_verified([M_GOOD, M_BAD, M_WALLED, M_NEW, stale, changed])

    assert verified == {"MGood", "MWalled"}


@pytest.mark.parametrize(
    ("policy", "expected"),
    [(None, {"Wmn", "MGood"}), ("all", {"Wmn", "MGood", "MBad", "MNew"}), ("off", {"Wmn"})],
)
def test_search_sites_gates_maigret_by_policy(monkeypatch, policy, expected) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        username_mod, "_load_sites",
        lambda include_nsfw=False, maigret=False: [WMN] + ([M_GOOD, M_BAD, M_NEW] if maigret else []),
    )
    _save({"MGood": _verdict(M_GOOD, selftest.HEALTHY), "MBad": _verdict(M_BAD, selftest.FALSE_NEGATIVE)})

    assert {s["name"] for s in username_mod.search_sites(maigret=policy)} == expected


def test_policy_reads_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(maigret.POLICY_ENV, "off")
    assert maigret.policy() == "off"
    assert maigret.policy("all") == "all"
    with pytest.raises(ValueError):
        maigret.policy("some")


@pytest.mark.asyncio
async def test_search_skips_sites_whose_regex_rejects_the_username(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    picky = {**M_GOOD, "name": "Picky", "url": "https://picky.test/{u}", "regex": "^[a-z]{3,8}$"}
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False, **_: [M_GOOD, picky])
    calls = []

    class Client:
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(url)
            return httpx.Response(404, request=httpx.Request("GET", url))

    await username_mod._search_username(
        "alice_99", Client(), only_categories=None, exclude_categories=None, include_nsfw=False,
        show_progress=False, per_domain_rate=0, guarded_backoff_seconds=0, verify_found=False,
        flagged_sites="off", maigret="all",
    )

    assert calls == ["https://mgood.test/alice_99"]


def test_select_sites_includes_unverified_maigret_and_filters_by_source(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        selftest, "_load_sites",
        lambda include_nsfw=False, maigret=False: [WMN] + ([M_GOOD, M_NEW] if maigret else []),
    )

    assert {s["name"] for s in selftest.select_sites()} == {"Wmn", "MGood", "MNew"}
    assert {s["name"] for s in selftest.select_sites(sources={"maigret"})} == {"MGood", "MNew"}


@pytest.mark.asyncio
async def test_health_entries_record_their_source() -> None:
    class Client:
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            return httpx.Response(200 if url.endswith("/alice") else 404, request=httpx.Request("GET", url))

    entry = await selftest.check_site_health(Client(), M_GOOD, "qcanary12345")

    assert entry["status"] == selftest.HEALTHY
    assert entry["source"] == "maigret"


# ---------------------------------------------------------------------------
# recce update
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_refresh_writes_cache_and_counts_importable_sites(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(maigret, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(maigret, "CACHED_MAIGRET", cache_dir / "maigret-data.json")
    payload = {"engines": {}, "sites": {"A": _entry(), "B": _entry(url="https://b.test/{username}"),
                                        "Off": _entry(url="https://c.test/{username}", disabled=True)}}

    class Client:
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url == maigret.MAIGRET_REMOTE
            return httpx.Response(200, text=json.dumps(payload), request=httpx.Request("GET", url))

    before, after = await maigret.refresh_data(Client())  # type: ignore[arg-type]

    assert before > 3000 and after == 2
    assert [s["name"] for s in maigret.load_sites()] == ["A", "B"]
    assert maigret.cache_status()["sites"] == 3


@pytest.mark.asyncio
async def test_refresh_rejects_unexpected_shape(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(maigret, "CACHE_DIR", tmp_path)

    class Client:
        async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
            return httpx.Response(200, text='{"sites": []}', request=httpx.Request("GET", url))

    with pytest.raises(RuntimeError):
        await maigret.refresh_data(Client())  # type: ignore[arg-type]
    assert not maigret.CACHED_MAIGRET.exists()
