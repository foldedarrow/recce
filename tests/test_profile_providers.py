# SPDX-License-Identifier: AGPL-3.0-or-later
import json

import pytest

from recce.config import Settings
from recce.core.result import Status
from recce.providers import PROVIDERS, query_registered_providers
from recce.providers.profiles import PROFILE_PROVIDERS


class Response:
    def __init__(self, status_code: int, payload=None, text: str | None = None) -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)

    def json(self):  # type: ignore[no-untyped-def]
        if self._payload is None and self.text != "null":
            raise ValueError("not json")
        return self._payload


class RoutingClient:
    def __init__(self, routes: dict[str, Response]) -> None:
        self.routes = routes
        self.requests: list[str] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append(url)
        return self.routes.get(url, Response(404, {"error": "not found"}))


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


async def _run(provider_id: str, username: str, routes: dict[str, Response]):  # type: ignore[no-untyped-def]
    client = RoutingClient(routes)
    others = {p.id for p in PROVIDERS if p.id != provider_id}
    hits = await query_registered_providers(username, "username", client, _settings(), skip_provider_ids=others)  # type: ignore[arg-type]
    return hits, client


def test_profile_providers_are_registered_for_usernames() -> None:
    registered = {p.id for p in PROVIDERS}
    for provider in PROFILE_PROVIDERS:
        assert provider.id in registered
        assert provider.enriches == ("username",)
        assert provider.tier == "free"


@pytest.mark.asyncio
async def test_gitlab_profile() -> None:
    url = "https://gitlab.com/api/v4/users?username=quill"
    payload = [
        {
            "username": "quill",
            "name": "Quill Testerson",
            "public_email": "quill@example.org",
            "avatar_url": "https://gitlab.example/avatar.png",
            "web_url": "https://gitlab.com/quill",
            "state": "active",
        }
    ]
    [hit], _ = await _run("gitlab-profile", "quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.extra["name"] == "Quill Testerson"
    assert hit.extra["emails"] == ["quill@example.org"]
    assert hit.url == "https://gitlab.com/quill"

    [miss], _ = await _run("gitlab-profile", "quill", {url: Response(200, [])})
    assert miss.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_mastodon_profile_extracts_field_links_but_not_mentions() -> None:
    url = "https://mastodon.social/api/v1/accounts/lookup?acct=quill"
    note = (
        '<p>Writes code. Mail me at quill@example.org. Friend of '
        '<span class="h-card"><a href="https://mastodon.social/@pal" class="u-url mention">@<span>pal</span></a></span> '
        '<a href="https://mastodon.social/tags/rust" class="mention hashtag">#<span>rust</span></a></p>'
    )
    field = (
        '<a href="https://github.com/quill-gh" rel="me"><span class="invisible">https://</span>'
        '<span class="">github.com/quill-gh</span></a>'
    )
    payload = {
        "username": "quill",
        "display_name": "Quill T",
        "note": note,
        "url": "https://mastodon.social/@quill",
        "avatar": "https://mastodon.social/avatars/original/missing.png",
        "created_at": "2022-11-05T00:00:00.000Z",
        "fields": [
            {"name": "GitHub", "value": field, "verified_at": "2023-01-01T00:00:00+00:00"},
            {"name": "Site", "value": '<a href="https://quill.example">quill.example</a>', "verified_at": None},
        ],
        "followers_count": 12,
        "statuses_count": 340,
    }
    [hit], _ = await _run("mastodon-profile", "quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.extra["links"] == ["https://github.com/quill-gh", "https://quill.example"]
    assert hit.extra["verified_links"] == ["https://github.com/quill-gh"]
    assert hit.extra["usernames"] == ["quill-gh"]
    assert hit.extra["emails"] == ["quill@example.org"]
    assert hit.extra["avatar_url"] is None  # default "missing" avatar
    assert "Friend of @pal #rust" in hit.extra["bio"]
    assert "joined 2022-11-05" in (hit.summary or "")

    [miss], _ = await _run("mastodon-profile", "quill", {})
    assert miss.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_bluesky_profile_uses_bsky_social_handle_and_skips_invalid_names() -> None:
    url = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=quill.bsky.social"
    payload = {
        "did": "did:plc:fake123",
        "handle": "quill.bsky.social",
        "displayName": "Quill",
        "description": "Builder. https://quill.example · contact: hi@quill.example",
        "avatar": "https://cdn.example/avatar.jpg",
        "createdAt": "2023-04-01T10:00:00.000Z",
        "followersCount": 3,
        "postsCount": 9,
    }
    [hit], _ = await _run("bluesky-profile", "Quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.url == "https://bsky.app/profile/quill.bsky.social"
    assert hit.extra["links"] == ["https://quill.example"]
    assert hit.extra["emails"] == ["hi@quill.example"]
    assert hit.extra["usernames"] == []  # bio links are links, not claimed handles

    missing = Response(400, {"error": "InvalidRequest", "message": "Profile not found"})
    [miss], _ = await _run("bluesky-profile", "quill", {url: missing})
    assert miss.status is Status.NOT_FOUND

    hits, client = await _run("bluesky-profile", "quill_x", {})
    assert hits == [] and client.requests == []


@pytest.mark.asyncio
async def test_keybase_profile_keeps_only_live_proofs() -> None:
    url = (
        "https://keybase.io/_/api/1.0/user/lookup.json"
        "?usernames=quill&fields=basics,profile,proofs_summary,pictures"
    )
    payload = {
        "status": {"code": 0, "name": "OK"},
        "them": [
            {
                "basics": {"username": "quill", "username_cased": "Quill", "ctime": 1500000000},
                "profile": {"full_name": "Quill Testerson", "location": "Leeds", "bio": "hi"},
                "pictures": {"primary": {"url": "https://keybase.example/pic.jpg"}},
                "proofs_summary": {
                    "all": [
                        {"proof_type": "twitter", "nametag": "quill_tw", "state": 1, "service_url": "https://twitter.com/quill_tw"},
                        {"proof_type": "github", "nametag": "quill-gh", "state": 1, "service_url": "https://github.com/quill-gh"},
                        {"proof_type": "dns", "nametag": "quill.example", "state": 1, "service_url": "dns://quill.example"},
                        {"proof_type": "reddit", "nametag": "old_quill", "state": 2, "service_url": "https://reddit.com/user/old_quill"},
                    ]
                },
            }
        ],
    }
    [hit], _ = await _run("keybase-profile", "Quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.url == "https://keybase.io/Quill"
    assert hit.extra["usernames"] == ["quill_tw", "quill-gh"]  # domain + broken proofs excluded
    assert hit.extra["proofs"][3] == {"type": "reddit", "name": "old_quill", "url": "https://reddit.com/user/old_quill", "ok": False}
    assert hit.extra["created_at"] == "2017-07-14T02:40:00Z"
    assert hit.extra["location"] == "Leeds"

    bad = Response(200, {"status": {"code": 100, "name": "INPUT_ERROR", "desc": "bad list value"}})
    [miss], _ = await _run("keybase-profile", "quill", {url: bad})
    assert miss.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_hackernews_profile_null_is_not_found() -> None:
    url = "https://hacker-news.firebaseio.com/v0/user/quill.json"
    about = 'Email: quill@example.org<p><a href="https:&#x2F;&#x2F;quill.example" rel="nofollow">https:&#x2F;&#x2F;quill.example</a>'
    payload = {"id": "quill", "created": 1300000000, "karma": 42, "about": about, "submitted": [1, 2, 3]}
    [hit], _ = await _run("hackernews-profile", "quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.extra["emails"] == ["quill@example.org"]
    assert hit.extra["links"] == ["https://quill.example"]
    assert hit.extra["karma"] == 42 and hit.extra["submissions"] == 3

    [miss], _ = await _run("hackernews-profile", "quill", {url: Response(200, None, text="null")})
    assert miss.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_chesscom_profile_streaming_handles() -> None:
    url = "https://api.chess.com/pub/player/quill"
    payload = {
        "username": "quill",
        "name": "Quill Testerson",
        "url": "https://www.chess.com/member/Quill",
        "country": "https://api.chess.com/pub/country/GB",
        "location": "Leeds",
        "joined": 1600000000,
        "followers": 7,
        "status": "basic",
        "twitch_url": "https://twitch.tv/quilltv",
        "streaming_platforms": [{"type": "twitch", "channel_url": "https://twitch.tv/quilltv"}],
    }
    [hit], _ = await _run("chesscom-profile", "Quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.extra["links"] == ["https://twitch.tv/quilltv"]
    assert hit.extra["usernames"] == ["quilltv"]
    assert hit.extra["country"] == "GB"


@pytest.mark.asyncio
async def test_dockerhub_profile_github_website_becomes_username() -> None:
    url = "https://hub.docker.com/v2/users/quill/"
    payload = {
        "username": "quill",
        "full_name": "Quill Testerson",
        "location": "",
        "company": "Example Ltd",
        "profile_url": "https://github.com/quill-gh",
        "date_joined": "2015-01-02T03:04:05Z",
        "gravatar_url": "",
        "type": "User",
    }
    [hit], _ = await _run("dockerhub-profile", "quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.extra["usernames"] == ["quill-gh"]
    assert hit.extra["company"] == "Example Ltd"
    assert hit.extra["location"] is None and hit.extra["avatar_url"] is None


@pytest.mark.asyncio
async def test_npm_profile_needs_exact_maintainer_match() -> None:
    url = "https://registry.npmjs.org/-/v1/search?text=maintainer:quill&size=20"

    def pkg(name: str, maintainer: str, email: str) -> dict:
        person = {"username": maintainer, "email": email}
        return {"package": {"name": name, "publisher": person, "maintainers": [person]}}

    payload = {"total": 2, "objects": [pkg("left-pad-ish", "quill", "quill@example.org"), pkg("other", "quillish", "q@example.net")]}
    [hit], _ = await _run("npm-profile", "quill", {url: Response(200, payload)})
    assert hit.status is Status.FOUND
    assert hit.extra["emails"] == ["quill@example.org"]
    assert hit.extra["sample_packages"] == ["left-pad-ish"]

    fuzzy = {"total": 1, "objects": [pkg("other", "quillish", "q@example.net")]}
    [miss], _ = await _run("npm-profile", "quill", {url: Response(200, fuzzy)})
    assert miss.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_steam_profile_xml() -> None:
    url = "https://steamcommunity.com/id/quill/?xml=1"
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><profile>'
        "<steamID64>76561190000000001</steamID64><steamID><![CDATA[QuillGamer]]></steamID>"
        "<privacyState>public</privacyState><vacBanned>0</vacBanned>"
        "<avatarFull><![CDATA[https://avatars.example/full.jpg]]></avatarFull>"
        "<customURL><![CDATA[quill]]></customURL><memberSince>March 4, 2012</memberSince>"
        "<location><![CDATA[Leeds, England, United Kingdom]]></location><realname><![CDATA[Quill T]]></realname>"
        '<summary><![CDATA[gg <a class="bb_link" href="https://quill.example">site</a>]]></summary></profile>'
    )
    [hit], _ = await _run("steam-profile", "quill", {url: Response(200, text=xml)})
    assert hit.status is Status.FOUND
    assert hit.extra["name"] == "Quill T"
    assert hit.extra["created_at"] == "2012-03-04"
    assert hit.extra["links"] == ["https://quill.example"]
    assert hit.extra["persona"] == "QuillGamer"
    assert "VAC banned" not in (hit.summary or "")

    error = '<?xml version="1.0"?><response><error><![CDATA[The specified profile could not be found.]]></error></response>'
    [miss], _ = await _run("steam-profile", "quill", {url: Response(200, text=error)})
    assert miss.status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_profile_provider_error_states() -> None:
    url = "https://api.chess.com/pub/player/quill"
    [limited], _ = await _run("chesscom-profile", "quill", {url: Response(429, {})})
    assert limited.status is Status.SKIPPED
    [blocked], _ = await _run("chesscom-profile", "quill", {url: Response(403, None, text="<html>")})
    assert blocked.status is Status.UNKNOWN and blocked.summary == "HTTP 403"
    [garbled], _ = await _run("chesscom-profile", "quill", {url: Response(200, None, text="<html>")})
    assert garbled.status is Status.UNKNOWN and garbled.summary == "unexpected response"


@pytest.mark.asyncio
async def test_profile_providers_ignore_other_target_types() -> None:
    client = RoutingClient({})
    others = {p.id for p in PROVIDERS if p.id not in {pp.id for pp in PROFILE_PROVIDERS}}
    hits = await query_registered_providers("a@example.org", "email", client, _settings(), skip_provider_ids=others)  # type: ignore[arg-type]
    assert hits == [] and client.requests == []
