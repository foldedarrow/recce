# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from recce.config import Settings
from recce.core.result import Status
from recce.providers import query_registered_providers


class Response:
    def __init__(self, status_code: int, payload) -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload

    def json(self):  # type: ignore[no-untyped-def]
        return self._payload


class RoutingClient:
    def __init__(self, routes: dict[str, Response]) -> None:
        self.routes = routes
        self.requests: list[str] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append(url)
        return self.routes.get(url, Response(404, {"message": "Not Found"}))


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


def _commit(name: str, email: str) -> dict:
    person = {"name": name, "email": email, "date": "2025-01-01T00:00:00Z"}
    return {"commit": {"author": person, "committer": {"name": "GitHub", "email": "noreply@github.com"}}}


@pytest.mark.asyncio
async def test_github_identity_extracts_profile_and_commit_identities() -> None:
    api = "https://api.github.com"
    client = RoutingClient(
        {
            f"{api}/users/alice": Response(
                200,
                {
                    "login": "alice",
                    "type": "User",
                    "name": "Alice Example",
                    "location": "Leeds",
                    "twitter_username": "alice_x",
                    "html_url": "https://github.com/alice",
                    "created_at": "2020-02-03T00:00:00Z",
                    "public_repos": 2,
                    "followers": 5,
                },
            ),
            f"{api}/users/alice/repos": Response(200, [{"name": "tool", "fork": False}, {"name": "forked", "fork": True}]),
            f"{api}/repos/alice/tool/commits": Response(
                200,
                [
                    _commit("Alice Example", "alice@example.org"),
                    _commit("Alice Example", "alice@example.org"),
                    _commit("alice", "1234+alice@users.noreply.github.com"),
                    _commit("Alice", "alice@Alices-MacBook.local"),
                ],
            ),
        }
    )

    hits = await query_registered_providers("alice", "username", client, _settings())  # type: ignore[arg-type]

    profile, *identities = hits
    assert profile.status is Status.FOUND
    assert "name: Alice Example" in (profile.summary or "") and "joined 2020-02-03" in (profile.summary or "")
    assert profile.extra["usernames"] == ["alice_x"]
    by_email = {hit.extra["email"]: hit for hit in identities}
    assert by_email["alice@example.org"].extra["commits"] == 2
    assert by_email["alice@example.org"].extra["emails"] == ["alice@example.org"]
    assert by_email["1234+alice@users.noreply.github.com"].extra["email_kind"] == "GitHub noreply alias"
    assert by_email["alice@alices-macbook.local"].extra["email_kind"].startswith("machine hostname")
    # Forks are skipped; GitHub's own committer identity is ignored.
    assert f"{api}/repos/alice/forked/commits" not in client.requests
    assert "noreply@github.com" not in by_email


@pytest.mark.asyncio
async def test_github_identity_missing_user() -> None:
    hits = await query_registered_providers("nobody", "username", RoutingClient({}), _settings())  # type: ignore[arg-type]
    assert [hit.status for hit in hits] == [Status.NOT_FOUND]
