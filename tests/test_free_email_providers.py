# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from recce.config import Settings
from recce.core.result import Status
from recce.providers import query_registered_providers

ALL_EMAIL = {"hibp", "hunter", "emailrep", "xposedornot", "leakcheck", "proton", "github-commits"}


class Response:
    def __init__(self, status_code: int, payload=None, text: str = "") -> None:  # type: ignore[no-untyped-def]
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):  # type: ignore[no-untyped-def]
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class Client:
    def __init__(self, response: Response) -> None:
        self.response = response
        self.requests: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append((url, kwargs))
        return self.response


def _settings(**overrides) -> Settings:  # type: ignore[no-untyped-def]
    data = dict.fromkeys(
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
    )
    data.update(user_agent="recce-test", timeout=3.0, max_concurrency=2)
    data.update(overrides)
    return Settings(**data)  # type: ignore[arg-type]


async def _run(provider_id: str, response: Response, **settings):  # type: ignore[no-untyped-def]
    client = Client(response)
    hits = await query_registered_providers(
        "alice@example.com",
        "email",
        client,  # type: ignore[arg-type]
        _settings(**settings),
        skip_provider_ids=ALL_EMAIL - {provider_id},
    )
    return hits, client


@pytest.mark.asyncio
async def test_xposedornot_summarises_breaches_and_data_types() -> None:
    payload = {
        "ExposedBreaches": {
            "breaches_details": [
                {"breach": "ExampleShop", "xposed_date": "2021", "xposed_data": "Email addresses;Passwords", "password_risk": "plaintext"},
                {"breach": "ExampleForum", "xposed_date": "2019", "xposed_data": "Email addresses;Usernames", "password_risk": "hardtocrack"},
            ]
        },
        "PastesSummary": {"cnt": 0},
    }
    hits, client = await _run("xposedornot", Response(200, payload))

    assert len(hits) == 1 and hits[0].status is Status.FOUND
    summary = hits[0].summary or ""
    assert "2 breach(es): ExampleShop (2021), ExampleForum (2019)" in summary
    assert "exposed: Email addresses, Passwords, Usernames" in summary
    assert "plaintext-password" in summary
    assert client.requests[0][1]["params"] == {"email": "alice@example.com"}


@pytest.mark.asyncio
async def test_xposedornot_404_is_not_found() -> None:
    hits, _ = await _run("xposedornot", Response(404, {"Error": "Not found"}))
    assert hits[0].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_leakcheck_reports_sources_and_fields_only() -> None:
    payload = {
        "success": True,
        "found": 3,
        "fields": ["username", "password"],
        "sources": [{"name": "Stealer Logs", "date": ""}, {"name": "Example.com", "date": "2020-05"}],
    }
    hits, _ = await _run("leakcheck", Response(200, payload))

    summary = hits[0].summary or ""
    assert hits[0].status is Status.FOUND
    assert "3 record(s)" in summary
    assert "Example.com (2020-05)" in summary
    assert "exposed fields: username, password" in summary
    assert "infostealer" in summary


@pytest.mark.asyncio
async def test_leakcheck_not_found() -> None:
    hits, _ = await _run("leakcheck", Response(200, {"success": False, "error": "Not found"}))
    assert hits[0].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_proton_key_index_reports_account_age() -> None:
    text = "info:1:1\npub:abc123:22::1600000000::\nuid:alice@example.com <alice@example.com>:1600000000::\n"
    hits, client = await _run("proton", Response(200, text=text))

    assert hits[0].status is Status.FOUND
    assert "oldest key created 2020-09-13" in (hits[0].summary or "")
    assert hits[0].extra["keys"][0]["uids"] == ["alice@example.com <alice@example.com>"]
    assert client.requests[0][1]["params"] == {"op": "index", "search": "alice@example.com"}


@pytest.mark.asyncio
async def test_proton_no_keys_is_not_proton() -> None:
    hits, _ = await _run("proton", Response(200, text="info:1:0\n"))
    assert hits[0].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_github_commits_extracts_logins_names_and_repos() -> None:
    payload = {
        "total_count": 2,
        "items": [
            {
                "author": {"login": "alice-gh"},
                "commit": {"author": {"name": "Alice Example", "date": "2024-01-02T00:00:00Z"}},
                "repository": {"full_name": "alice-gh/tool"},
            },
            {
                "author": None,
                "commit": {"author": {"name": "alice", "date": "2023-05-06T00:00:00Z"}},
                "repository": {"full_name": "someone/fork"},
            },
        ],
    }
    hits, client = await _run("github-commits", Response(200, payload), github_token="tok")

    hit = hits[0]
    assert hit.status is Status.FOUND
    assert hit.extra["logins"] == ["alice-gh"]
    assert hit.extra["author_names"] == ["Alice Example", "alice"]
    assert hit.extra["repos"] == ["alice-gh/tool", "someone/fork"]
    assert "sampled commits 2023-05-06 → 2024-01-02" in (hit.summary or "")
    assert client.requests[0][1]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_github_commits_rate_limit_is_skipped() -> None:
    hits, _ = await _run("github-commits", Response(403, {"message": "API rate limit exceeded"}))
    assert hits[0].status is Status.SKIPPED
    assert "GITHUB_TOKEN" in (hits[0].summary or "")
