# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recce.cli import app
from recce.config import Settings
from recce.core.investigations import InvestigationStore
from recce.core.result import Hit, PivotOrigin, Report, Status
from recce.modules import pivot as pivot_mod
from recce.modules.pivot import (
    MAX_DEPTH,
    extract_pivots,
    normalise,
    pivot_search,
    run_pivots,
    username_from_url,
)

runner = CliRunner()


def _report(query: str, query_type: str, *hits: Hit) -> Report:
    report = Report(query=query, query_type=query_type)
    for hit in hits:
        report.add(hit)
    report.finish()
    return report


def _found(source: str, **extra) -> Hit:  # type: ignore[no-untyped-def]
    return Hit(source=source, status=Status.FOUND, url=f"https://{source.lower().replace(' ', '-')}.example/x", extra=extra)


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


# --- extraction --------------------------------------------------------------


def test_normalise_rejects_unsearchable_identifiers() -> None:
    assert normalise("username", "@Sample_Handle") == "Sample_Handle"
    assert normalise("username", "has space") is None
    assert normalise("username", "") is None
    assert normalise("username", None) is None
    assert normalise("email", " Person@Example.TEST ") == "person@example.test"
    assert normalise("email", "123+sample@users.noreply.github.com") is None
    assert normalise("email", "noreply@example.test") is None
    assert normalise("email", "not-an-email") is None
    assert normalise("phone", "+441234") is None


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://twitter.com/sample_x", "sample_x"),
        ("https://x.com/sample_x/status/1", "sample_x"),
        ("https://www.linkedin.com/in/sample-person/", "sample-person"),
        ("https://reddit.com/u/sampleredditor", "sampleredditor"),
        ("https://www.reddit.com/user/sampleredditor", "sampleredditor"),
        ("https://www.tiktok.com/@sampletok", "sampletok"),
        ("https://youtube.com/@sampletube", "sampletube"),
        ("github.com/samplecoder", "samplecoder"),
        ("https://twitter.com/intent/tweet", None),
        ("https://linkedin.com/company/acme", None),
        ("https://blog.example.test/about", None),
        ("", None),
        (None, None),
    ],
)
def test_username_from_profile_url(url, expected) -> None:  # type: ignore[no-untyped-def]
    assert username_from_url(url) == expected


def test_extract_pivots_reads_every_pivot_field_from_found_hits_only() -> None:
    report = _report(
        "samplecoder",
        "username",
        _found("GitHub identity", usernames=["sample_x"], emails=["sam@example.test"]),
        _found("GitHub identity", emails=["SAM@example.test", "dev@example.test"]),
        _found(
            "Gravatar",
            accounts=[
                "https://twitter.com/sample_x",
                "https://www.linkedin.com/in/sample-person",
                "https://blog.example.test/",
            ],
        ),
        _found("Username pivot", username="sam.local"),
        _found("Self", usernames=["SampleCoder"]),
        Hit(source="Missed", status=Status.NOT_FOUND, extra={"usernames": ["ghost"]}),
        Hit(source="Broken", status=Status.ERROR, extra={"emails": ["ghost@example.test"]}),
    )

    pivots = extract_pivots(report)

    assert [(p.kind, p.value) for p in pivots] == [
        ("username", "sample_x"),
        ("email", "sam@example.test"),
        ("email", "dev@example.test"),
        ("username", "sample-person"),
        ("username", "sam.local"),
    ]
    first = pivots[0]
    assert first.origin == PivotOrigin(
        from_query="samplecoder",
        from_type="username",
        source="GitHub identity",
        field="usernames",
        hit_url="https://github-identity.example/x",
        depth=1,
    )
    linkedin = pivots[3]
    assert linkedin.origin.field == "accounts"
    assert linkedin.origin.hit_url == "https://www.linkedin.com/in/sample-person"
    assert first.command == "recce username sample_x"


# --- recursion ---------------------------------------------------------------


class FakeSearch:
    """Canned reports per identifier; records every search it is asked to run."""

    def __init__(self, graph: dict[tuple[str, str], list[Hit]]) -> None:
        self.graph = graph
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, kind: str, value: str) -> Report:
        self.calls.append((kind, value))
        return _report(value, kind, *self.graph.get((kind, value), []))


def _chain_graph() -> dict[tuple[str, str], list[Hit]]:
    # email root → username b → email c → username d → (back to the root email)
    return {
        ("username", "user-b"): [_found("GitHub identity", emails=["c@example.test"])],
        ("email", "c@example.test"): [_found("GitHub commits", usernames=["user-d"])],
        ("username", "user-d"): [_found("GitHub identity", emails=["root@example.test"])],
    }


def _root() -> Report:
    return _report("root@example.test", "email", _found("Username pivot", username="user-b"))


@pytest.mark.asyncio
async def test_run_pivots_depth_one_runs_first_level_and_suggests_the_next() -> None:
    search = FakeSearch(_chain_graph())

    run = await run_pivots(_root(), search, depth=1)

    assert search.calls == [("username", "user-b")]
    assert [r.query for r in run.reports] == ["user-b"]
    assert run.reports[0].pivot is not None
    assert run.reports[0].pivot.from_query == "root@example.test"
    assert [(p.kind, p.value, p.origin.depth) for p in run.pending] == [("email", "c@example.test", 2)]


@pytest.mark.asyncio
async def test_run_pivots_follows_the_chain_and_never_revisits() -> None:
    search = FakeSearch(_chain_graph())

    run = await run_pivots(_root(), search, depth=3)

    assert search.calls == [
        ("username", "user-b"),
        ("email", "c@example.test"),
        ("username", "user-d"),
    ]
    # user-d names the root email; it was already searched, so nothing is pending.
    assert run.pending == []
    assert run.chain() == [
        {
            "from_type": "email",
            "from_query": "root@example.test",
            "to_type": "username",
            "to_query": "user-b",
            "source": "Username pivot",
            "field": "username",
            "hit_url": "https://username-pivot.example/x",
            "depth": 1,
        },
        {
            "from_type": "username",
            "from_query": "user-b",
            "to_type": "email",
            "to_query": "c@example.test",
            "source": "GitHub identity",
            "field": "emails",
            "hit_url": "https://github-identity.example/x",
            "depth": 2,
        },
        {
            "from_type": "email",
            "from_query": "c@example.test",
            "to_type": "username",
            "to_query": "user-d",
            "source": "GitHub commits",
            "field": "usernames",
            "hit_url": "https://github-commits.example/x",
            "depth": 3,
        },
    ]


@pytest.mark.asyncio
async def test_run_pivots_caps_depth_and_per_level_fanout() -> None:
    hits = [_found("GitHub identity", usernames=[f"user-{i}" for i in range(5)])]
    search = FakeSearch({("username", f"user-{i}"): [] for i in range(5)})

    run = await run_pivots(_report("root", "username", *hits), search, depth=99, max_per_level=2)

    assert MAX_DEPTH == 3
    assert search.calls == [("username", "user-0"), ("username", "user-1")]
    assert [p.value for p in run.pending] == ["user-2", "user-3", "user-4"]


@pytest.mark.asyncio
async def test_run_pivots_skips_identifiers_already_searched() -> None:
    search = FakeSearch(_chain_graph())

    run = await run_pivots(_root(), search, depth=2, seen={("username", "USER-B".lower())})

    assert search.calls == []
    assert run.reports == []


@pytest.mark.asyncio
async def test_pivot_search_is_passive_only(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple] = []

    async def fake_email(addr, client, settings, *, skip_provider_ids=None):  # type: ignore[no-untyped-def]
        calls.append(("email", addr, skip_provider_ids))
        return Report(query=addr, query_type="email")

    async def fake_username(name, client, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(("username", name, kwargs["skip_provider_ids"], kwargs["include_nsfw"]))
        return Report(query=name, query_type="username")

    async def forbidden(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("pivots must never run deep email probes")

    monkeypatch.setattr("recce.modules.email.search_email", fake_email)
    monkeypatch.setattr("recce.modules.username.search_username", fake_username)
    monkeypatch.setattr("recce.modules.email_deep.deep_email_probes", forbidden)

    search = pivot_search(object(), _settings(), skip_provider_ids={"hibp"}, include_nsfw=False)
    await search("email", "c@example.test")
    await search("username", "user-b")
    with pytest.raises(ValueError):
        await search("domain", "example.test")

    assert calls == [
        ("email", "c@example.test", {"hibp"}),
        ("username", "user-b", {"hibp"}, False),
    ]


def test_pivot_module_never_imports_deep_or_bruteforce() -> None:
    source = Path(pivot_mod.__file__).read_text()
    assert "deep_email_probes" not in source.replace("never `deep_email_probes`", "")
    assert "search_domain" not in source


# --- CLI ---------------------------------------------------------------------


@pytest.fixture
def fake_searches(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    """Route every CLI search through the fake graph; count deep probes."""
    monkeypatch.setenv("RECCE_DATA_DIR", str(tmp_path))
    graph = _chain_graph()
    graph[("email", "root@example.test")] = [_found("Username pivot", username="user-b")]
    search = FakeSearch(graph)
    deep_calls: list[str] = []

    async def fake_email(addr, client, settings, *, skip_provider_ids=None):  # type: ignore[no-untyped-def]
        return await search("email", addr)

    async def fake_username(name, client, **kwargs):  # type: ignore[no-untyped-def]
        return await search("username", name)

    async def fake_deep(addr, **kwargs):  # type: ignore[no-untyped-def]
        deep_calls.append(addr)
        return []

    for target in ("recce.cli", "recce.modules.email"):
        monkeypatch.setattr(f"{target}.search_email", fake_email)
    for target in ("recce.cli", "recce.modules.username"):
        monkeypatch.setattr(f"{target}.search_username", fake_username)
    monkeypatch.setattr("recce.cli.deep_email_probes", fake_deep)
    monkeypatch.setattr("recce.modules.email_deep.deep_email_probes", fake_deep)
    return search, deep_calls


def test_cli_without_recursive_suggests_next_commands(fake_searches) -> None:  # type: ignore[no-untyped-def]
    search, _ = fake_searches

    result = runner.invoke(app, ["email", "root@example.test", "--no-providers"])

    assert result.exit_code == 0, result.output
    assert "recce username user-b" in result.output
    assert search.calls == [("email", "root@example.test")]


def test_cli_recursive_deep_root_keeps_deep_off_for_pivots(fake_searches) -> None:  # type: ignore[no-untyped-def]
    search, deep_calls = fake_searches

    result = runner.invoke(
        app,
        [
            "email", "root@example.test", "--deep", "--i-own-these-emails",
            "--recursive", "--depth", "2", "--no-providers",
        ],
    )

    assert result.exit_code == 0, result.output
    assert search.calls == [
        ("email", "root@example.test"),
        ("username", "user-b"),
        ("email", "c@example.test"),
    ]
    assert deep_calls == ["root@example.test"]
    assert "Pivot chain" in result.output
    assert "recce username user-d" in result.output  # discovered at depth 3, not run


def test_cli_depth_is_capped(fake_searches) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(app, ["username", "user-b", "--recursive", "--depth", "4"])

    assert result.exit_code == 2


def test_cli_recursive_records_chain_to_case_and_exports_it(fake_searches) -> None:  # type: ignore[no-untyped-def]
    store = InvestigationStore()
    inv = store.create_investigation(name="Pivot test")

    result = runner.invoke(
        app,
        [
            "username", "user-b", "--recursive", "--depth", "2",
            "--no-providers", "--case", inv["id"],
        ],
    )
    assert result.exit_code == 0, result.output

    runs = store.list_runs(inv["id"])
    assert {(r["query_type"], r["query"]) for r in runs} == {
        ("username", "user-b"),
        ("email", "c@example.test"),
        ("username", "user-d"),
    }
    pivot_runs = [r for r in runs if r["report"].get("pivot")]
    assert all(r["args"]["deep"] is False for r in pivot_runs)
    events = [e for e in store.list_audit_events(inv["id"]) if e["event_type"] == "pivot.run"]
    assert {e["payload"]["to_query"] for e in events} == {"c@example.test", "user-d"}

    exported = runner.invoke(app, ["investigations", "export", inv["id"]])
    assert exported.exit_code == 0, exported.output
    md = exported.output
    assert "## Pivot chain" in md
    assert "username user-b -> email c@example.test (via GitHub identity, emails" in md
    assert "email c@example.test -> username user-d (via GitHub commits, usernames" in md
    assert "- Discovered via: GitHub identity hit (emails) in the username search for user-b" in md

    payload = store.export_investigation(inv["id"])
    assert [(e["from_query"], e["to_query"]) for e in payload["pivot_chain"]] == [
        ("user-b", "c@example.test"),
        ("c@example.test", "user-d"),
    ]
    redacted = store.export_markdown(inv["id"], redacted=True)
    assert "c@example.test" not in redacted


def test_cli_rejects_unknown_case(fake_searches) -> None:  # type: ignore[no-untyped-def]
    search, _ = fake_searches

    result = runner.invoke(app, ["username", "user-b", "--case", "nope"])

    assert result.exit_code == 2
    assert search.calls == []


# --- providers carry pivot material ------------------------------------------


def test_github_profile_email_is_a_pivot() -> None:
    from recce.providers.github_identity import GitHubIdentityProvider

    hit = GitHubIdentityProvider()._profile_hit(
        "samplecoder",
        {"email": "sam@example.test", "twitter_username": "sample_x", "html_url": "https://github.com/samplecoder"},
        5,
    )
    pivots = extract_pivots(_report("samplecoder", "username", hit))

    assert [(p.kind, p.value) for p in pivots] == [("username", "sample_x"), ("email", "sam@example.test")]


def test_describe_origin_accepts_model_and_dict() -> None:
    from recce.modules.pivot import describe_origin

    origin = PivotOrigin(
        from_query="root@example.test", from_type="email", source="Username pivot", field="username"
    )
    expected = "Username pivot hit (username) in the email search for root@example.test"
    assert describe_origin(origin) == expected
    assert describe_origin(origin.model_dump()) == expected
