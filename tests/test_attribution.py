# SPDX-License-Identifier: AGPL-3.0-or-later
import io
from pathlib import Path

import pytest
from PIL import Image, ImageDraw
from typer.testing import CliRunner

from recce.cli import app
from recce.core.investigations import InvestigationStore
from recce.core.result import Hit, Report, Status
from recce.modules.attribution import attribute, avatar_hash, url_key

runner = CliRunner()


def _image(kind: str, size: int = 128, fmt: str = "PNG") -> bytes:
    img = Image.new("RGB", (size, size), "white")
    draw = ImageDraw.Draw(img)
    s = size / 128
    if kind == "circle":
        draw.ellipse((20 * s, 20 * s, 100 * s, 100 * s), fill="navy")
        draw.rectangle((50 * s, 0, 70 * s, 128 * s), fill="orange")
    elif kind == "stripes":
        for x in range(0, 128, 16):
            draw.rectangle((x * s, 0, (x + 8) * s, 128 * s), fill="black")
    elif kind == "flat":
        draw.rectangle((0, 0, size, size), fill="grey")
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


class Response:
    def __init__(self, status_code: int, content: bytes = b"") -> None:
        self.status_code = status_code
        self.content = content


class ImageClient:
    def __init__(self, images: dict[str, bytes]) -> None:
        self.images = images
        self.requests: list[str] = []

    async def get(self, url: str, **kwargs):  # type: ignore[no-untyped-def]
        self.requests.append(url)
        if url in self.images:
            return Response(200, self.images[url])
        return Response(404)


def _site(source: str, url: str) -> Hit:
    """A bare site probe: exists, no profile data."""
    return Hit(source=source, category="social", status=Status.FOUND, url=url, extra={"probe_url": url})


def _profile(source: str, url: str, **fields) -> Hit:  # type: ignore[no-untyped-def]
    extra = {"name": None, "bio": None, "location": None, "links": [], "avatar_url": None, "created_at": None}
    extra.update(fields)
    return Hit(source=source, category="identity", status=Status.FOUND, url=url, extra=extra)


def _report(*hits: Hit, query: str = "sample") -> Report:
    report = Report(query=query, query_type="username")
    for hit in hits:
        report.add(hit)
    return report


def _cluster_of(hit: Hit) -> int | None:
    return hit.extra["attribution"]["cluster"]


# --- building blocks -----------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://twitter.com/Sample", "https://x.com/sample"),
        ("https://github.com/sample/", "github.com/Sample"),
        ("https://www.reddit.com/u/sample", "https://reddit.com/user/sample"),
        ("https://news.ycombinator.com/user?id=sample", "https://news.ycombinator.com/user?id=sample"),
    ],
)
def test_url_key_treats_spellings_of_one_profile_as_equal(a: str, b: str) -> None:
    assert url_key(a) == url_key(b)


def test_url_key_keeps_different_accounts_apart() -> None:
    assert url_key("https://github.com/sample") != url_key("https://github.com/other")
    assert url_key("https://github.com/sample") != url_key("https://gitlab.com/sample")
    assert url_key(None) is None


def test_avatar_hash_survives_resizing_and_recompression() -> None:
    original = avatar_hash(_image("circle", 128))
    resized = avatar_hash(_image("circle", 460, "JPEG"))
    other = avatar_hash(_image("stripes"))

    assert original is not None and resized is not None and other is not None
    assert bin(original ^ resized).count("1") <= 6
    assert bin(original ^ other).count("1") > 20


def test_avatar_hash_ignores_flat_and_undecodable_images() -> None:
    assert avatar_hash(_image("flat")) is None
    assert avatar_hash(b"<svg xmlns='http://www.w3.org/2000/svg'/>") is None
    assert avatar_hash(b"") is None


# --- clustering ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attribute_clusters_corroborated_hits_and_leaves_the_rest() -> None:
    github_site = _site("GitHub", "https://github.com/sample")
    x_site = _site("X", "https://x.com/sample")
    pinterest = _site("Pinterest", "https://pinterest.com/sample")
    github_identity = _profile(
        "GitHub identity",
        "https://github.com/sample",
        name="Sam Example",
        location="Leeds, UK",
        avatar_url="https://avatars.example.test/gh.png",
        blog="https://sam.example.test",
        twitter="sample",
        created_at="2015-03-01T00:00:00Z",
    )
    gitlab = _profile(
        "GitLab profile",
        "https://gitlab.com/sample",
        name="Sam Example (she/her)",
        avatar_url="https://avatars.example.test/gl.jpg",
        created_at="2018-06-01T00:00:00Z",
    )
    keybase = _profile(
        "Keybase profile",
        "https://keybase.io/sample",
        name="sample",  # same as the handle: a site default, not evidence
        links=["https://github.com/sample"],
        created_at="2014-01-01T00:00:00Z",
    )
    chess = _profile(
        "Chess.com profile",
        "https://www.chess.com/member/sample",
        name="Alex Other",
        location="Paris",
        avatar_url="https://avatars.example.test/chess.png",
        created_at="2019-01-01T00:00:00Z",
    )
    report = _report(github_site, x_site, pinterest, github_identity, gitlab, keybase, chess)
    client = ImageClient(
        {
            "https://avatars.example.test/gh.png": _image("circle", 128),
            "https://avatars.example.test/gl.jpg": _image("circle", 300, "JPEG"),
            "https://avatars.example.test/chess.png": _image("stripes"),
        }
    )

    clusters = await attribute(report, client)

    assert len(clusters) == 1
    [cluster] = clusters
    # The GitHub probe and GitHub identity hit are one account.
    assert [m.source for m in cluster.members] == [
        "GitHub + GitHub identity", "X", "GitLab profile", "Keybase profile",
    ]
    assert report.clusters == clusters
    assert cluster.signals == [
        "GitHub + GitHub identity ↔ X: cross-link",
        "GitHub + GitHub identity ↔ GitLab profile: same avatar, same display name",
        "GitHub + GitHub identity ↔ Keybase profile: cross-link",
    ]
    assert [m.source for m in cluster.timeline] == [
        "Keybase profile", "GitHub + GitHub identity", "GitLab profile",
    ]
    assert 0.0 < cluster.confidence <= 1.0

    assert _cluster_of(pinterest) is None
    assert _cluster_of(chess) is None
    assert pinterest.extra["attribution"]["signals"] == ["username match only"]
    assert github_identity.extra["attribution"]["confidence"] >= 0.95
    assert any("same avatar with GitHub + GitHub identity" in s for s in gitlab.extra["attribution"]["signals"])


@pytest.mark.asyncio
async def test_one_account_seen_by_several_sources_is_not_a_cluster() -> None:
    probe = _site("GitHub (User)", "https://github.com/sample")
    profile = _profile("GitHub identity", "https://github.com/sample", name="Sam Example")
    commits = [
        Hit(source="GitHub identity", status=Status.FOUND, url="https://github.com/sample",
            extra={"name": "Sam Example", "email": f"sam{i}@example.test", "emails": []})
        for i in range(3)
    ]
    other = _site("Pinterest", "https://pinterest.com/sample")
    report = _report(probe, profile, *commits, other)

    assert await attribute(report, fetch_avatars=False) == []
    assert all(_cluster_of(h) is None for h in report.hits)


@pytest.mark.asyncio
async def test_weak_signals_alone_do_not_link() -> None:
    a = _profile("A profile", "https://gitlab.com/sample", name="Sam", location="Leeds")
    b = _profile("B profile", "https://keybase.io/sample", name="sam", location="Leeds, UK")
    c = _profile("C profile", "https://www.chess.com/member/sample", location="Earth")
    d = _profile("D profile", "https://hub.docker.com/u/sample", location="earth")

    clusters = await attribute(_report(a, b, c, d), fetch_avatars=False)

    assert clusters == []
    assert all(_cluster_of(h) is None for h in (a, b, c, d))


@pytest.mark.asyncio
async def test_shared_email_links_profiles() -> None:
    npm = _profile("npm profile", "https://www.npmjs.com/~sample", emails=["sam@example.test"])
    docker = _profile("Docker Hub profile", "https://hub.docker.com/u/sample", emails=["SAM@example.test"])

    [cluster] = await attribute(_report(npm, docker), fetch_avatars=False)

    assert cluster.signals == ["npm profile ↔ Docker Hub profile: shared email"]


@pytest.mark.asyncio
async def test_default_avatars_are_not_fetched_or_compared() -> None:
    steam = "https://avatars.example.test/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg"
    a = _profile("Steam profile", "https://steamcommunity.com/id/sample", avatar_url=steam)
    b = _profile("Mastodon profile", "https://mastodon.social/@sample", avatar_url="https://x.example.test/missing.png")
    client = ImageClient({})

    assert await attribute(_report(a, b), client) == []
    assert client.requests == []


@pytest.mark.asyncio
async def test_attribute_is_idempotent() -> None:
    a = _profile("npm profile", "https://www.npmjs.com/~sample", emails=["sam@example.test"])
    b = _profile("Docker Hub profile", "https://hub.docker.com/u/sample", emails=["sam@example.test"])
    report = _report(a, b)

    first = await attribute(report, fetch_avatars=False)
    b.extra["emails"] = []
    second = await attribute(report, fetch_avatars=False)

    assert len(first) == 1
    assert second == []
    assert _cluster_of(a) is None


# --- surfaces ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clusters_appear_in_investigation_exports(tmp_path: Path) -> None:
    a = _profile("npm profile", "https://www.npmjs.com/~sample", emails=["sam@example.test"],
                 created_at="2016-01-01T00:00:00Z")
    b = _profile("Docker Hub profile", "https://hub.docker.com/u/sample", emails=["sam@example.test"],
                 created_at="2017-01-01T00:00:00Z")
    report = _report(a, b)
    await attribute(report, fetch_avatars=False)
    report.finish()
    store = InvestigationStore(tmp_path / "recce.sqlite3")
    inv = store.create_investigation(name="Attribution")
    store.record_run(investigation_id=inv["id"], report=report, args={}, recce_version="t", wmn_cache={})

    md = store.export_markdown(inv["id"])
    assert "**Likely the same person (cluster 1, confidence 0.80):** npm profile, Docker Hub profile" in md
    assert "- npm profile ↔ Docker Hub profile: shared email" in md
    assert "- Account timeline: npm profile 2016-01-01 -> Docker Hub profile 2017-01-01" in md
    assert store.export_pdf_bytes(inv["id"]).startswith(b"%PDF")


def test_cli_prints_clusters(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def fake_username(name, client, **kwargs):  # type: ignore[no-untyped-def]
        report = _report(
            _profile("npm profile", "https://www.npmjs.com/~sample", emails=["sam@example.test"]),
            _profile("Docker Hub profile", "https://hub.docker.com/u/sample", emails=["sam@example.test"]),
            _site("Pinterest", "https://pinterest.com/sample"),
            query=name,
        )
        await attribute(report, fetch_avatars=False)
        report.finish()
        return report

    monkeypatch.setattr("recce.cli.search_username", fake_username)

    result = runner.invoke(app, ["username", "sample", "--no-providers"])

    assert result.exit_code == 0, result.output
    assert "Likely the same person" in result.output
    assert "Cluster 1" in result.output
    assert "1 other account(s) match on the username only" in result.output


def test_non_dict_attribution_is_not_a_cluster_annotation() -> None:
    from recce.core.dossier import _finding_row
    from recce.core.output import render_clusters
    from recce.modules.attribution import cluster_attribution, uncorroborated_accounts

    report = Report(query="+447700900123", query_type="phone")
    report.add(
        Hit(
            source="Ofcom numbering",
            category="carrier",
            status=Status.FOUND,
            extra={"attribution": "Contains Ofcom data"},
        )
    )

    assert cluster_attribution(report.hits[0].extra) is None
    assert cluster_attribution({"attribution": {"cluster": 1}}) == {"cluster": 1}
    assert uncorroborated_accounts(report) == 0
    render_clusters(report)  # no clusters panel, and no crash
    assert "cluster" not in _finding_row(report.hits[0].model_dump(mode="json"))
