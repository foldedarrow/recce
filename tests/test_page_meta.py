# SPDX-License-Identifier: AGPL-3.0-or-later
import httpx
import pytest

from recce.core.result import Hit, Report, Status
from recce.modules import username as username_mod
from recce.modules.attribution import attribute
from recce.modules.page_meta import apply_page_meta, display_name, extract_page_meta

PAGE = """<!doctype html><html><head>
<title>Sam Example (@sample) | Example Social</title>
<meta property="og:title" content="Sam Example (@sample) &middot; Example Social">
<meta property="og:image" content="/avatars/sample.png">
<meta name="description" content="Builds things in Leeds.">
<link rel="me" href="https://github.com/samplecoder">
</head><body><a rel="me nofollow" href="https://mastodon.example.test/@sample">m</a></body></html>"""


def test_extract_page_meta_reads_og_title_image_and_rel_me() -> None:
    meta = extract_page_meta(PAGE, "https://social.example.test/sample")

    assert meta == {
        "title": "Sam Example (@sample) · Example Social",
        "image": "https://social.example.test/avatars/sample.png",
        "description": "Builds things in Leeds.",
        "me_links": ["https://github.com/samplecoder", "https://mastodon.example.test/@sample"],
    }
    assert extract_page_meta('{"json": true}') == {}


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("Sam Example (@sample) · Example Social", "Sam Example"),
        ("Sam Example - Example Social", "Sam Example"),
        ("Example Social", None),
        ("sample", None),
        ("Log in • Example Social", None),
        ("Page not found · Example Social", None),
        ("◆", None),
        ("", None),
    ],
)
def test_display_name_strips_site_and_handle(title: str, expected: str | None) -> None:
    assert display_name(title, "Example Social", "sample") == expected


def test_apply_page_meta_drops_what_the_canary_page_shares() -> None:
    hit = Hit(source="Example Social", status=Status.FOUND, url="https://social.example.test/sample",
              extra={"page_meta": extract_page_meta(PAGE, "https://social.example.test/sample")})
    canary = {"image": "https://social.example.test/avatars/sample.png", "description": "Builds things in Leeds."}

    apply_page_meta(hit, "sample", canary)

    assert "page_meta" not in hit.extra
    assert hit.extra["name"] == "Sam Example"
    assert hit.extra["avatar_url"] is None  # site-wide image
    assert hit.extra["bio"] is None
    assert hit.extra["usernames"] == ["samplecoder"]  # only known profile hosts become handles
    assert hit.extra["metadata_source"] == "page meta tags"


def test_apply_page_meta_keeps_api_fields() -> None:
    hit = Hit(source="X", status=Status.FOUND, extra={"name": "From API", "page_meta": {"title": "Other Name - X"}})
    apply_page_meta(hit, "sample")
    assert hit.extra["name"] == "From API"


@pytest.mark.asyncio
async def test_username_search_enriches_found_hits_from_their_pages(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sites = [
        {"name": "Example Social", "category": "social", "url": "https://social.example.test/{u}",
         "method": "status", "found": [200], "missing": [404]},
    ]
    monkeypatch.setattr(username_mod, "_load_sites", lambda include_nsfw=False: sites)
    canary_page = '<html><head><meta property="og:image" content="/avatars/sample.png"><title>Example Social</title></head></html>'

    class Client:
        proxy = None

        async def request_detailed(self, method, url, **kwargs):  # type: ignore[no-untyped-def]
            body = PAGE if url.endswith("/sample") else canary_page
            return httpx.Response(200 if url.endswith("/sample") else 404, text=body,
                                  request=httpx.Request(method, url)), None

    report = await username_mod.search_username(
        "sample", Client(), show_progress=False, impersonate=False, per_domain_rate=0,
        flagged_sites="off", attribute_hits=False,
    )

    [hit] = report.hits
    assert hit.status is Status.FOUND
    assert hit.extra["name"] == "Sam Example"
    assert hit.extra["avatar_url"] is None  # the canary's page has the same image
    assert hit.extra["links"][0] == "https://github.com/samplecoder"
    assert "page_meta" not in hit.extra


# --- attribution rules learned from live runs ------------------------------------


def _hit(source: str, url: str, **extra) -> Hit:  # type: ignore[no-untyped-def]
    return Hit(source=source, status=Status.FOUND, url=url,
               extra={"links": [], "avatar_url": None, **extra})


@pytest.mark.asyncio
async def test_names_containing_the_handle_are_templates_not_evidence() -> None:
    report = Report(query="sample", query_type="username")
    for host, name in (("a.test", "sample's profile"), ("b.test", "Profile: sample"),
                       ("c.test", "Profil użytkownika sample"), ("d.test", "Profil użytkownika sample")):
        report.add(_hit(host, f"https://{host}/sample", name=name))

    assert await attribute(report, fetch_avatars=False) == []


@pytest.mark.asyncio
async def test_two_definitions_of_one_site_do_not_corroborate() -> None:
    report = Report(query="sample", query_type="username")
    report.add(_hit("Genius (Artist)", "https://genius.com/artists/sample", name="Sam Example"))
    report.add(_hit("Genius (User)", "https://genius.com/sample", name="Sam Example"))
    report.add(_hit("Other", "https://other.test/sample", name="Sam Example"))

    [cluster] = await attribute(report, fetch_avatars=False)

    # Each Genius hit links to Other on its own; they never link to each other.
    assert cluster.signals == [
        "Genius (Artist) ↔ Other: same display name",
        "Genius (User) ↔ Other: same display name",
    ]
