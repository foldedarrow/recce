# SPDX-License-Identifier: AGPL-3.0-or-later
"""Profile metadata from a site probe's HTML: OpenGraph/Twitter card tags,
<title>, and rel="me" links.

Most username hits are bare site probes: they prove a profile URL exists but
carry no name, avatar or links, so attribution has nothing to compare. The
probe already downloaded the page, and many profile pages describe their
owner in meta tags. `apply_page_meta` turns those into the same `extra`
fields the profile APIs use (`name`, `avatar_url`, `bio`, `links`).

Site-wide boilerplate (a generic title or logo on every page) is filtered by
comparing with the page the made-up canary username got: anything the two
share describes the site, not the person.
"""

from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from .pivot import username_from_url

MAX_HTML = 300_000
_SEPARATORS = re.compile(r"\s+(?:[|•·—–-]|on)\s+")
_GENERIC_TITLES = (
    "log in", "login", "sign in", "sign up", "page not found", "not found", "404",
    "access denied", "just a moment", "attention required", "error", "home",
)
_TAGS = {
    "og:title": "title",
    "twitter:title": "title",
    "og:image": "image",
    "og:image:url": "image",
    "twitter:image": "image",
    "twitter:image:src": "image",
    "og:description": "description",
    "twitter:description": "description",
    "description": "description",
    "profile:username": "handle",
}


class _HeadParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.title = ""
        self.me_links: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            key = (a.get("property") or a.get("name") or "").lower()
            field = _TAGS.get(key)
            if field and a.get("content") and field not in self.meta:
                self.meta[field] = a["content"].strip()
        elif tag in ("link", "a") and "me" in a.get("rel", "").lower().split() and a.get("href"):
            self.me_links.append(a["href"].strip())
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 300:
            self.title += data


def extract_page_meta(html: str, base_url: str = "") -> dict[str, Any]:
    """Raw metadata from an HTML page; empty if it isn't HTML."""
    if not html or "<" not in html[:2000]:
        return {}
    parser = _HeadParser()
    try:
        parser.feed(html[:MAX_HTML])
    except Exception:
        return {}
    meta = dict(parser.meta)
    title = " ".join(unescape(parser.title).split())
    if title and "title" not in meta:
        meta["title"] = title
    if "image" in meta and base_url:
        meta["image"] = urljoin(base_url, meta["image"])
    links = [urljoin(base_url, href) if base_url else href for href in parser.me_links]
    if links:
        meta["me_links"] = list(dict.fromkeys(links))[:20]
    return meta


def display_name(title: str | None, site_name: str, username: str) -> str | None:
    """The person's name from a page title like "Jane Doe (@jdoe) · Site"."""
    if not title:
        return None
    first = _SEPARATORS.split(title.strip(), maxsplit=1)[0]
    first = re.sub(r"\(@?[^)]*\)|@\S+", " ", first)
    name = " ".join(first.split()).strip(" ,'\"")
    lowered = name.lower()
    if not name or len(name) > 80 or not any(ch.isalnum() for ch in name):
        return None
    if lowered in {site_name.lower(), username.lower()} or any(g == lowered or lowered.startswith(g + " ") for g in _GENERIC_TITLES):
        return None
    if site_name.lower() in lowered and username.lower() not in lowered:
        return None  # a site tagline, not a person
    return name


def apply_page_meta(hit: Any, username: str, canary_meta: dict[str, Any] | None = None) -> None:
    """Move `extra["page_meta"]` into profile fields, dropping site boilerplate."""
    meta = hit.extra.pop("page_meta", None) or {}
    if not meta:
        return
    canary_meta = canary_meta or {}
    shared = {k for k, v in meta.items() if canary_meta.get(k) == v}

    def keep(key: str) -> Any:
        return None if key in shared else meta.get(key)

    title = keep("title")
    name = display_name(title, hit.source, username)
    image = keep("image")
    bio = keep("description")
    links = [] if "me_links" in shared else list(meta.get("me_links") or [])
    if not any((name, image, bio, links)):
        return
    fields: dict[str, Any] = {
        "name": name,
        "avatar_url": image,
        "bio": bio[:500] if bio else None,
        "links": links,
        "metadata_source": "page meta tags",
    }
    handles = [h for h in (username_from_url(link) for link in links) if h]
    if handles:
        fields["usernames"] = sorted(set(handles), key=handles.index)
    for key, value in fields.items():
        hit.extra.setdefault(key, value)
