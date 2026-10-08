# SPDX-License-Identifier: AGPL-3.0-or-later
"""Attribution confidence: which username hits look like the same person.

A username existing on eight sites does not mean one person owns all eight.
This module compares the FOUND hits of a report pairwise and links two hits
when their public data corroborates each other:

- same profile — two hits for one account (a site probe and its profile API);
- cross-link — one profile links to the other (website field, Keybase proof);
- shared email — both profiles expose the same email;
- same avatar — perceptual hash (dHash) of the avatar images matches;
- same display name — normalised, and not just the username itself (a
  one-word name counts for less);
- same location — weak, only adds to other signals.

Linked hits are grouped into clusters ("these 5 profiles look like the same
person"). Account-creation dates order each cluster into a timeline. Hits
with no corroboration match on the username alone.

Avatar fetching is the only network access: one GET per avatar image, which
the site already serves publicly. Nothing here contacts the subject.
"""

from __future__ import annotations

import asyncio
import io
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..core.result import Cluster, ClusterMember, Hit, Report
from .pivot import username_from_url

LINK_THRESHOLD = 0.4
MAX_AVATARS = 30
MAX_AVATAR_BYTES = 2_000_000
AVATAR_MAX_DISTANCE = 6  # of 64 dHash bits

# Signal weights: probability-style, combined as 1 - prod(1 - w).
WEIGHTS = {
    "same profile": 0.95,
    "cross-link": 0.8,
    "shared email": 0.8,
    "same avatar": 0.6,
    "same display name": 0.45,
    "same one-word name": 0.2,
    "same location": 0.15,
}

# Keys in a hit's `extra` that mark it as carrying profile data.
_PROFILE_KEYS = ("avatar_url", "created_at", "bio", "location", "links", "blog")
_DEFAULT_AVATAR_HINTS = (
    "default", "missing", "placeholder", "blank", "anonymous", "no_avatar", "noavatar",
    "fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb",  # Steam's default avatar
)
_VAGUE_LOCATIONS = {
    "earth", "internet", "the internet", "online", "remote", "worldwide", "global",
    "everywhere", "nowhere", "home", "here", "planet earth", "localhost", "web",
}
_HOST_ALIASES = {"twitter.com": "x.com"}


@dataclass
class _Node:
    index: int
    hit: Hit
    key: tuple[str, str] | None
    name: str | None = None
    location: str | None = None
    emails: set[str] = field(default_factory=set)
    link_keys: set[tuple[str, str]] = field(default_factory=set)
    avatar_url: str | None = None
    avatar_hash: int | None = None
    created_at: str | None = None


async def attribute(report: Report, client: Any = None, *, fetch_avatars: bool = True) -> list[Cluster]:
    """Cluster `report`'s FOUND hits; annotate each with `extra["attribution"]`."""
    for hit in report.hits:
        hit.extra.pop("attribution", None)
    nodes = [_node(i, hit, report.query) for i, hit in enumerate(report.hits) if hit.is_found]
    if fetch_avatars and client is not None:
        await _hash_avatars(nodes, client)

    edges: dict[tuple[int, int], list[str]] = {}
    for a_pos, a in enumerate(nodes):
        for b in nodes[a_pos + 1:]:
            signals = _signals(a, b)
            if signals and _combine(signals) >= LINK_THRESHOLD:
                edges[(a.index, b.index)] = signals

    clusters = _clusters(nodes, edges, report)
    report.clusters = clusters
    return clusters


# --- per-hit features ---------------------------------------------------------


def _node(index: int, hit: Hit, query: str) -> _Node:
    extra = hit.extra or {}
    node = _Node(index=index, hit=hit, key=url_key(hit.url))
    if not any(k in extra for k in _PROFILE_KEYS):
        return node  # a bare site probe: only its URL can corroborate
    node.name = _norm_name(extra.get("name"), query)
    node.location = _norm_location(extra.get("location"))
    raw_emails = _as_list(extra.get("emails")) + _as_list(extra.get("email"))
    node.emails = {e.lower() for e in raw_emails if isinstance(e, str) and "@" in e}
    links = _as_list(extra.get("links")) + _as_list(extra.get("blog"))
    if extra.get("twitter"):
        links.append(f"https://x.com/{extra['twitter']}")
    node.link_keys = {k for k in (url_key(link) for link in links) if k and k != node.key}
    avatar = extra.get("avatar_url")
    if isinstance(avatar, str) and avatar.startswith("http") and not _is_default_avatar(avatar):
        node.avatar_url = avatar
    created = extra.get("created_at")
    node.created_at = created if isinstance(created, str) and created else None
    return node


def url_key(url: Any) -> tuple[str, str] | None:
    """(host, handle) for a profile URL, so different URL spellings compare equal."""
    if not isinstance(url, str) or not url.strip():
        return None
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").lower()
    for prefix in ("www.", "m.", "mobile."):
        host = host.removeprefix(prefix)
    host = _HOST_ALIASES.get(host, host)
    if not host:
        return None
    handle = username_from_url(raw)
    if handle:
        return (host, handle.lower())
    path = parsed.path.strip("/").lower()
    if parsed.query and not path:
        path = parsed.query.lower()
    return (host, path)


def _norm_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = unicodedata.normalize("NFKC", value).casefold()
    text = re.sub(r"\(.*?\)|\[.*?\]", " ", text)  # pronouns, (he/him), [bot]
    text = re.sub(r"[^\w\s]", " ", text)
    return " ".join(text.split())


def _norm_name(value: Any, query: str) -> str | None:
    name = _norm_text(value)
    if not name:
        return None
    # A display name that is just the handle is a site default, not evidence.
    if name.replace(" ", "") == re.sub(r"[^\w]", "", query.casefold()):
        return None
    return name


def _norm_location(value: Any) -> str | None:
    loc = _norm_text(value)
    if not loc or loc in _VAGUE_LOCATIONS:
        return None
    return loc


def _is_default_avatar(url: str) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in _DEFAULT_AVATAR_HINTS)


# --- avatars ------------------------------------------------------------------


async def _hash_avatars(nodes: list[_Node], client: Any) -> None:
    wanted = [n for n in nodes if n.avatar_url][:MAX_AVATARS]
    by_url: dict[str, int | None] = {}

    async def fetch(url: str) -> None:
        try:
            resp = await client.get(url)
        except Exception:
            resp = None
        content = getattr(resp, "content", None) if resp is not None and resp.status_code == 200 else None
        by_url[url] = avatar_hash(content) if isinstance(content, bytes | bytearray) else None

    await asyncio.gather(*(fetch(url) for url in {n.avatar_url for n in wanted if n.avatar_url}))
    for node in wanted:
        node.avatar_hash = by_url.get(node.avatar_url or "")


def avatar_hash(data: bytes) -> int | None:
    """64-bit difference hash of an image, or None if it can't be decoded or is blank."""
    if not data or len(data) > MAX_AVATAR_BYTES:
        return None
    try:
        from PIL import Image, ImageStat
    except ImportError:  # pragma: no cover - pillow is a dependency
        return None
    try:
        with Image.open(io.BytesIO(data)) as img:
            gray = img.convert("L")
            if ImageStat.Stat(gray.resize((16, 16))).stddev[0] < 6:
                return None  # flat colour: placeholder, not a face or logo
            small = gray.resize((9, 8), Image.Resampling.LANCZOS)
            px = small.tobytes()
    except Exception:
        return None
    bits = 0
    for row in range(8):
        for col in range(8):
            left, right = px[row * 9 + col], px[row * 9 + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# --- pairwise signals and clustering ------------------------------------------


def _signals(a: _Node, b: _Node) -> list[str]:
    out = []
    if a.key and a.key == b.key:
        out.append("same profile")
    if (a.key and a.key in b.link_keys) or (b.key and b.key in a.link_keys):
        out.append("cross-link")
    if a.emails & b.emails:
        out.append("shared email")
    if a.avatar_hash is not None and b.avatar_hash is not None:
        if _hamming(a.avatar_hash, b.avatar_hash) <= AVATAR_MAX_DISTANCE:
            out.append("same avatar")
    if a.name and b.name and _names_match(a.name, b.name):
        out.append("same display name" if " " in a.name else "same one-word name")
    if a.location and b.location and _locations_match(a.location, b.location):
        out.append("same location")
    return out


def _names_match(a: str, b: str) -> bool:
    if a == b:
        return True
    ta, tb = set(a.split()), set(b.split())
    small, big = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    return len(small) >= 2 and small <= big


def _locations_match(a: str, b: str) -> bool:
    if a == b:
        return True
    # "London" vs "London, UK": compare the first place name.
    return a.split()[0] == b.split()[0] and len(a.split()[0]) > 2


def _combine(signals: list[str]) -> float:
    miss = 1.0
    for signal in signals:
        miss *= 1.0 - WEIGHTS[signal]
    return round(1.0 - miss, 2)


def _clusters(
    nodes: list[_Node], edges: dict[tuple[int, int], list[str]], report: Report
) -> list[Cluster]:
    parent = {n.index: n.index for n in nodes}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for a, b in edges:
        parent[find(a)] = find(b)

    groups: dict[int, list[_Node]] = {}
    for node in nodes:
        groups.setdefault(find(node.index), []).append(node)
    multi = sorted((g for g in groups.values() if len(g) > 1), key=lambda g: (-len(g), g[0].index))

    clusters: list[Cluster] = []
    for cid, group in enumerate(multi, start=1):
        members = {n.index for n in group}
        member_scores: dict[int, float] = {}
        member_signals: dict[int, list[str]] = {}
        cluster_signals: list[str] = []
        for (a, b), signals in edges.items():
            if a not in members:
                continue
            score = _combine(signals)
            for i, other in ((a, b), (b, a)):
                miss = 1.0 - member_scores.get(i, 0.0)
                member_scores[i] = round(1.0 - miss * (1.0 - score), 2)
                member_signals.setdefault(i, []).extend(
                    f"{s} with {report.hits[other].source}" for s in signals
                )
            cluster_signals.append(
                f"{report.hits[a].source} ↔ {report.hits[b].source}: {', '.join(signals)}"
            )
        timeline = sorted((n for n in group if n.created_at), key=lambda n: n.created_at or "")
        confidence = round(sum(member_scores.values()) / len(group), 2)
        for node in group:
            node.hit.extra["attribution"] = {
                "cluster": cid,
                "confidence": member_scores.get(node.index, 0.0),
                "signals": member_signals.get(node.index, []),
            }
        clusters.append(
            Cluster(
                id=cid,
                confidence=confidence,
                members=[ClusterMember(source=n.hit.source, url=n.hit.url) for n in group],
                signals=cluster_signals,
                timeline=[
                    ClusterMember(source=n.hit.source, url=n.hit.url, created_at=n.created_at)
                    for n in timeline
                ],
            )
        )

    for node in nodes:
        if "attribution" not in node.hit.extra:
            node.hit.extra["attribution"] = {
                "cluster": None,
                "confidence": 0.0,
                "signals": ["username match only"],
            }
    return clusters


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list | tuple | set):
        return list(value)
    return [value]
