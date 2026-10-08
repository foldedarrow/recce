# SPDX-License-Identifier: AGPL-3.0-or-later
"""Profile providers — username → structured profile data from public APIs.

The username module only says whether an account exists. These providers
read the site's own public JSON (or XML) endpoint and pull out display name,
bio, location, external links, avatar and account age, plus linked handles
(`extra.usernames`) and emails (`extra.emails`) for pivoting.

Every site here was checked live from a Proton VPN egress. Sites that block
it or need auth are left out: Reddit's `about.json` 403s, PyPI has no user
JSON, GitLab's per-user detail endpoint needs a token. A hit is FOUND only
when the API itself returns the account.
"""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

# host → path pattern whose first group is the account handle. Only links in
# structured profile fields (Mastodon fields, Keybase proofs, a site's
# "website" slot) become usernames; links in free-text bios stay links.
HANDLE_SITES: dict[str, re.Pattern[str]] = {
    "github.com": re.compile(r"^/([A-Za-z0-9-]{1,39})/?$"),
    "gitlab.com": re.compile(r"^/([A-Za-z0-9_.-]{1,255})/?$"),
    "twitter.com": re.compile(r"^/@?([A-Za-z0-9_]{1,15})/?$"),
    "x.com": re.compile(r"^/@?([A-Za-z0-9_]{1,15})/?$"),
    "instagram.com": re.compile(r"^/([A-Za-z0-9_.]{1,30})/?$"),
    "twitch.tv": re.compile(r"^/([A-Za-z0-9_]{3,25})/?$"),
    "reddit.com": re.compile(r"^/(?:u|user)/([A-Za-z0-9_-]{3,20})/?$"),
    "keybase.io": re.compile(r"^/([A-Za-z0-9_]{2,16})/?$"),
    "youtube.com": re.compile(r"^/@([A-Za-z0-9_.-]{3,30})/?$"),
    "bsky.app": re.compile(r"^/profile/([A-Za-z0-9.-]+)/?$"),
    "news.ycombinator.com": re.compile(r"^/user$"),
}


@dataclass
class Profile:
    url: str
    name: str | None = None
    bio: str | None = None
    location: str | None = None
    links: list[str] = field(default_factory=list)
    avatar_url: str | None = None
    created_at: str | None = None
    usernames: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


class ProfileProvider(Provider):
    """A username provider that fetches one public profile endpoint."""

    missing_codes: frozenset[int] = frozenset({404, 410})
    headers: dict[str, str] = {"Accept": "application/json"}  # noqa: RUF012

    def __init__(self, id: str, name: str, homepage: str, notes: str) -> None:
        super().__init__(
            id=id,
            name=name,
            tier="free",
            enriches=("username",),
            config_keys=(),
            setting_attrs=(),
            homepage=homepage,
            notes=notes,
        )

    def endpoint(self, username: str) -> str | None:
        """API URL for `username`, or None when the name can't exist on this site."""
        raise NotImplementedError

    def parse(self, username: str, resp: Any) -> Profile | None:
        """Profile from a 200 response, or None when the API says there's no account."""
        raise NotImplementedError

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "username":
            return []
        url = self.endpoint(target)
        if url is None:
            return []
        started = time.perf_counter()
        resp = await ctx.client.get(url, headers=self.headers)
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("identity", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code in self.missing_codes:
            return [self._not_found(elapsed)]
        if resp.status_code == 429:
            return [self.make_hit("identity", Status.SKIPPED, summary="rate limited", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("identity", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            profile = self.parse(target, resp)
        except Exception:
            return [self.make_hit("identity", Status.UNKNOWN, summary="unexpected response", elapsed_ms=elapsed)]
        if profile is None:
            return [self._not_found(elapsed)]
        return [self._profile_hit(profile, elapsed)]

    def _not_found(self, elapsed: int) -> Hit:
        return self.make_hit("identity", Status.NOT_FOUND, summary=f"no {self.name.removesuffix(' profile')} account", elapsed_ms=elapsed)

    def _profile_hit(self, p: Profile, elapsed: int) -> Hit:
        p.links = _dedupe(p.links)
        p.usernames = _dedupe(p.usernames, casefold=True)
        p.emails = _dedupe([e.lower() for e in p.emails])
        parts = [
            f"{label}: {value}"
            for label, value in (("name", p.name), ("location", p.location))
            if value
        ]
        if p.bio:
            bio = " ".join(p.bio.split())
            parts.append(f"bio: “{bio[:80]}{'…' if len(bio) > 80 else ''}”")
        if p.links:
            parts.append("links: " + ", ".join(p.links[:3]) + (f" +{len(p.links) - 3}" if len(p.links) > 3 else ""))
        if p.usernames:
            parts.append("linked: " + ", ".join(p.usernames[:5]))
        if p.emails:
            parts.append("email: " + ", ".join(p.emails))
        parts.append(f"joined {p.created_at[:10]}" if p.created_at else "account exists")
        stats = [f"{value:,} {label}" if isinstance(value, int) else f"{label} {value}" for label, value in p.stats.items() if value not in (None, "")]
        if stats:
            parts.append(" · ".join(stats))
        return self.make_hit(
            "identity",
            Status.FOUND,
            url=p.url,
            summary=" · ".join(parts),
            confidence=0.9,
            elapsed_ms=elapsed,
            extra={
                "name": p.name,
                "bio": p.bio,
                "location": p.location,
                "links": p.links,
                "avatar_url": p.avatar_url,
                "created_at": p.created_at,
                "usernames": p.usernames,
                "emails": p.emails,
                **p.stats,
                **p.details,
            },
        )


class GitLabProfileProvider(ProfileProvider):
    def __init__(self) -> None:
        super().__init__(
            "gitlab-profile", "GitLab profile", "https://docs.gitlab.com/api/users/",
            "gitlab.com user lookup: name, avatar, public email",
        )

    def endpoint(self, username: str) -> str:
        return f"https://gitlab.com/api/v4/users?username={username}"

    def parse(self, username: str, resp: Any) -> Profile | None:
        users = resp.json()
        user = next((u for u in users if str(u.get("username", "")).lower() == username.lower()), None)
        if user is None:
            return None
        email = (user.get("public_email") or "").strip()
        return Profile(
            url=user.get("web_url") or f"https://gitlab.com/{username}",
            name=_clean(user.get("name")),
            avatar_url=user.get("avatar_url"),
            emails=[email] if email else [],
            details={"state": user.get("state"), "bot": user.get("bot")},
        )


class MastodonProfileProvider(ProfileProvider):
    INSTANCE = "mastodon.social"

    def __init__(self) -> None:
        super().__init__(
            "mastodon-profile", "Mastodon profile", "https://docs.joinmastodon.org/methods/accounts/#lookup",
            f"{self.INSTANCE} account lookup: bio, profile links (with verification), join date",
        )

    def endpoint(self, username: str) -> str:
        return f"https://{self.INSTANCE}/api/v1/accounts/lookup?acct={username}"

    def parse(self, username: str, resp: Any) -> Profile | None:
        acct = resp.json()
        if str(acct.get("username", "")).lower() != username.lower():
            return None
        note = _html_text(acct.get("note") or "")
        links, usernames, verified = list(note.links), [], []
        for item in acct.get("fields") or []:
            value = _html_text(item.get("value") or "")
            for link in value.links or URL_RE.findall(value.text):
                links.append(link)
                usernames.extend(_handles([link]))
                if item.get("verified_at"):
                    verified.append(link)
        avatar = acct.get("avatar") or ""
        moved = (acct.get("moved") or {}).get("acct")
        return Profile(
            url=acct.get("url") or f"https://{self.INSTANCE}/@{username}",
            name=_clean(acct.get("display_name")),
            bio=note.text or None,
            links=links,
            avatar_url=None if avatar.endswith("missing.png") else avatar or None,
            created_at=acct.get("created_at"),
            usernames=usernames + ([moved] if moved else []),
            emails=EMAIL_RE.findall(note.text),
            stats={"followers": acct.get("followers_count"), "posts": acct.get("statuses_count")},
            details={"verified_links": verified, "bot": acct.get("bot"), "moved_to": moved},
        )


class BlueskyProfileProvider(ProfileProvider):
    # A bare name is a bsky.social handle; a dotted name is tried as a custom-domain handle.
    HANDLE_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
    missing_codes = frozenset({400, 404})

    def __init__(self) -> None:
        super().__init__(
            "bluesky-profile", "Bluesky profile", "https://docs.bsky.app/docs/api/app-bsky-actor-get-profile",
            "public AppView profile: display name, bio, join date",
        )

    def endpoint(self, username: str) -> str | None:
        handle = username.lower() if "." in username else f"{username.lower()}.bsky.social"
        if not self.HANDLE_RE.match(handle):
            return None
        return f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}"

    def parse(self, username: str, resp: Any) -> Profile | None:
        actor = resp.json()
        handle = actor.get("handle")
        if not handle or not actor.get("did"):
            return None
        bio = (actor.get("description") or "").strip()
        return Profile(
            url=f"https://bsky.app/profile/{handle}",
            name=_clean(actor.get("displayName")),
            bio=bio or None,
            links=URL_RE.findall(bio),
            avatar_url=actor.get("avatar"),
            created_at=actor.get("createdAt"),
            emails=EMAIL_RE.findall(bio),
            stats={"followers": actor.get("followersCount"), "posts": actor.get("postsCount")},
            details={"handle": handle, "did": actor.get("did")},
        )


class KeybaseProfileProvider(ProfileProvider):
    # Proof types whose nametag is a handle on another site (vs a domain).
    DOMAIN_PROOFS = frozenset({"dns", "generic_web_site", "https", "http", "web"})

    def __init__(self) -> None:
        super().__init__(
            "keybase-profile", "Keybase profile", "https://keybase.io/docs/api/1.0/call/user/lookup",
            "profile + cryptographic proofs of linked accounts and domains",
        )

    def endpoint(self, username: str) -> str | None:
        if not re.fullmatch(r"[A-Za-z0-9_]{2,16}", username):
            return None
        return (
            "https://keybase.io/_/api/1.0/user/lookup.json"
            f"?usernames={username.lower()}&fields=basics,profile,proofs_summary,pictures"
        )

    def parse(self, username: str, resp: Any) -> Profile | None:
        data = resp.json()
        # Keybase answers a missing user with HTTP 200 and an INPUT_ERROR status.
        if (data.get("status") or {}).get("code") != 0:
            return None
        them = data.get("them") or []
        user = them[0] if them else None
        if not user or not user.get("basics"):
            return None
        basics, prof = user["basics"], user.get("profile") or {}
        proofs, links, usernames = [], [], []
        for proof in (user.get("proofs_summary") or {}).get("all") or []:
            kind, tag, ok = proof.get("proof_type"), proof.get("nametag"), proof.get("state") == 1
            proofs.append({"type": kind, "name": tag, "url": proof.get("service_url"), "ok": ok})
            if not ok or not tag:
                continue
            if proof.get("service_url"):
                links.append(proof["service_url"])
            if kind not in self.DOMAIN_PROOFS:
                usernames.append(tag)
        name = basics.get("username_cased") or basics.get("username")
        return Profile(
            url=f"https://keybase.io/{name}",
            name=_clean(prof.get("full_name")),
            bio=_clean(prof.get("bio")),
            location=_clean(prof.get("location")),
            links=links,
            avatar_url=((user.get("pictures") or {}).get("primary") or {}).get("url"),
            created_at=_epoch(basics.get("ctime")),
            usernames=usernames,
            stats={"proofs": sum(1 for p in proofs if p["ok"])},
            details={"proofs": proofs},
        )


class HackerNewsProfileProvider(ProfileProvider):
    def __init__(self) -> None:
        super().__init__(
            "hackernews-profile", "Hacker News profile", "https://github.com/HackerNews/API",
            "Firebase API: about text (links/emails), karma, join date",
        )

    def endpoint(self, username: str) -> str:
        return f"https://hacker-news.firebaseio.com/v0/user/{username}.json"

    def parse(self, username: str, resp: Any) -> Profile | None:
        user = resp.json()
        # HN ids are case-sensitive; a miss is HTTP 200 with body `null`.
        if not isinstance(user, dict) or user.get("id") != username:
            return None
        about = _html_text(user.get("about") or "")
        return Profile(
            url=f"https://news.ycombinator.com/user?id={username}",
            bio=about.text or None,
            links=about.links or URL_RE.findall(about.text),
            created_at=_epoch(user.get("created")),
            emails=EMAIL_RE.findall(about.text),
            stats={"karma": user.get("karma"), "submissions": len(user.get("submitted") or [])},
        )


class ChessComProfileProvider(ProfileProvider):
    def __init__(self) -> None:
        super().__init__(
            "chesscom-profile", "Chess.com profile", "https://www.chess.com/news/view/published-data-api",
            "published-data API: name, location, country, streaming links, join date",
        )

    def endpoint(self, username: str) -> str:
        return f"https://api.chess.com/pub/player/{username.lower()}"

    def parse(self, username: str, resp: Any) -> Profile | None:
        player = resp.json()
        if str(player.get("username", "")).lower() != username.lower():
            return None
        streams = [s.get("channel_url") for s in player.get("streaming_platforms") or [] if s.get("channel_url")]
        if player.get("twitch_url"):
            streams.append(player["twitch_url"])
        country = (player.get("country") or "").rstrip("/").rsplit("/", 1)[-1] or None
        return Profile(
            url=player.get("url") or f"https://www.chess.com/member/{username}",
            name=_clean(player.get("name")),
            location=_clean(player.get("location")),
            links=streams,
            avatar_url=player.get("avatar"),
            created_at=_epoch(player.get("joined")),
            usernames=_handles(streams),
            stats={"followers": player.get("followers"), "title": player.get("title"), "status": player.get("status")},
            details={"country": country, "last_online": _epoch(player.get("last_online"))},
        )


class DockerHubProfileProvider(ProfileProvider):
    def __init__(self) -> None:
        super().__init__(
            "dockerhub-profile", "Docker Hub profile", "https://docs.docker.com/reference/api/hub/latest/",
            "user/org record: full name, company, location, website, join date",
        )

    def endpoint(self, username: str) -> str:
        # Organisations 308 to /v2/orgs/{name}; the client follows it.
        return f"https://hub.docker.com/v2/users/{username.lower()}/"

    def parse(self, username: str, resp: Any) -> Profile | None:
        user = resp.json()
        login = user.get("username") or user.get("orgname") or ""
        if login.lower() != username.lower():
            return None
        website = (user.get("profile_url") or "").strip()
        avatar = user.get("gravatar_url") or ""
        return Profile(
            url=f"https://hub.docker.com/u/{login}",
            name=_clean(user.get("full_name")),
            location=_clean(user.get("location")),
            links=[website] if website else [],
            avatar_url=avatar or None,
            created_at=user.get("date_joined"),
            usernames=_handles([website]),
            emails=[user["gravatar_email"]] if user.get("gravatar_email") else [],
            stats={"type": user.get("type")},
            details={"company": _clean(user.get("company"))},
        )


class NpmProfileProvider(ProfileProvider):
    def __init__(self) -> None:
        super().__init__(
            "npm-profile", "npm maintainer", "https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md",
            "packages maintained + the maintainer's registry email (accounts without packages can't be seen)",
        )

    def endpoint(self, username: str) -> str:
        return f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username.lower()}&size=20"

    def parse(self, username: str, resp: Any) -> Profile | None:
        data = resp.json()
        emails, packages = [], []
        for obj in data.get("objects") or []:
            pkg = obj.get("package") or {}
            people = [pkg.get("publisher") or {}, *(pkg.get("maintainers") or [])]
            mine = [p for p in people if str(p.get("username", "")).lower() == username.lower()]
            if not mine:
                continue
            packages.append(pkg.get("name"))
            emails.extend(p["email"] for p in mine if p.get("email"))
        if not packages:
            return None
        return Profile(
            url=f"https://www.npmjs.com/~{username.lower()}",
            emails=emails,
            stats={"packages": data.get("total") or len(packages)},
            details={"sample_packages": packages[:10]},
        )

    def _not_found(self, elapsed: int) -> Hit:
        return self.make_hit(
            "identity", Status.NOT_FOUND, summary="no npm packages maintained by this name", elapsed_ms=elapsed
        )


class SteamProfileProvider(ProfileProvider):
    headers = {"Accept": "text/xml"}  # noqa: RUF012

    def __init__(self) -> None:
        super().__init__(
            "steam-profile", "Steam profile", "https://steamcommunity.com/",
            "custom-URL profile XML: persona, real name, location, summary, join date",
        )

    def endpoint(self, username: str) -> str:
        return f"https://steamcommunity.com/id/{username}/?xml=1"

    def parse(self, username: str, resp: Any) -> Profile | None:
        root = ET.fromstring(resp.text)
        if root.tag != "profile" or not root.findtext("steamID64"):
            return None

        def text(tag: str) -> str | None:
            return _clean(root.findtext(tag))

        summary = _html_text(root.findtext("summary") or "")
        return Profile(
            url=f"https://steamcommunity.com/id/{root.findtext('customURL') or username}",
            name=text("realname"),
            bio=summary.text or None,
            location=text("location"),
            links=summary.links,
            avatar_url=text("avatarFull"),
            created_at=_steam_date(root.findtext("memberSince")),
            emails=EMAIL_RE.findall(summary.text),
            stats={
                "persona": text("steamID"),
                "privacy": text("privacyState"),
                "VAC banned": text("vacBanned") if text("vacBanned") != "0" else None,
            },
            details={"steam_id64": text("steamID64")},
        )


PROFILE_PROVIDERS: tuple[ProfileProvider, ...] = (
    GitLabProfileProvider(),
    MastodonProfileProvider(),
    BlueskyProfileProvider(),
    KeybaseProfileProvider(),
    HackerNewsProfileProvider(),
    ChessComProfileProvider(),
    DockerHubProfileProvider(),
    NpmProfileProvider(),
    SteamProfileProvider(),
)


@dataclass
class _Text:
    text: str
    links: list[str]


class _TextAndLinks(HTMLParser):
    """Visible text plus hrefs, skipping Mastodon @mentions and #hashtags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.links: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag in {"br", "p"}:
            self.chunks.append("\n")
        if tag == "span" and "invisible" in (a.get("class") or "").split():
            self._hidden += 1
        if tag == "a" and a.get("href", "").startswith(("http://", "https://")):
            classes = set((a.get("class") or "").split())
            if not classes & {"mention", "hashtag"} and "/tags/" not in (a["href"] or ""):
                self.links.append(a["href"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "span" and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.chunks.append(data)


def _html_text(html: str) -> _Text:
    parser = _TextAndLinks()
    parser.feed(html)
    parser.close()
    text = "\n".join(" ".join(line.split()) for line in "".join(parser.chunks).splitlines())
    return _Text(text.strip(), _dedupe(parser.links))


def _handles(links: list[str]) -> list[str]:
    """Account handles from links to known profile sites."""
    out = []
    for link in links:
        parsed = urlparse(link if "://" in link else f"https://{link}")
        host = (parsed.hostname or "").lower().removeprefix("www.").removeprefix("m.")
        pattern = HANDLE_SITES.get(host)
        if pattern is None:
            continue
        if host == "news.ycombinator.com":
            match = re.search(r"(?:^|&)id=([A-Za-z0-9_-]+)", parsed.query)
        else:
            match = pattern.match(parsed.path)
        if match:
            out.append(match.group(1))
    return out


def _dedupe(items: list[str], *, casefold: bool = False) -> list[str]:
    seen, out = set(), []
    for item in items:
        key = item.lower() if casefold else item
        if item and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _clean(value: Any) -> str | None:
    text = " ".join(str(value or "").split())
    return text or None


def _epoch(value: Any) -> str | None:
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _steam_date(value: str | None) -> str | None:
    for fmt in ("%B %d, %Y", "%d %B, %Y", "%B %d %Y"):
        try:
            return datetime.strptime((value or "").strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return None
