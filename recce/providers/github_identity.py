# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitHub identity provider — username → profile details and commit identities.

Commit metadata in a user's own public repos often carries the real name and
email they configured in git (and sometimes a laptop hostname, when git was
never configured). That is one of the strongest public username → identity
pivots available, and needs no key.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext

API = "https://api.github.com"
MAX_REPOS = 5
COMMITS_PER_REPO = 30


class GitHubIdentityProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="github-identity",
            name="GitHub identity",
            tier="free",
            enriches=("username",),
            config_keys=("GITHUB_TOKEN",),
            setting_attrs=("github_token",),
            homepage="https://docs.github.com/en/rest/users/users",
            notes="profile + real names/emails from the user's own commits; token optional",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "username":
            return []
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if ctx.settings.github_token:
            headers["Authorization"] = f"Bearer {ctx.settings.github_token}"

        started = time.perf_counter()
        resp = await ctx.client.get(f"{API}/users/{target}", headers=headers)
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("identity", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code == 404:
            return [self.make_hit("identity", Status.NOT_FOUND, summary="no GitHub user", elapsed_ms=elapsed)]
        if resp.status_code in {403, 429}:
            return [
                self.make_hit(
                    "identity",
                    Status.SKIPPED,
                    summary="GitHub API rate limit hit (set GITHUB_TOKEN for more)",
                    elapsed_ms=elapsed,
                )
            ]
        if resp.status_code != 200:
            return [self.make_hit("identity", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            profile: dict[str, Any] = resp.json() or {}
        except Exception:
            return [self.make_hit("identity", Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)]
        if profile.get("type") == "Organization":
            return [self._profile_hit(target, profile, elapsed)]

        identities = await self._commit_identities(target, headers, ctx)
        return [self._profile_hit(target, profile, elapsed), *self._identity_hits(target, identities)]

    def _profile_hit(self, login: str, profile: dict[str, Any], elapsed: int) -> Hit:
        fields = {
            "name": profile.get("name"),
            "company": profile.get("company"),
            "location": profile.get("location"),
            "email": profile.get("email"),
            "blog": profile.get("blog") or None,
            "twitter": profile.get("twitter_username"),
            "bio": (profile.get("bio") or "").strip() or None,
        }
        parts = [f"{label}: {value}" for label, value in fields.items() if value and label != "bio"]
        if fields["bio"]:
            parts.append(f"bio: “{fields['bio'][:80]}”")
        created = (profile.get("created_at") or "")[:10]
        parts.append(f"joined {created}" if created else "account exists")
        parts.append(f"{profile.get('public_repos', 0)} repos · {profile.get('followers', 0)} followers")
        usernames = [fields["twitter"]] if fields["twitter"] else []
        return self.make_hit(
            "identity",
            Status.FOUND,
            url=profile.get("html_url") or f"https://github.com/{login}",
            summary=" · ".join(parts),
            confidence=0.9,
            elapsed_ms=elapsed,
            extra={**fields, "created_at": profile.get("created_at"), "type": profile.get("type"), "usernames": usernames},
        )

    async def _commit_identities(
        self, login: str, headers: dict[str, str], ctx: ProviderContext
    ) -> dict[tuple[str, str], dict[str, Any]]:
        resp = await ctx.client.get(
            f"{API}/users/{login}/repos",
            params={"type": "owner", "sort": "pushed", "per_page": 30},
            headers=headers,
        )
        if resp is None or resp.status_code != 200:
            return {}
        try:
            repos = [repo["name"] for repo in resp.json() if not repo.get("fork")][:MAX_REPOS]
        except Exception:
            return {}

        async def commits(repo: str) -> list[tuple[str, dict[str, Any]]]:
            r = await ctx.client.get(
                f"{API}/repos/{login}/{repo}/commits",
                params={"author": login, "per_page": COMMITS_PER_REPO},
                headers=headers,
            )
            if r is None or r.status_code != 200:
                return []
            try:
                return [(repo, item) for item in r.json() if isinstance(item, dict)]
            except Exception:
                return []

        identities: dict[tuple[str, str], dict[str, Any]] = {}
        for batch in await asyncio.gather(*(commits(repo) for repo in repos)):
            for repo, item in batch:
                for role in ("author", "committer"):
                    person = (item.get("commit") or {}).get(role) or {}
                    name, email = person.get("name") or "", (person.get("email") or "").lower()
                    if not email or email == "noreply@github.com":
                        continue
                    entry = identities.setdefault((name, email), {"name": name, "email": email, "repos": set(), "commits": 0})
                    entry["repos"].add(repo)
                    entry["commits"] += 1
        return identities

    def _identity_hits(self, login: str, identities: dict[tuple[str, str], dict[str, Any]]) -> list[Hit]:
        hits = []
        for entry in sorted(identities.values(), key=lambda e: -e["commits"]):
            email = entry["email"]
            kind = _email_kind(email)
            parts = [f"{entry['name'] or '(no name)'} <{email}>", kind, f"{entry['commits']} commit(s) in {', '.join(sorted(entry['repos']))}"]
            hits.append(
                self.make_hit(
                    "identity",
                    Status.FOUND,
                    url=f"https://github.com/{login}",
                    summary=" · ".join(parts),
                    confidence=0.85 if kind == "real email" else 0.6,
                    extra={
                        "name": entry["name"],
                        "email": email,
                        "email_kind": kind,
                        "repos": sorted(entry["repos"]),
                        "commits": entry["commits"],
                        "emails": [email] if kind == "real email" else [],
                    },
                )
            )
        return hits


def _email_kind(email: str) -> str:
    domain = email.rsplit("@", 1)[-1]
    if domain.endswith("users.noreply.github.com"):
        return "GitHub noreply alias"
    if domain.endswith((".local", ".lan", ".localdomain", ".home", ".internal")) or "." not in domain:
        return "machine hostname (git user.email never set)"
    return "real email"
