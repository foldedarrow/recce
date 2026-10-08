# SPDX-License-Identifier: AGPL-3.0-or-later
"""GitHub commit search — which GitHub accounts and repos commit as this email."""

from __future__ import annotations

import time
from typing import Any

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class GitHubCommitsProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="github-commits",
            name="GitHub commits",
            tier="free",
            enriches=("email",),
            config_keys=("GITHUB_TOKEN",),
            setting_attrs=("github_token",),
            homepage="https://docs.github.com/en/rest/search/search#search-commits",
            notes="email → GitHub logins, author names and repos; token optional (raises rate limit)",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "email":
            return []
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if ctx.settings.github_token:
            headers["Authorization"] = f"Bearer {ctx.settings.github_token}"
        started = time.perf_counter()
        resp = await ctx.client.get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{target}", "per_page": 100, "sort": "author-date"},
            headers=headers,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("pivot", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code in {403, 429}:
            return [
                self.make_hit(
                    "pivot",
                    Status.SKIPPED,
                    summary="GitHub search rate limit hit (set GITHUB_TOKEN for more)",
                    elapsed_ms=elapsed,
                )
            ]
        if resp.status_code == 422:
            return [self.make_hit("pivot", Status.NOT_FOUND, summary="no commits", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("pivot", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]
        try:
            data: dict[str, Any] = resp.json() or {}
        except Exception:
            return [self.make_hit("pivot", Status.UNKNOWN, summary="bad json", elapsed_ms=elapsed)]

        total = int(data.get("total_count") or 0)
        items = data.get("items") or []
        if not total:
            return [self.make_hit("pivot", Status.NOT_FOUND, summary="no public commits", elapsed_ms=elapsed)]
        logins = sorted({(item.get("author") or {}).get("login") for item in items} - {None})
        names = sorted({((item.get("commit") or {}).get("author") or {}).get("name") for item in items} - {None, ""})
        repos = sorted({(item.get("repository") or {}).get("full_name") for item in items} - {None})
        dates = sorted(
            d for d in (((item.get("commit") or {}).get("author") or {}).get("date") for item in items) if d
        )
        parts = [f"{total} public commit(s)"]
        if logins:
            parts.append("GitHub login(s): " + ", ".join(logins))
        if names:
            parts.append("author name(s): " + ", ".join(names[:6]))
        if repos:
            parts.append(f"{len(repos)} repo(s): " + ", ".join(repos[:6]))
        if dates:
            parts.append(f"sampled commits {dates[0][:10]} → {dates[-1][:10]}")
        url = f"https://github.com/search?q=author-email%3A{target}&type=commits"
        return [
            self.make_hit(
                "pivot",
                Status.FOUND,
                url=url,
                summary=" · ".join(parts),
                confidence=0.9,
                elapsed_ms=elapsed,
                extra={
                    "total_commits": total,
                    "logins": logins,
                    "author_names": names,
                    "repos": repos,
                    "first_commit": dates[0] if dates else None,
                    "last_commit": dates[-1] if dates else None,
                    "usernames": logins,
                },
            )
        ]
