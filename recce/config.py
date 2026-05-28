# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime configuration: loads optional API keys from env / .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env, override=False)
    home_env = Path.home() / ".config" / "recce" / ".env"
    if home_env.exists():
        load_dotenv(home_env, override=False)


@dataclass(frozen=True)
class Settings:
    hibp_api_key: str | None
    hunter_api_key: str | None
    numverify_api_key: str | None
    emailrep_api_key: str | None
    leakcheck_api_key: str | None
    companies_house_key: str | None
    user_agent: str
    timeout: float
    max_concurrency: int

    @classmethod
    def load(cls) -> Settings:
        _load_env()
        return cls(
            hibp_api_key=os.getenv("HIBP_API_KEY") or None,
            hunter_api_key=os.getenv("HUNTER_API_KEY") or None,
            numverify_api_key=os.getenv("NUMVERIFY_API_KEY") or None,
            emailrep_api_key=os.getenv("EMAILREP_API_KEY") or None,
            leakcheck_api_key=os.getenv("LEAKCHECK_API_KEY") or None,
            companies_house_key=os.getenv("COMPANIES_HOUSE_KEY") or None,
            user_agent=os.getenv(
                "RECCE_USER_AGENT",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36",
            ),
            timeout=float(os.getenv("RECCE_TIMEOUT", "12")),
            max_concurrency=int(os.getenv("RECCE_CONCURRENCY", "30")),
        )

    def has(self, key: str) -> bool:
        return bool(getattr(self, key, None))
