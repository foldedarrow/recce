# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime configuration: loads optional API keys from env / .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from recce import __version__

DEFAULT_USER_AGENT = f"recce/{__version__} (+https://github.com/foldedarrow/recce)"


def _load_env() -> None:
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env, override=False)
    home_env = user_env_path()
    if home_env.exists():
        load_dotenv(home_env, override=False)


def user_config_dir() -> Path:
    return Path.home() / ".config" / "recce"


def user_env_path() -> Path:
    return user_config_dir() / ".env"


def write_user_env(updates: dict[str, str | None], path: Path | None = None) -> Path:
    """Update the user-level recce .env while preserving unknown keys/comments."""
    env_path = path or user_env_path()
    env_path.parent.mkdir(parents=True, exist_ok=True)

    existing = env_path.read_text().splitlines() if env_path.exists() else []
    pending = {key: "" if value is None else str(value) for key, value in updates.items()}
    output: list[str] = []
    seen: set[str] = set()

    for line in existing:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            output.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in pending:
            output.append(f"{key}={pending[key]}")
            seen.add(key)
        else:
            output.append(line)

    for key, value in pending.items():
        if key not in seen:
            output.append(f"{key}={value}")
        if value:
            os.environ[key] = value
        else:
            os.environ.pop(key, None)

    env_path.write_text("\n".join(output).rstrip() + "\n")
    try:
        env_path.chmod(0o600)
    except OSError:
        pass
    return env_path


@dataclass(frozen=True)
class Settings:
    hibp_api_key: str | None
    hunter_api_key: str | None
    numverify_api_key: str | None
    emailrep_api_key: str | None
    leakcheck_api_key: str | None
    companies_house_key: str | None
    shodan_api_key: str | None
    virustotal_api_key: str | None
    securitytrails_api_key: str | None
    censys_api_id: str | None
    censys_api_secret: str | None
    user_agent: str
    timeout: float
    max_concurrency: int
    provider_integrations_enabled: bool = True

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
            shodan_api_key=os.getenv("SHODAN_API_KEY") or None,
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
            securitytrails_api_key=os.getenv("SECURITYTRAILS_API_KEY") or None,
            censys_api_id=os.getenv("CENSYS_API_ID") or None,
            censys_api_secret=os.getenv("CENSYS_API_SECRET") or None,
            user_agent=os.getenv("RECCE_USER_AGENT", DEFAULT_USER_AGENT),
            timeout=float(os.getenv("RECCE_TIMEOUT", "12")),
            max_concurrency=int(os.getenv("RECCE_CONCURRENCY", "30")),
        )

    def has(self, key: str) -> bool:
        return bool(getattr(self, key, None))

    def without_provider_integrations(self) -> Settings:
        return Settings(**{**self.__dict__, "provider_integrations_enabled": False})
