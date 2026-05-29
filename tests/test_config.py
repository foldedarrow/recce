# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from stat import S_IMODE

from recce.config import DEFAULT_USER_AGENT, Settings, write_user_env


def test_write_user_env_preserves_comments_and_uses_private_permissions(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("# recce\nHIBP_API_KEY=old\nUNKNOWN=value\n")

    write_user_env(
        {
            "HIBP_API_KEY": "new",
            "SHODAN_API_KEY": "shodan",
        },
        path=env_path,
    )

    assert env_path.read_text().splitlines() == [
        "# recce",
        "HIBP_API_KEY=new",
        "UNKNOWN=value",
        "SHODAN_API_KEY=shodan",
    ]
    assert S_IMODE(env_path.stat().st_mode) == 0o600


def test_default_user_agent_identifies_recce(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("recce.config.user_env_path", lambda: tmp_path / "missing.env")
    monkeypatch.delenv("RECCE_USER_AGENT", raising=False)

    settings = Settings.load()

    assert settings.user_agent == DEFAULT_USER_AGENT
    assert settings.user_agent.startswith("recce/")
