# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from stat import S_IMODE

from recce.config import write_user_env


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
