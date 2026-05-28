# SPDX-License-Identifier: AGPL-3.0-or-later
"""Small Recce Pro entitlement helpers.

This is intentionally local and offline for now. The commercial licence server
flow can replace the internals later without changing provider-gating callers.
"""

from __future__ import annotations

import os
from pathlib import Path

from .config import user_config_dir


def pro_licence_path() -> Path:
    return user_config_dir() / "pro_licence.txt"


def has_pro_entitlement() -> bool:
    env_value = (os.getenv("RECCE_PRO_LICENCE") or "").strip()
    if env_value:
        return True
    path = pro_licence_path()
    try:
        return path.exists() and bool(path.read_text().strip())
    except OSError:
        return False


def write_pro_licence(value: str | None) -> Path:
    path = pro_licence_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cleaned = (value or "").strip()
    if cleaned:
        path.write_text(cleaned + "\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    elif path.exists():
        path.unlink()
    return path
