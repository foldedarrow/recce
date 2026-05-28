# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
from stat import S_IMODE

from recce.licensing import has_pro_entitlement, pro_licence_path, write_pro_licence


def test_has_pro_entitlement_accepts_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_PRO_LICENCE", "test-token")

    assert has_pro_entitlement()


def test_has_pro_entitlement_accepts_private_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("RECCE_PRO_LICENCE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    path = write_pro_licence("file-token")

    assert path == pro_licence_path()
    assert has_pro_entitlement()
    assert S_IMODE(path.stat().st_mode) == 0o600
