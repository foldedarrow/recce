# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest


@pytest.fixture(autouse=True)
def _isolated_selftest_state(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Username searches read ~/.cache/recce/selftest.json; keep a developer's
    real selftest results (and $RECCE_FLAGGED_SITES) out of every test."""
    from recce.modules import selftest

    monkeypatch.setattr(selftest, "SELFTEST_PATH", tmp_path / "selftest.json")
    monkeypatch.delenv(selftest.FLAGGED_ENV, raising=False)
