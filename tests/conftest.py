# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest


@pytest.fixture(autouse=True)
def _isolated_selftest_state(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Username searches read ~/.cache/recce/selftest.json; keep a developer's
    real selftest results (and $RECCE_FLAGGED_SITES) out of every test."""
    from recce.modules import selftest

    monkeypatch.setattr(selftest, "SELFTEST_PATH", tmp_path / "selftest.json")
    monkeypatch.delenv(selftest.FLAGGED_ENV, raising=False)


@pytest.fixture(autouse=True)
def _isolated_ofcom_cache(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Phone lookups prefer ~/.cache/recce's Ofcom index; tests use the
    bundled snapshot or their own fixture index."""
    from recce.modules import ofcom

    load_index = ofcom.load_index  # tests may monkeypatch the name
    monkeypatch.setattr(ofcom, "CACHED_INDEX", tmp_path / "ofcom-numbering.json.xz")
    load_index.cache_clear()
    yield
    load_index.cache_clear()
