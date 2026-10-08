# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import pytest

from recce.core.investigations import InvestigationStore
from recce.core.result import Hit, Report, Status

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "recce" / "gui" / "app.py")


def _pivot_buttons(at: AppTest) -> list:  # type: ignore[type-arg]
    return [b for b in at.button if b.label.startswith("🔎")]


def test_gui_follow_up_buttons_chain_searches_without_deep(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("RECCE_DATA_DIR", str(tmp_path))
    deep_calls: list[str] = []

    async def fake_email(addr, client, settings, **kwargs):  # type: ignore[no-untyped-def]
        report = Report(query=addr, query_type="email")
        local = addr.split("@")[0]
        report.add(Hit(source="Username pivot", status=Status.FOUND, extra={"username": local}))
        report.finish()
        return report

    async def fake_username(name, client, **kwargs):  # type: ignore[no-untyped-def]
        report = Report(query=name, query_type="username")
        report.add(
            Hit(
                source="GitHub identity",
                status=Status.FOUND,
                url=f"https://github.com/{name}",
                extra={"emails": ["c@example.test"]},
            )
        )
        report.finish()
        return report

    async def fake_deep(addr, **kwargs):  # type: ignore[no-untyped-def]
        deep_calls.append(addr)
        return []

    monkeypatch.setattr("recce.modules.email.search_email", fake_email)
    monkeypatch.setattr("recce.modules.username.search_username", fake_username)
    monkeypatch.setattr("recce.modules.email_deep.deep_email_probes", fake_deep)
    store = InvestigationStore()
    inv = store.create_investigation(name="GUI pivot")

    at = AppTest.from_file(APP, default_timeout=30)
    at.run()
    at.sidebar.radio(key="mode").set_value("Email").run()
    at.text_input(key="e_target").input("root@example.test")
    at.checkbox(key="e_deep").check()
    at.checkbox(key="e_own").check()
    next(b for b in at.button if b.label == "Run").click()
    at.run()
    assert not at.exception
    assert deep_calls == ["root@example.test"]

    [follow_username] = _pivot_buttons(at)
    assert follow_username.label == "🔎 username: root"
    follow_username.click().run()
    assert not at.exception
    assert at.session_state["mode"] == "Username"
    assert at.session_state["u_report"].pivot.from_query == "root@example.test"
    assert "discovered via Username pivot hit" in at.info[0].value

    [follow_email] = _pivot_buttons(at)
    follow_email.click().run()
    assert not at.exception
    assert at.session_state["e_report"].query == "c@example.test"
    # The deep checkbox is still ticked, but a discovered email never gets deep probes.
    assert deep_calls == ["root@example.test"]

    chain = store.export_investigation(inv["id"])["pivot_chain"]
    assert [(e["from_query"], e["to_query"]) for e in chain] == [
        ("root@example.test", "root"),
        ("root", "c@example.test"),
    ]
