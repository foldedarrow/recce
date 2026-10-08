# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep email (user-scanner + holehe) module selection, exit routing and the
made-up-address canary."""

from __future__ import annotations

import pathlib
import types
from typing import Any

import httpx
import pytest
from user_scanner.core.result import Result

from recce.core.result import Status
from recce.modules import email_deep
from recce.modules.email_deep import DeepProbe


def _holehe_result(name: str, exists: bool | None, rate_limited: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "domain": f"{name}.test",
        "method": "register",
        "frequent_rate_limit": False,
        "rateLimit": rate_limited,
        "exists": exists,
        "emailrecovery": None,
        "phoneNumber": None,
        "others": None,
    }


def _holehe_probe(name: str, registered: set[str]) -> DeepProbe:
    """A fake holehe probe that says yes for the addresses in `registered`
    ("*" = every address)."""

    async def probe(email: str, client: Any, out: list[dict[str, Any]]) -> None:
        probe.calls.append(email)  # type: ignore[attr-defined]
        out.append(_holehe_result(name, "*" in registered or email in registered))

    probe.calls = []  # type: ignore[attr-defined]
    return DeepProbe("holehe", "social", name, probe)


def _us_probe(name: str, answer: Any) -> DeepProbe:
    """A fake user-scanner module; `answer(email)` returns its Result."""

    async def validate(email: str) -> Result:
        validate.calls.append(email)  # type: ignore[attr-defined]
        return answer(email)

    validate.calls = []  # type: ignore[attr-defined]
    return DeepProbe("user-scanner", "social", name, validate)


def _installed_user_scanner_modules() -> set[str]:
    import user_scanner.email_scan as root

    base = pathlib.Path(root.__file__).parent
    return {
        path.stem.replace("_", ".")
        for path in base.glob("*/*.py")
        if path.name != "__init__.py"
    }


def test_user_scanner_allowlist_covers_every_installed_module() -> None:
    allowed = set(email_deep.USER_SCANNER_MODULES)
    notifying = set(email_deep.NOTIFYING_USER_SCANNER_MODULES)
    broken = set(email_deep.BROKEN_USER_SCANNER_MODULES)

    assert not allowed & notifying
    assert not allowed & broken
    assert not notifying & broken
    # Every module of the pinned release was reviewed; a release with new
    # modules fails here until it is audited.
    assert allowed | notifying | broken == _installed_user_scanner_modules()


def test_upstream_loud_modules_and_known_notifiers_never_run() -> None:
    from user_scanner.core.helpers import LOUD_MODULES

    names = {probe.name for probe in email_deep._load_modules()}

    # The loud list also names sites with no email module (leetcode).
    loud = set(LOUD_MODULES["email"]) & _installed_user_scanner_modules()
    assert loud and loud <= set(email_deep.NOTIFYING_USER_SCANNER_MODULES)
    for name in ("vedantu", "anilist", "facebook", "patreon", "hubspot", "fixderma", "mastodon"):
        assert name in email_deep.NOTIFYING_USER_SCANNER_MODULES
        assert name not in names
    assert "office365" in email_deep.BROKEN_USER_SCANNER_MODULES


def test_holehe_only_runs_sites_user_scanner_lacks() -> None:
    probes = email_deep._load_modules()
    holehe = {p.name for p in probes if p.backend == "holehe"}
    names = [p.name for p in probes]

    assert set(email_deep.HOLEHE_REPLACED_BY_USER_SCANNER.values()) <= set(
        email_deep.USER_SCANNER_MODULES
    )
    assert holehe
    assert not holehe & set(email_deep.HOLEHE_REPLACED_BY_USER_SCANNER)
    assert not holehe & email_deep.SKIPPED_HOLEHE_MODULES
    assert {"lastpass", "replit"} <= holehe
    assert len(names) == len(set(names))


def test_every_skip_has_a_reason() -> None:
    for reasons in (
        email_deep.NOTIFYING_HOLEHE_MODULES,
        email_deep.BROKEN_HOLEHE_MODULES,
        email_deep.NOTIFYING_USER_SCANNER_MODULES,
        email_deep.BROKEN_USER_SCANNER_MODULES,
    ):
        assert all(reason.strip() for reason in reasons.values())
    assert not set(email_deep.NOTIFYING_HOLEHE_MODULES) & set(email_deep.BROKEN_HOLEHE_MODULES)


def test_loading_leaves_httpx_alone() -> None:
    before = httpx.AsyncClient.__init__

    email_deep._load_modules()

    assert httpx.AsyncClient.__init__ is before


def test_exit_shim_routes_module_clients_through_the_proxy(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    built: list[dict[str, Any]] = []
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: built.append(kw))
    module = types.ModuleType("fake_site")
    module.httpx = httpx  # type: ignore[attr-defined]
    email_deep._install_exit_shims(module)

    token = email_deep._exit_proxy.set("socks5h://exit.test:9050")
    try:
        module.httpx.AsyncClient(timeout=15.0)  # type: ignore[attr-defined]
        module.httpx.AsyncClient(proxy=None)  # type: ignore[attr-defined]
        module.httpx.AsyncClient(proxy="http://own.test:8080")  # type: ignore[attr-defined]
    finally:
        email_deep._exit_proxy.reset(token)

    assert [kw["proxy"] for kw in built] == [
        "socks5h://exit.test:9050",
        "socks5h://exit.test:9050",
        "http://own.test:8080",
    ]
    # Everything else still resolves to the real library.
    assert module.httpx.TimeoutException is httpx.TimeoutException  # type: ignore[attr-defined]


def test_canary_is_made_up_at_the_same_domain() -> None:
    a = email_deep._canary_email("someone@pm.me")
    b = email_deep._canary_email("someone@pm.me")

    assert a.endswith("@pm.me") and b.endswith("@pm.me")
    assert a != b
    assert not a.startswith("someone@")


@pytest.mark.asyncio
async def test_user_scanner_results_map_to_hits(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    target = "alice@example.test"
    probes = [
        _us_probe(
            "taken",
            lambda e: Result.taken(url="https://taken.test", extra={"login_method": "SSO"})
            if e == target
            else Result.available(url="https://taken.test"),
        ),
        _us_probe("free", lambda e: Result.available(url="https://free.test")),
        _us_probe("broken", lambda e: Result.error("Unexpected response body")),
        _us_probe("crashy", lambda e: 1 / 0),
    ]
    monkeypatch.setattr(email_deep, "_load_modules", lambda: probes)

    hits = await email_deep.deep_email_probes(target, show_progress=False, retry=False)

    by_name = {hit.source: hit for hit in hits}
    taken = by_name["taken"]
    assert taken.status is Status.FOUND
    assert taken.url == "https://taken.test"
    assert taken.summary == "login method: SSO"
    assert taken.extra["backend"] == "user-scanner"
    assert taken.extra["canary"]["status"] == "not_found"
    assert taken.category == "deep/social"
    assert by_name["free"].status is Status.NOT_FOUND
    assert by_name["broken"].status is Status.ERROR
    assert by_name["broken"].error == "Unexpected response body"
    assert by_name["crashy"].status is Status.ERROR
    assert "ZeroDivisionError" in (by_name["crashy"].error or "")


@pytest.mark.asyncio
async def test_rate_limited_user_scanner_probe_is_retried(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    answers = iter([Result.error("Rate limited (429)"), Result.taken(url="https://slow.test")])
    slow = _us_probe("slow", lambda e: next(answers) if e == "alice@example.test" else Result.available())
    monkeypatch.setattr(email_deep, "_load_modules", lambda: [slow])

    hits = await email_deep.deep_email_probes(
        "alice@example.test", show_progress=False, retry_wait=0
    )

    assert hits[0].status is Status.FOUND
    assert slow.fn.calls[:2] == ["alice@example.test", "alice@example.test"]


@pytest.mark.asyncio
async def test_canary_downgrades_site_that_finds_any_address(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    target = "alice@example.test"
    always = _holehe_probe("always", {"*"})
    strict = _holehe_probe("strict", {target})
    missing = _holehe_probe("missing", set())
    us_always = _us_probe("us_always", lambda e: Result.taken())
    monkeypatch.setattr(
        email_deep, "_load_modules", lambda: [always, strict, missing, us_always]
    )

    hits = await email_deep.deep_email_probes(target, show_progress=False, retry=False)

    by_name = {hit.source: hit for hit in hits}
    for name in ("always", "us_always"):
        assert by_name[name].status is Status.UNKNOWN
        assert "made-up address" in (by_name[name].summary or "")
        assert by_name[name].extra["canary"]["status"] == "found"
    assert by_name["strict"].status is Status.FOUND
    assert by_name["strict"].extra["canary"]["status"] == "not_found"
    assert by_name["strict"].extra["backend"] == "holehe"
    canary = by_name["strict"].extra["canary"]["email"]
    assert canary.endswith("@example.test") and canary != target
    # Only FOUND sites are re-probed.
    assert missing.fn.calls == [target]
    assert by_name["missing"].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_no_verify_keeps_hits_and_skips_the_canary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    always = _holehe_probe("always", {"*"})
    monkeypatch.setattr(email_deep, "_load_modules", lambda: [always])

    hits = await email_deep.deep_email_probes(
        "alice@example.test", show_progress=False, retry=False, verify=False
    )

    assert hits[0].status is Status.FOUND
    assert "canary" not in hits[0].extra
    assert always.fn.calls == ["alice@example.test"]
