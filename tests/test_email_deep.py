# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep email (holehe) module selection and the made-up-address canary."""

from __future__ import annotations

from typing import Any

import pytest

from recce.core.result import Status
from recce.modules import email_deep


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


def _module(name: str, registered: set[str]) -> Any:
    """A fake holehe probe that says yes for the addresses in `registered`
    ("*" = every address)."""

    async def probe(email: str, client: Any, out: list[dict[str, Any]]) -> None:
        probe.calls.append(email)  # type: ignore[attr-defined]
        out.append(_holehe_result(name, "*" in registered or email in registered))

    probe.calls = []  # type: ignore[attr-defined]
    return probe


def test_notifying_and_broken_modules_are_never_loaded() -> None:
    names = {name for _cat, name, _fn in email_deep._load_modules()}

    assert names
    assert not names & set(email_deep.NOTIFYING_HOLEHE_MODULES)
    assert not names & set(email_deep.BROKEN_HOLEHE_MODULES)
    # Probes that submit a password or start a sign-up stay out even if a
    # future holehe repairs them.
    for name in ("hubspot", "nutshell", "discord", "pipedrive", "samsung", "adobe"):
        assert name in email_deep.NOTIFYING_HOLEHE_MODULES
    assert "protonmail" in email_deep.BROKEN_HOLEHE_MODULES


def test_every_skip_has_a_reason() -> None:
    for reasons in (email_deep.NOTIFYING_HOLEHE_MODULES, email_deep.BROKEN_HOLEHE_MODULES):
        assert all(reason.strip() for reason in reasons.values())
    assert not set(email_deep.NOTIFYING_HOLEHE_MODULES) & set(email_deep.BROKEN_HOLEHE_MODULES)


def test_canary_is_made_up_at_the_same_domain() -> None:
    a = email_deep._canary_email("someone@pm.me")
    b = email_deep._canary_email("someone@pm.me")

    assert a.endswith("@pm.me") and b.endswith("@pm.me")
    assert a != b
    assert not a.startswith("someone@")


@pytest.mark.asyncio
async def test_canary_downgrades_site_that_finds_any_address(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    target = "alice@example.test"
    always = _module("always", {"*"})
    strict = _module("strict", {target})
    missing = _module("missing", set())
    modules = [("social", "always", always), ("social", "strict", strict), ("social", "missing", missing)]
    monkeypatch.setattr(email_deep, "_load_modules", lambda: modules)

    hits = await email_deep.deep_email_probes(target, show_progress=False, retry=False)

    by_name = {hit.source: hit for hit in hits}
    assert by_name["always"].status is Status.UNKNOWN
    assert "made-up address" in (by_name["always"].summary or "")
    assert by_name["always"].extra["canary"]["status"] == "found"
    assert by_name["strict"].status is Status.FOUND
    assert by_name["strict"].extra["canary"]["status"] == "not_found"
    canary = by_name["strict"].extra["canary"]["email"]
    assert canary.endswith("@example.test") and canary != target
    # Only FOUND sites are re-probed.
    assert missing.calls == [target]
    assert by_name["missing"].status is Status.NOT_FOUND


@pytest.mark.asyncio
async def test_no_verify_keeps_hits_and_skips_the_canary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    always = _module("always", {"*"})
    monkeypatch.setattr(email_deep, "_load_modules", lambda: [("social", "always", always)])

    hits = await email_deep.deep_email_probes(
        "alice@example.test", show_progress=False, retry=False, verify=False
    )

    assert hits[0].status is Status.FOUND
    assert "canary" not in hits[0].extra
    assert always.calls == ["alice@example.test"]
