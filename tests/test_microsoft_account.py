# SPDX-License-Identifier: AGPL-3.0-or-later
import json

import httpx
import pytest

from recce.core.result import Status
from recce.modules import email_deep, microsoft_account
from recce.modules.microsoft_account import LoginPageError, parse_login_page, request_body, to_hit

# Shape of the real sign-in page: config JSON inside a script, so the PPFT tag
# carries escaped quotes and the URL carries &.
PAGE = (
    '<script>var ServerData = {"sFTTag":"<input type=\\"hidden\\" name=\\"PPFT\\" id=\\"i0327\\" '
    'value=\\"FLOW!token*\\"/>","urlGetCredentialType":"https://login.live.com/GetCredentialType.srf?'
    'opid=AB\\u0026uaid=c2a6","sUnauthSessionID":"c2a6a248b1f64c8b"};</script>'
)


def test_parse_login_page_reads_escaped_config() -> None:
    token, url, session = parse_login_page(PAGE)

    assert token == "FLOW!token*"
    assert url == "https://login.live.com/GetCredentialType.srf?opid=AB&uaid=c2a6"
    assert session == "c2a6a248b1f64c8b"


def test_parse_login_page_rejects_changed_layout() -> None:
    with pytest.raises(LoginPageError):
        parse_login_page("<html>Microsoft account requires JavaScript</html>")


def test_request_never_lets_the_owner_be_contacted() -> None:
    body = request_body("alice@example.test", "tok", "sid")

    assert body["username"] == "alice@example.test"
    for flag in ("isRemoteNGCSupported", "isFidoSupported", "checkPhones", "forceotclogin", "isSignup"):
        assert body[flag] is False, flag
    assert body["otclogindisallowed"] is True


def test_existing_personal_account_reports_sign_in_methods() -> None:
    data = {
        "IfExistsResult": 0,
        "Credentials": {"HasPassword": 1, "HasPhone": 1, "HasRemoteNGC": 0, "HasFido": 0, "HasGoogleFed": 1, "PrefCredential": 1},
    }

    hit = to_hit("alice@example.test", data)

    assert hit.status is Status.FOUND
    assert hit.summary == "personal Microsoft account · sign-in: password, phone · linked sign-in: Google"
    assert hit.extra["sign_in_methods"] == ["password", "phone"]
    assert hit.extra["backend"] == "recce"


@pytest.mark.parametrize(
    ("data", "status", "text"),
    [
        ({"IfExistsResult": 1}, Status.NOT_FOUND, None),
        ({"IfExistsResult": 5, "Credentials": {}}, Status.FOUND, "work or school account"),
        ({"IfExistsResult": 0, "ThrottleStatus": 1}, Status.SKIPPED, "rate-limited"),
        ({"IfExistsResult": 4}, Status.UNKNOWN, "unexpected IfExistsResult 4"),
    ],
)
def test_if_exists_result_mapping(data, status, text) -> None:  # type: ignore[no-untyped-def]
    hit = to_hit("alice@example.test", data)
    assert hit.status is status
    if text:
        assert text in (hit.summary or "")


@pytest.mark.asyncio
async def test_check_runs_page_then_username_step_through_the_exit(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    posted: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login.srf":
            return httpx.Response(200, text=PAGE)
        posted.append(json.loads(request.content))
        known = posted[-1]["username"] == "alice@example.test"
        return httpx.Response(200, json={"IfExistsResult": 0 if known else 1, "Credentials": {"HasPassword": 1}})

    built: list[dict] = []
    real = httpx.AsyncClient

    def client(**kwargs):  # type: ignore[no-untyped-def]
        built.append(dict(kwargs))
        kwargs.pop("proxy", None)
        return real(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(microsoft_account.httpx, "AsyncClient", client)

    found = await microsoft_account.check("alice@example.test", proxy="socks5://exit.test:1")
    missing = await microsoft_account.check("nobody@example.test")

    assert found.status is Status.FOUND and missing.status is Status.NOT_FOUND
    assert posted[0]["flowToken"] == "FLOW!token*" and posted[0]["uaid"] == "c2a6a248b1f64c8b"
    assert built[0]["proxy"] == "socks5://exit.test:1"


@pytest.mark.asyncio
async def test_deep_mode_runs_the_microsoft_check_with_canary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[str] = []

    async def fake_check(email: str, *, proxy=None, timeout=20.0):  # type: ignore[no-untyped-def]
        calls.append(email)
        return to_hit(email, {"IfExistsResult": 0 if email == "alice@example.test" else 1, "Credentials": {}})

    monkeypatch.setattr(microsoft_account, "check", fake_check)
    monkeypatch.setattr(email_deep, "_load_modules", email_deep._load_recce)

    [hit] = await email_deep.deep_email_probes("alice@example.test", show_progress=False, retry=False)

    assert hit.source == "microsoft" and hit.status is Status.FOUND
    assert hit.extra["canary"]["status"] == "not_found"
    assert calls[0] == "alice@example.test" and calls[1].endswith("@example.test") and calls[1] != calls[0]
