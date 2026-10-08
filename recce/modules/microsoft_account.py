# SPDX-License-Identifier: AGPL-3.0-or-later
"""Microsoft personal-account existence, via the sign-in page's username step.

`login.live.com/GetCredentialType.srf` is what the Microsoft sign-in page
calls after you type an address and before any password. Its
`IfExistsResult` tells whether a Microsoft account uses that address (any
domain -- a Microsoft account can be registered on a Gmail address), and its
`Credentials` block says how the account signs in.

Nothing reaches the account owner: every option that could make that step
contact them -- Authenticator push (remote NGC), FIDO, phone checks, emailed
or texted one-time codes -- is switched off in the request. Live-checked on
2026-10-08 against the operator's own account: no prompt, code or email.

The AAD `login.microsoftonline.com/common/GetCredentialType` endpoint that
tools usually use is unreliable for consumer accounts (it reported a real
outlook.com account as missing), and Autodiscover answers yes for any
outlook.com address, so neither is used.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..core.result import Hit, Status

LOGIN_PAGE = "https://login.live.com/login.srf"
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"

# IfExistsResult values seen on the consumer endpoint.
EXISTS = {0: "personal Microsoft account", 5: "work or school account", 6: "personal and work/school account"}
MISSING = 1

# Sign-in methods, in the order they're worth reporting.
_METHODS = (
    ("HasPassword", "password"),
    ("HasPhone", "phone"),
    ("HasRemoteNGC", "Authenticator app"),
    ("HasFido", "security key / passkey"),
)
_FEDERATIONS = (
    ("HasGoogleFed", "Google"),
    ("HasAppleFed", "Apple"),
    ("HasGitHubFed", "GitHub"),
    ("HasLinkedInFed", "LinkedIn"),
)


class LoginPageError(RuntimeError):
    """The sign-in page didn't carry the tokens the username step needs."""


def parse_login_page(html: str) -> tuple[str, str, str]:
    """(flow token, session id, GetCredentialType URL) from the sign-in page.

    The page embeds its config as JSON inside a script, so the PPFT input tag
    appears with escaped quotes.
    """
    ppft = re.search(r'name=\\"PPFT\\"[^>]*?value=\\"([^"\\]+)\\"', html) or re.search(
        r'name="PPFT"[^>]*?value="([^"]+)"', html
    )
    url = re.search(r'"urlGetCredentialType":"([^"]+)"', html)
    session = re.search(r'"sUnauthSessionID":"([0-9a-fA-F]+)"', html)
    if not (ppft and url and session):
        raise LoginPageError("sign-in page layout changed (no flow token)")
    return ppft.group(1), json.loads(f'"{url.group(1)}"'), session.group(1)


def request_body(email: str, flow_token: str, session_id: str) -> dict[str, Any]:
    """The username-step payload with every owner-contacting option off."""
    return {
        "username": email,
        "uaid": session_id,
        "flowToken": flow_token,
        "isOtherIdpSupported": False,
        "checkPhones": False,
        "isRemoteNGCSupported": False,  # no Authenticator push
        "isFidoSupported": False,
        "isCookieBannerShown": False,
        "forceotclogin": False,
        "otclogindisallowed": True,  # never send a one-time code
        "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False,
        "federationFlags": 3,
        "isSignup": False,
    }


def to_hit(email: str, data: dict[str, Any], name: str = "microsoft", category: str = "deep/email") -> Hit:
    """Map a GetCredentialType reply to a Hit."""
    if data.get("ThrottleStatus"):
        return Hit(source=name, category=category, status=Status.SKIPPED, summary="rate-limited")
    code = data.get("IfExistsResult")
    if code == MISSING:
        return Hit(source=name, category=category, status=Status.NOT_FOUND, extra={"backend": "recce"})
    if code not in EXISTS:
        return Hit(source=name, category=category, status=Status.UNKNOWN, summary=f"unexpected IfExistsResult {code!r}")

    creds = data.get("Credentials") or {}
    methods = [label for key, label in _METHODS if creds.get(key)]
    linked = [label for key, label in _FEDERATIONS if creds.get(key)]
    parts = [EXISTS[code]]
    if methods:
        parts.append("sign-in: " + ", ".join(methods))
    if creds.get("IsPasswordDisabled"):
        parts.append("passwordless")
    if linked:
        parts.append("linked sign-in: " + ", ".join(linked))
    if data.get("AliasDisabledForLogin"):
        parts.append("this alias can't be used to sign in")
    return Hit(
        source=name,
        category=category,
        status=Status.FOUND,
        url="https://account.microsoft.com/",
        summary=" · ".join(parts),
        confidence=0.9,
        extra={
            "backend": "recce",
            "account_type": EXISTS[code],
            "if_exists_result": code,
            "sign_in_methods": methods,
            "linked_sign_in": linked,
            "passwordless": bool(creds.get("IsPasswordDisabled")),
        },
    )


async def check(email: str, *, proxy: str | None = None, timeout: float = 20.0) -> Hit:
    """Look `email` up as a Microsoft account. One sign-in page load plus one
    username-step request; nothing is sent to the account owner."""
    headers = {"User-Agent": _UA, "Accept-Language": "en-GB,en;q=0.9"}
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=timeout, headers=headers, proxy=proxy
    ) as client:
        page = await client.get(LOGIN_PAGE)
        if page.status_code != 200:
            return Hit(source="microsoft", category="deep/email", status=Status.ERROR, error=f"sign-in page HTTP {page.status_code}")
        try:
            flow_token, url, session_id = parse_login_page(page.text)
        except LoginPageError as exc:
            return Hit(source="microsoft", category="deep/email", status=Status.ERROR, error=str(exc))
        resp = await client.post(
            url,
            json=request_body(email, flow_token, session_id),
            headers={"Referer": LOGIN_PAGE, "Origin": "https://login.live.com", "hpgid": "33", "hpgact": "0"},
        )
    if resp.status_code == 429:
        return Hit(source="microsoft", category="deep/email", status=Status.SKIPPED, summary="rate-limited")
    if resp.status_code != 200:
        return Hit(source="microsoft", category="deep/email", status=Status.ERROR, error=f"HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        return Hit(source="microsoft", category="deep/email", status=Status.ERROR, error="bad json")
    return to_hit(email, data)
