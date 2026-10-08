# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deep email search — probes sites' sign-up and sign-in lookups to discover
which have an account registered to an email.

Two backends, both audited on 2026-10-08 against addresses the operator owns
plus made-up ones:

- [user-scanner](https://github.com/kaifcodec/user-scanner) 1.5.2.1 (MIT):
  99 of its 211 email modules (docs/USER_SCANNER_AUDIT.md). Each module is an
  `async validate_<site>(email) -> Result` that builds its own HTTP client.
- holehe 1.61: only the audited modules for sites user-scanner lacks
  (docs/HOLEHE_AUDIT.md). Each module is `async fn(email, client, out)` and
  appends a dict with an `exists` flag to `out`.

Every probe becomes one Hit, and every "found" site is re-probed with a
made-up address at the same domain; sites that "find" that too are
downgraded to unknown.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import secrets
import string
import sys
import time
import types
from dataclasses import dataclass
from typing import Any

import httpx
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..core.output import console
from ..core.result import Hit, Status

# user-scanner is pinned to the audited release: a new release can change what
# a module sends, so bump it only after re-running the audit. Its modules were
# read before anything ran; only quiet lookups (availability checks, sign-in
# method lookups, sign-up form validators) are listed below. Anything that
# sends a reset, OTP or login link, signs in with a password, or submits a
# sign-up is never run, even if a later release repairs it. Modules missing
# from this allowlist (new ones included) never run.
USER_SCANNER_MODULES: dict[str, str] = {
    "adobe": "creator.adobe",
    "aljazeera": "news.aljazeera",
    "allen": "learning.allen",
    "alza.at": "shopping.alza_at",
    "alza.cz": "shopping.alza_cz",
    "alza.de": "shopping.alza_de",
    "alza.hu": "shopping.alza_hu",
    "alza.sk": "shopping.alza_sk",
    "anydo": "other.anydo",
    "appletv": "entertainment.appletv",
    "aslbloom": "learning.aslbloom",
    "atlassian": "dev.atlassian",
    "axonaut": "crm.axonaut",
    "bbc": "news.bbc",
    "cakeapp": "learning.cakeapp",
    "canva": "creator.canva",
    "chess.com": "gaming.chess_com",
    "classdojo": "learning.classdojo",
    "codecademy": "dev.codecademy",
    "codepen": "dev.codepen",
    "coursera": "learning.coursera",
    "crazygames": "gaming.crazygames",
    "deezer": "music.deezer",
    "dirbam": "jobs.dirbam",
    "dropbox": "other.dropbox",
    "duolingo": "learning.duolingo",
    "envato": "dev.envato",
    "espn": "sports.espn",
    "etsy": "shopping.etsy",
    "eventbrite": "other.eventbrite",
    "faproulette": "adult.faproulette",
    "femometer": "women_health.femometer",
    "figma": "creator.figma",
    "fitnessblender": "fitness.fitnessblender",
    "flipboard": "news.flipboard",
    "foxnews": "news.foxnews",
    "freelancer": "jobs.freelancer",
    "gaana": "music.gaana",
    "glow": "women_health.glow",
    "gravatar": "social.gravatar",
    "hackerrank": "dev.hackerrank",
    "hackthebox": "dev.hackthebox",
    "howtogeek": "dev.howtogeek",
    "huggingface": "dev.huggingface",
    "indiatimes": "news.indiatimes",
    "insightly": "crm.insightly",
    "instagram": "social.instagram",
    "jiosaavn": "music.jiosaavn",
    "justwatch": "entertainment.justwatch",
    "kandideeri": "jobs.kandideeri",
    "kick": "creator.kick",
    "lingq": "learning.lingq",
    "locket": "social.locket",
    "lovenudge": "social.lovenudge",
    "marca": "sports.marca",
    "medal": "gaming.medal",
    "meetyou": "women_health.meetyou",
    "mewe": "social.mewe",
    "moz": "other.moz",
    "myanimelist": "entertainment.myanimelist",
    "myfitnesspal": "fitness.myfitnesspal",
    "myperiodtracker": "women_health.myperiodtracker",
    "naturabuy": "shopping.naturabuy",
    "nba": "sports.nba",
    "neocities": "hosting.neocities",
    "nykaaman": "shopping.nykaaman",
    "okcupid": "dating.okcupid",
    "otsintood": "jobs.otsintood",
    "pinterest": "social.pinterest",
    "playtomic": "sports.playtomic",
    "plurk": "social.plurk",
    "polarsteps": "travel.polarsteps",
    "quizlet": "learning.quizlet",
    "quora": "community.quora",
    "rappi": "shopping.rappi",
    "redtube": "adult.redtube",
    "secondline": "other.secondline",
    "skout": "dating.skout",
    "skyscanner": "travel.skyscanner",
    "speak": "learning.speak",
    "spotify": "music.spotify",
    "start.me": "other.start_me",
    "sunnxt": "entertainment.sunnxt",
    "superporn": "adult.superporn",
    "tatacliq": "shopping.tatacliq",
    "tindie": "shopping.tindie",
    "tube8": "adult.tube8",
    "tumblr": "social.tumblr",
    "visidarbi": "jobs.visidarbi",
    "walmart": "shopping.walmart",
    "wisio": "creator.wisio",
    "wix": "dev.wix",
    "wondershare": "dev.wondershare",
    "wordpress": "dev.wordpress",
    "x": "social.x",
    "xnxx": "adult.xnxx",
    "xvideos": "adult.xvideos",
    "youporn": "adult.youporn",
    "zoho": "crm.zoho",
}

# Never run: modules user-scanner itself flags as loud, vedantu (which this
# audit caught answering "emailSent": true), and modules that sign in with a
# password, submit a sign-up or start a recovery flow.
NOTIFYING_USER_SCANNER_MODULES: dict[str, str] = {
    "addictinggames": "submits a registration with a valid password; only a reused username stops it",
    "aiscore": "submits a registration with a valid password; a free address gets a registration token back",
    "alison": "submits a registration with a blank password",
    "ama": "loud upstream: resetPassword sends a reset email",
    "amazon": "submits the sign-in email step; the newer /ax/claim flow can mail a one-time code (and it reads any captcha as registered)",
    "anilist": "calls the ResetPassword GraphQL mutation",
    "asafeer": "loud upstream: forgotPass sends a reset email",
    "babbel": "submits a registration with a blank password",
    "babestation": "loud upstream: sends a username-reminder email",
    "besoccer": "submits a registration with a blank password (BeSoccer)",
    "bnrlanguages": "loud upstream: Firebase getOobConfirmationCode sends a reset email",
    "bunny": "submits a registration (password fails policy)",
    "bunpo": "loud upstream: Firebase getOobConfirmationCode sends a reset email",
    "buymeacoffee": "loud upstream: email login sends an OTP",
    "cambly": "loud upstream: forgotPassword sends a reset email",
    "classmates": "submits a sign-in with a wrong password",
    "cnn": "creates an identity with a password (registration request)",
    "codewars": "submits a sign-up with blank username/password",
    "couplejoy": "loud upstream: reset-password sends a reset email",
    "cv.ee": "loud upstream: forgot-password sends a reset email",
    "cv.lv": "loud upstream: forgot-password sends a reset email",
    "cvkeskus": "loud upstream: sends a username reminder",
    "cvmarket.lt": "loud upstream: sends a username reminder",
    "cvmarket.lv": "loud upstream: sends a username reminder",
    "cvonline.lt": "loud upstream: forgot-password sends a reset email",
    "deviantart": "submits a sign-up with a blank password",
    "devrant": "submits a registration with a blank username",
    "disqus": "submits a sign-up with a blank password",
    "dollarfix": "submits a sign-in with a wrong password",
    "dragongroot": "loud upstream: sends a sign-up OTP to free addresses",
    "dreame": "submits a sign-in with a wrong password",
    "duocards": "loud upstream: may send a login link to passwordless accounts",
    "evolveyou": "submits a sign-in with a wrong password",
    "facebook": "first step of the account-recovery flow (identify)",
    "fantasia": "loud upstream: sends a sign-in code",
    "fapfolder": "submits a sign-up (password \"1\")",
    "finch": "loud upstream: Firebase getOobConfirmationCode sends a reset email",
    "fixderma": "Shopify customerCreate: for a guest-checkout address Shopify mails an account-activation link",
    "flickr": "Cognito SignUp with a valid password; only the PreSignUp hook stops account creation",
    "flipkart": "loud upstream: login identity verify",
    "flirtbate": "loud upstream: sends a password-reset email",
    "girlslife": "submits a registration with a blank password",
    "globaltimes": "submits a sign-in with a wrong password; the site counts failures toward a lockout",
    "gumroad": "submits a sign-up (3-character password)",
    "hackerearth": "submits a sign-up with a blank password",
    "hackerone": "submits a sign-up with mismatched passwords",
    "hanzii": "loud upstream: password/reset sends a reset email",
    "hautesauce": "Shopify customerCreate: for a guest-checkout address Shopify mails an account-activation link",
    "hellochinese": "loud upstream: forget_password sends a reset email",
    "hercul": "loud upstream: requests a password reset for registered addresses",
    "heyjapan": "loud upstream: sends a recovery code",
    "hoichoi": "loud upstream: sends a sign-in OTP",
    "hubspot": "submits a sign-in with a blank password",
    "iyoni": "Firebase verifyPassword with a wrong password (failed sign-in)",
    "jetpunk": "loud upstream: sends a password-reset email",
    "jobs.cz": "loud upstream: password-reset form sends a link",
    "komoot": "advances the sign-in flow; Komoot can mail a sign-in link",
    "leanpub": "submits a sign-up with a book (1-character password)",
    "lespark": "submits a sign-in with a wrong password",
    "letsporn": "submits a sign-up (mismatched passwords)",
    "letterboxd": "submits a registration with a valid password (empty captcha)",
    "linga": "loud upstream: recovery sends an email",
    "locanto": "register_attempt: sign-up starts from the address alone and may mail a registration link",
    "lovescape": "submits a full sign-up with a valid password; only a reused username stops it",
    "luarocks": "loud upstream: forgot-password sends a reset link",
    "made.porn": "loud upstream: change-password endpoint emails a reset link",
    "mastodon": "submits a full registration with a valid password; only a reused username stops it",
    "medium": "loud upstream: sends a login code",
    "meeff": "submits a sign-in with a blank password",
    "memrise": "loud upstream: password-reset form sends a link",
    "mixcloud": "submits a registration with a blank password",
    "mondly": "submits a sign-in with a wrong password",
    "nebula.tv": "submits a registration (1-character password)",
    "netflix": "loud upstream: starts the sign-up journey",
    "nextdoor": "password grant with a wrong password (failed sign-in)",
    "numsify": "submits a registration (password fails policy)",
    "patreon": "first step of the login flow; passwordless accounts may be sent a sign-in code",
    "payhip": "loud upstream: forgot-password sends a reset email",
    "pornhub": "module notes the check mails the account holder for the plain address; probes a +tag alias instead",
    "premom": "submits a sign-up with a valid password; only a missing first name stops it",
    "programminghub": "loud upstream: recover/initiate sends a recovery email",
    "pulser": "loud upstream: requests a password reset",
    "qiita": "submits a registration with a valid password (empty captcha); reports \"available\" for anything else",
    "rubygems": "submits a sign-up with a blank password",
    "screener": "submits a registration with a blank password",
    "sexvid": "loud upstream: reset-password flow mails a new password",
    "slowly": "loud upstream: sends an email passcode",
    "speakly": "loud upstream: password reset sends an email",
    "stackb": "submits a sign-in with a wrong password",
    "stackoverflow": "submits a sign-in with a wrong password",
    "stremio": "submits a sign-in with a wrong password",
    "superlive": "loud upstream: sends a password-renewal code",
    "sweat": "Auth0 password grant with a wrong password (Auth0 can mail a lockout notice)",
    "talkme": "submits a sign-in with a wrong password",
    "talkpal": "loud upstream: recovery-request sends a reset email",
    "thegay": "submits a sign-up (no captcha token)",
    "uniscore": "loud upstream: forgot-password sends a magic link",
    "vedantu": "preLoginVerification answers \"emailSent\":true,\"smsSent\":true for every address: it sends a login code (found in this audit; ran once per audit address before the response was read)",
    "vivino": "submits a sign-in with a wrong password",
    "weawow": "loud upstream: password-reset form sends a link",
    "weverse": "loud upstream: opens a password-reset OTP session",
    "whering": "Firebase verifyPassword with a wrong password (failed sign-in)",
    "womanlog": "submits a sign-in with a wrong password",
    "xda": "newsletter form's check-user-exists called with subscribe=true",
}

# Sites that "find" made-up addresses or never answer from any exit tested
# (the Proton exit, Tor and a residential line).
BROKEN_USER_SCANNER_MODULES: dict[str, str] = {
    "annaabi": "Cloudflare challenge from every exit",
    "emirates": "times out from every exit",
    "firefox": "account-status API answers 406",
    "github": "sign-up check behind DataDome from every exit (the user-search half only sees public profile emails)",
    "nytimes": "DataDome 403 from every exit",
    "office365": "always true for @outlook.com: Autodiscover answers 200 for any consumer Microsoft address",
    "threadless": "Cloudflare 403 on the check from every exit",
    "vimeo": "captcha challenge from every exit",
}


# Every holehe 1.61 module was audited on 2026-10-08 (roadmap #6): each ran
# against two addresses the operator owns plus made-up ones, from the VM's
# Proton exit, Tor and a residential line; the raw HTTP exchanges were read
# to tell a real "not registered" answer from holehe's silent fall-through to
# `exists: False`. Modules below are skipped. Reassess when holehe (or a
# replacement) ships an update; the per-module table is docs/HOLEHE_AUDIT.md.

# Probes that could alert the address owner: they submit a password, create or
# start an account, or walk a password-reset flow. Never run these, even if a
# future holehe release repairs them.
NOTIFYING_HOLEHE_MODULES: dict[str, str] = {
    "adobe": "password-recovery challenge flow; existing accounts fail there and read as rate-limited",
    "aboutme": "posts a sign-up form (endpoint now 302 -> 404)",
    "devrant": "posts a registration (rejected for the blank username before the email is checked)",
    "discord": "posts a full registration with consent; only the missing date of birth stops it",
    "docker": "posts a sign-up (endpoint 404)",
    "hubspot": "submits a sign-in with a blank password",
    "mail_ru": "password-restore endpoint (and posts the literal text '{email}', so never finds anything)",
    "nutshell": "submits a sign-in with a wrong password (now refused: 'disable your adblocker')",
    "odnoklassniki": "password-recovery flow (the address no longer reaches the recovery page: always false)",
    "parler": "submits a sign-in with a wrong password (API redirects to the app: always false)",
    "pipedrive": "starts a sign-up for addresses that are free (Cloudflare 403 from every exit)",
    "samsung": "walks the resetPassword flow",
    "seoclerks": "submits a full sign-up (refused on captcha: always false)",
    "sevencups": "posts to CreateAccount.php (CloudFront 403)",
    "venmo": "posts a new-user record (crashes on an undefined name first)",
    "vivino": "submits a sign-in with a wrong password (CSRF token fetched from tunefind.com: never works)",
}

# Permanently broken from every exit tested: stale endpoints, dead domains,
# changed sign-up flows, answers that say "not registered" for everything, or
# bot walls that block the VPN, Tor and a residential IP alike.
BROKEN_HOLEHE_MODULES: dict[str, str] = {
    # always "registered"
    "protonmail": "always true: Proton's key server returns a key for made-up Proton-domain addresses",
    # say "not registered" whatever the input
    "amazon": "sign-in POST answers 404: always false",
    "archive": "sign-up check redirects to /signup: always false",
    "armurerieauxerre": "endpoint answers 410 Gone: always false",
    "biotechnologyforums": "MyBB 'authorization code mismatch': always false",
    "blitzortung": "availability check redirects to the forum index: always false",
    "caringbridge": "sign-in POST answers 405: always false",
    "dominosfr": "Akamai 403 read as not registered: always false",
    "envato": "Cloudflare 403 read as not registered: always false",
    "fanpop": "registration closed ('currently unavailable'): always false",
    "flickr": "identity API answers 'cognito error': always false",
    "laposte": "endpoint 404: always false",
    "mybb": "availability check returns the HTML forum page: always false",
    "ndemiccreations": "availability check returns an empty body: always false",
    "taringa": "availability API returns the HTML app shell: always false",
    "tellonym": "API wants a token (403 TOKEN_INVALID): always false",
    # error out, or report every input as rate-limited
    "amocrm": "moved to kommo.com; the check answers 405",
    "atlassian": "login page no longer carries the CSRF token",
    "badeggsonline": "forum answers with PHP warnings instead of a token",
    "bitmoji": "Snapchat's login page changed (v2); token not found",
    "blip": "consistently times out",
    "buymeacoffee": "AttributeError on the response shape",
    "chinaphonearena": "DNS gone",
    "cpahero": "TLS certificate no longer matches the host",
    "cracked_to": "DNS gone",
    "crevado": "site answers 404; IndexError",
    "deliveroo": "DNS gone",
    "ello": "Cloudflare 520 (Ello shut down)",
    "evernote": "login moved to accounts.evernote.com; IndexError",
    "firefox": "account-status API answers 406",
    "freiberg": "forum 404",
    "garmin": "sign-up token missing from the page",
    "github": "sign-up page 403s; IndexError",
    "google": "sign-up moved to the lifecycle flow; token not found",
    "imgur": "email check answers 406/403",
    "instagram": "sign-up page no longer carries the CSRF token",
    "issuu": "check endpoint 503 (no_route)",
    "komoot": "sign-in endpoint 404",
    "nattyornot": "DNS gone",
    "nike": "DNS gone (unite.nike.com)",
    "nocrm": "check endpoint 404",
    "patreon": "email-available API 404",
    "pinterest": "EmailExistsResource 403; JSONDecodeError",
    "pornhub": "check endpoint 404/410",
    "rocketreach": "validateEmail 404; KeyError",
    "snapchat": "login page changed (v2); IndexError",
    "soundcloud": "client id no longer scrapeable; IndexError",
    "strava": "email_unique endpoint 404",
    "teamleader": "availability API returns the HTML app shell",
    "thevapingforum": "domain for sale",
    "tumblr": "API token no longer found in the page",
    "tunefind": "join page 404",
    "voxmedia": "Fastly 'unknown domain'",
    "xing": "sign-up page 404",
    "yahoo": "login page no longer carries acrumb; times out over Tor",
    # bot walls on the Proton exit, Tor and a residential line alike
    "babeshows": "Cloudflare challenge from every exit",
    "blablacar": "DataDome captcha from every exit",
    "blackworldforum": "403 'forbidden by administrative rules' from every exit",
    "bluegrassrivals": "Cloudflare 403 from every exit",
    "cambridgemt": "Cloudflare challenge from every exit",
    "codecademy": "bot check (/errors/browser) from every exit",
    "codeigniter": "Cloudflare challenge from every exit",
    "codepen": "Cloudflare challenge from every exit",
    "cpaelites": "Cloudflare 403 from every exit",
    "demonforums": "Cloudflare challenge from every exit",
    "ebay": "Distil / 403 bot wall from every exit",
    "nimble": "Cloudflare challenge from every exit",
    "quora": "Cloudflare challenge from every exit",
    "smule": "Cloudflare challenge on most requests from every exit",
    "therianguide": "429 'you're a spambot' from every exit",
    "vrbo": "429 'Bot or Not?' from every exit",
    "vsco": "Cloudflare 403 from every exit",
}

SKIPPED_HOLEHE_MODULES: frozenset[str] = frozenset(NOTIFYING_HOLEHE_MODULES) | frozenset(
    BROKEN_HOLEHE_MODULES
)

# holehe modules for sites user-scanner covers: user-scanner runs them instead.
HOLEHE_REPLACED_BY_USER_SCANNER: dict[str, str] = {
    "anydo": "anydo",
    "axonaut": "axonaut",
    "eventbrite": "eventbrite",
    "freelancer": "freelancer",
    "gravatar": "gravatar",
    "insightly": "insightly",
    "naturabuy": "naturabuy",
    "plurk": "plurk",
    "redtube": "redtube",
    "spotify": "spotify",
    "twitter": "x",
    "wordpress": "wordpress",
    "xnxx": "xnxx",
    "xvideos": "xvideos",
    "zoho": "zoho",
}



SKIPPED_USER_SCANNER_MODULES: frozenset[str] = frozenset(
    NOTIFYING_USER_SCANNER_MODULES
) | frozenset(BROKEN_USER_SCANNER_MODULES)


@dataclass(frozen=True)
class DeepProbe:
    backend: str  # "user-scanner" or "holehe"
    category: str
    name: str
    fn: Any


# user-scanner modules build their own clients, so the exit for the current
# run reaches them through this variable (asyncio tasks and to_thread workers
# inherit it).
_exit_proxy: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "deep_exit_proxy", default=None
)


def _exit_async_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
    if kwargs.get("proxy") is None:
        kwargs["proxy"] = _exit_proxy.get()
    return httpx.AsyncClient(*args, **kwargs)


class _ModuleShim(types.ModuleType):
    """Stands in for a library inside user-scanner modules, forwarding
    everything except the client constructors it overrides."""

    def __init__(self, wrapped: types.ModuleType, **overrides: Any) -> None:
        super().__init__(wrapped.__name__)
        self._wrapped = wrapped
        self.__dict__.update(overrides)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


def _install_exit_shims(module: types.ModuleType) -> None:
    """Route a user-scanner module's own clients through recce's exit instead
    of user-scanner's global proxy file. Its email orchestrator would patch
    httpx process-wide, so it is never imported."""
    from curl_cffi import requests as curl_requests

    if getattr(module, "httpx", None) is httpx:
        module.httpx = _ModuleShim(httpx, AsyncClient=_exit_async_client)  # type: ignore[attr-defined]
    if getattr(module, "requests", None) is curl_requests:

        def session(*args: Any, **kwargs: Any) -> Any:
            proxy = _exit_proxy.get()
            if proxy and not kwargs.get("proxies"):
                kwargs["proxies"] = {"http": proxy, "https": proxy}
            return curl_requests.Session(*args, **kwargs)

        module.requests = _ModuleShim(curl_requests, Session=session)  # type: ignore[attr-defined]


def _load_user_scanner() -> list[DeepProbe]:
    import user_scanner.core.impersonate as impersonate

    # Its shared browser-impersonating sessions are keyed by this proxy.
    impersonate.get_proxy = _exit_proxy.get  # type: ignore[attr-defined]
    out: list[DeepProbe] = []
    for name, path in USER_SCANNER_MODULES.items():
        # rappi only reaches its loud login step when the process was started
        # with user-scanner's --allow-loud flag.
        if name == "rappi" and "--allow-loud" in sys.argv:
            continue
        module = importlib.import_module(f"user_scanner.email_scan.{path}")
        _install_exit_shims(module)
        fn = next(getattr(module, attr) for attr in dir(module) if attr.startswith("validate_"))
        out.append(DeepProbe("user-scanner", path.split(".")[0], name, fn))
    return out


def _load_holehe() -> list[DeepProbe]:
    import holehe.modules as root
    from holehe.core import import_submodules

    skipped = SKIPPED_HOLEHE_MODULES | frozenset(HOLEHE_REPLACED_BY_USER_SCANNER)
    out: list[DeepProbe] = []
    for module_path, module in import_submodules(root).items():
        parts = module_path.split(".")
        if len(parts) < 4:
            continue
        site_name = parts[-1]
        if site_name in skipped:
            continue
        fn = getattr(module, site_name, None)
        if fn is None or not callable(fn):
            continue
        out.append(DeepProbe("holehe", parts[2], site_name, fn))
    return out


def _load_modules() -> list[DeepProbe]:
    """Every audited probe: the user-scanner allowlist, then holehe's
    remaining modules for sites user-scanner lacks."""
    return _load_user_scanner() + _load_holehe()


def _holehe_to_hit(probe: DeepProbe, raw: dict[str, Any], elapsed_ms: int) -> Hit:
    category = f"deep/{probe.category}"
    url = f"https://{raw.get('domain', '')}"
    if raw.get("rateLimit"):
        return Hit(
            source=probe.name,
            category=category,
            status=Status.SKIPPED,
            url=url,
            summary="rate-limited",
            elapsed_ms=elapsed_ms,
        )
    exists = raw.get("exists")
    if exists is True:
        bits = []
        if raw.get("emailrecovery"):
            bits.append(f"recovery hint: {raw['emailrecovery']}")
        if raw.get("phoneNumber"):
            bits.append(f"recovery phone: {raw['phoneNumber']}")
        if raw.get("others"):
            bits.append(f"other: {raw['others']}")
        summary = " · ".join(bits) if bits else "account registered"
        return Hit(
            source=probe.name,
            category=category,
            status=Status.FOUND,
            url=url,
            summary=summary,
            extra={
                "backend": "holehe",
                **{k: v for k, v in raw.items() if k not in {"name", "domain"}},
            },
            confidence=0.85,
            elapsed_ms=elapsed_ms,
        )
    if exists is False:
        return Hit(
            source=probe.name,
            category=category,
            status=Status.NOT_FOUND,
            url=url,
            elapsed_ms=elapsed_ms,
        )
    return Hit(
        source=probe.name,
        category=category,
        status=Status.UNKNOWN,
        url=url,
        summary="probe inconclusive",
        elapsed_ms=elapsed_ms,
    )


def _user_scanner_to_hit(probe: DeepProbe, result: Any, elapsed_ms: int) -> Hit:
    """Map a user-scanner Result (status TAKEN / AVAILABLE / ERROR / SKIPPED)."""
    category = f"deep/{probe.category}"
    status = getattr(result.status, "name", "")
    url = getattr(result, "url", "") or None
    reason = str(result.reason or "")
    if status == "TAKEN":
        details: dict[str, Any] = dict(result.extra or {})
        bits = [f"{key.replace('_', ' ')}: {value}" for key, value in details.items()]
        # rappi's reason only advertises user-scanner's --allow-loud flag.
        if reason and "allow-loud" not in reason:
            bits.append(reason)
        if getattr(result, "media", None):
            details["media"] = dict(result.media)
        return Hit(
            source=probe.name,
            category=category,
            status=Status.FOUND,
            url=url,
            summary=" · ".join(bits) if bits else "account registered",
            extra={"backend": "user-scanner", **details},
            confidence=0.85,
            elapsed_ms=elapsed_ms,
        )
    if status == "AVAILABLE":
        return Hit(
            source=probe.name,
            category=category,
            status=Status.NOT_FOUND,
            url=url,
            elapsed_ms=elapsed_ms,
        )
    if status == "ERROR" and ("rate limit" in reason.lower() or "429" in reason):
        return Hit(
            source=probe.name,
            category=category,
            status=Status.SKIPPED,
            url=url,
            summary="rate-limited",
            elapsed_ms=elapsed_ms,
        )
    if status == "ERROR":
        return Hit(
            source=probe.name,
            category=category,
            status=Status.ERROR,
            url=url,
            error=reason[:140] or "probe failed",
            elapsed_ms=elapsed_ms,
        )
    return Hit(
        source=probe.name,
        category=category,
        status=Status.UNKNOWN,
        url=url,
        summary=reason or "probe inconclusive",
        elapsed_ms=elapsed_ms,
    )


async def _run_one(
    probe: DeepProbe,
    email: str,
    client: httpx.AsyncClient,
    per_module_timeout: float,
) -> Hit:
    started = time.perf_counter()
    category = f"deep/{probe.category}"
    out: list[dict[str, Any]] = []
    result: Any = None
    try:
        if probe.backend == "holehe":
            await asyncio.wait_for(probe.fn(email, client, out), timeout=per_module_timeout)
        else:
            # user-scanner modules make up to three sequential requests (page,
            # token, check), each with its own 15s timeout.
            result = await asyncio.wait_for(
                probe.fn(email), timeout=max(per_module_timeout * 2, 30.0)
            )
    except asyncio.TimeoutError:
        return Hit(
            source=probe.name,
            category=category,
            status=Status.SKIPPED,
            summary="timed out",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    except Exception as e:
        return Hit(
            source=probe.name,
            category=category,
            status=Status.ERROR,
            error=f"{type(e).__name__}: {e}"[:140],
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if probe.backend != "holehe":
        return _user_scanner_to_hit(probe, result, elapsed_ms)
    if not out:
        return Hit(
            source=probe.name,
            category=category,
            status=Status.UNKNOWN,
            summary="probe returned no result",
            elapsed_ms=elapsed_ms,
        )
    return _holehe_to_hit(probe, out[0], elapsed_ms)


def _is_rate_limited(hit: Hit) -> bool:
    return hit.status is Status.SKIPPED and "rate" in (hit.summary or "").lower()


def _canary_email(email: str) -> str:
    """A made-up address at the target's own domain. Same domain, because some
    probes answer per domain (Proton's key server "knows" every made-up
    @pm.me address) and some sites refuse example.com outright."""
    alphabet = string.ascii_lowercase + string.digits
    local = "q" + "".join(secrets.choice(alphabet) for _ in range(15))
    domain = email.rpartition("@")[2] or "example.com"
    return f"{local}@{domain}"


async def _verify_found(
    modules: list[DeepProbe],
    hits: list[Hit],
    client: httpx.AsyncClient,
    timeout: float,
    canary: str,
) -> None:
    """Re-probe every FOUND site with a made-up address. A site that also
    "finds" the made-up one says yes to anything, so the hit is unverifiable
    and is downgraded (mirrors the username canary)."""
    by_name = {probe.name: probe for probe in modules}
    found = [hit for hit in hits if hit.status is Status.FOUND and hit.source in by_name]

    async def check(hit: Hit) -> None:
        probe = await _run_one(by_name[hit.source], canary, client, per_module_timeout=timeout)
        hit.extra["canary"] = {"email": canary, "status": probe.status.value}
        if probe.status is Status.FOUND:
            hit.status = Status.UNKNOWN
            hit.summary = "unverifiable — site also reports a made-up address as registered"
            hit.confidence = 0.2

    await asyncio.gather(*(check(hit) for hit in found))


async def deep_email_probes(
    email: str,
    *,
    timeout: float = 12.0,
    max_concurrency: int = 20,
    proxy: str | None = None,
    show_progress: bool = True,
    retry: bool = True,
    retry_wait: float = 15.0,
    verify: bool = True,
) -> list[Hit]:
    """Run every audited probe against the given email, concurrently.

    If `retry=True`, modules that came back rate-limited are retried once
    after `retry_wait` seconds — many sites' rate-limit windows are short
    enough that a brief pause turns ~half of those into real hits.

    If `verify=True`, every FOUND site is re-probed with a made-up address at
    the same domain and downgraded to unknown if it "finds" that one too.
    """
    modules = _load_modules()
    _exit_proxy.set(proxy)

    # Holehe modules expect an httpx.AsyncClient. They often set their own
    # headers per-request, so we leave the client's defaults alone.
    client_kwargs: dict[str, Any] = {"timeout": timeout, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy
    client = httpx.AsyncClient(**client_kwargs)
    sem = asyncio.Semaphore(max(1, max_concurrency))

    async def run_pass(
        targets: list[DeepProbe],
        progress_label: str,
    ) -> list[Hit]:
        async def guarded_run(probe: DeepProbe) -> Hit:
            async with sem:
                return await _run_one(probe, email, client, per_module_timeout=timeout)

        if not show_progress:
            return list(await asyncio.gather(*(guarded_run(p) for p in targets)))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[bold]{task.completed}/{task.total}[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(progress_label, total=len(targets))

            async def runner(probe: DeepProbe) -> Hit:
                hit = await guarded_run(probe)
                progress.advance(task)
                return hit

            return list(await asyncio.gather(*(runner(p) for p in targets)))

    async def retry_rate_limited(results: list[Hit]) -> None:
        rl_indices = [i for i, h in enumerate(results) if _is_rate_limited(h)]
        if not rl_indices:
            return

        retry_targets = [modules[i] for i in rl_indices]
        console.print(
            f"[dim]→ {len(retry_targets)} probes were rate-limited. "
            f"Waiting {int(retry_wait)}s and retrying once…[/]"
        )
        await asyncio.sleep(retry_wait)
        retry_results = await run_pass(
            retry_targets, f"Retrying [bold]{len(retry_targets)}[/] rate-limited probes…"
        )
        salvaged = 0
        for orig_idx, retry_hit in zip(rl_indices, retry_results, strict=True):
            if not _is_rate_limited(retry_hit) and retry_hit.status is not Status.ERROR:
                results[orig_idx] = retry_hit
                if retry_hit.is_found:
                    salvaged += 1
        if salvaged:
            console.print(
                f"[dim]→ Retry pass surfaced [bold green]{salvaged}[/] new hit(s).[/]"
            )

    try:
        results = await run_pass(
            modules, f"Probing [bold]{email}[/] across {len(modules)} sites…"
        )
        if retry:
            await retry_rate_limited(results)
        if verify:
            await _verify_found(modules, results, client, timeout, _canary_email(email))
        return results
    finally:
        await client.aclose()
