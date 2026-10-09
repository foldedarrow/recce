# SPDX-License-Identifier: AGPL-3.0-or-later
"""Maigret's site database as a third username source.

[Maigret](https://github.com/soxoj/maigret) ships ``data.json``: ~8,000 site
definitions (most of them forums built on a shared engine such as XenForo or
Discourse) with three check types:

- ``status_code``   account exists iff the probe answers 2xx
- ``message``       exists iff a ``presenseStrs`` marker is in the body (or
                    there are none) and no ``absenceStrs`` marker is
- ``response_url``  redirects off; exists iff 2xx and a presence marker

This module translates those definitions into recce's site schema
(``method: "maigret"``, classified by `username._classify` with Maigret's own
rules) and leaves out what recce can't run faithfully: disabled entries,
non-username identifiers (numeric IDs), Tor/I2P/DNS checks, POST and
"activation" (session token) checks, similar-name searches, and sites whose
``regexCheck`` would reject recce's canary, which therefore can't be verified.

Every Maigret site is untrusted until `recce selftest` has checked it with its
``usernameClaimed`` account and a canary: searches only run the ones with a
fresh ``healthy`` verdict (see `selftest.maigret_verified`), unless the user
asks for ``--maigret all``.

``recce update`` refreshes ``~/.cache/recce/maigret-data.json``, which wins
over the bundled snapshot (``recce/data/maigret-data.json.xz``).

Data licence: Maigret is MIT-licensed, © Soxoj; the bundled snapshot is
unmodified upstream data and ``recce/data/MAIGRET_LICENSE`` carries the notice.
"""

from __future__ import annotations

import json
import lzma
import os
import re
import tempfile
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..core.http import HttpClient

MAIGRET_REMOTE = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json"
CACHE_DIR = Path.home() / ".cache" / "recce"
CACHED_MAIGRET = CACHE_DIR / "maigret-data.json"
BUNDLED_NAME = "maigret-data.json.xz"
SOURCE = "maigret"

# verified: only sites the last selftest found healthy; all: every importable
# site (unverified, slow); off: none.
POLICIES = ("verified", "all", "off")
POLICY_ENV = "RECCE_MAIGRET"

NSFW_CATEGORY = "xx NSFW xx"  # WMN's spelling, so `--nsfw` gates both sources
_NSFW_TAGS = {"porn", "erotic", "webcam"}
_REGION_TAGS = {"global"}
# Maigret tags most forums "discussion"; recce files them under "forum".
_TAG_ALIASES = {"discussion": "forum"}
# Shaped like `username._canary_username()`. A site whose regexCheck rejects
# this can't be canary-verified (it wants numeric IDs and the like).
_SAMPLE_CANARY = "qa1b2c3d4e5f"
_PLACEHOLDER = "recceusernameplaceholder"


def policy(value: str | None = None) -> str:
    chosen = (value or os.environ.get(POLICY_ENV) or "verified").strip().lower()
    if chosen not in POLICIES:
        raise ValueError(f"maigret policy must be one of {', '.join(POLICIES)}")
    return chosen


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------

def _with_engine(entry: dict[str, Any], engines: dict[str, Any]) -> dict[str, Any]:
    """Apply the entry's engine template the way Maigret's
    `MaigretSite.update_from_engine` does: lists concatenate, dicts merge,
    scalars fill in only where the entry doesn't state its own."""
    engine = (engines.get(entry.get("engine") or "") or {}).get("site") or {}
    merged = dict(entry)
    for key, value in engine.items():
        if isinstance(value, dict):
            merged[key] = {**(entry.get(key) or {}), **value}
        elif isinstance(value, list):
            merged[key] = list(entry.get(key) or []) + value
        elif key not in entry:
            merged[key] = value
    return merged


def _fill(template: str, entry: dict[str, Any]) -> str:
    return (
        template.replace("{urlMain}", entry.get("urlMain") or "")
        .replace("{urlSubpath}", entry.get("urlSubpath") or "")
        .replace("{username}", "{u}")
    )


def _category(tags: list[str]) -> str:
    if _NSFW_TAGS.intersection(tags):
        return NSFW_CATEGORY
    for tag in tags:
        if len(tag) != 2 and tag not in _REGION_TAGS:
            return _TAG_ALIASES.get(tag, tag)
    return "misc"


def translate(name: str, entry: dict[str, Any], engines: dict[str, Any]) -> dict[str, Any] | None:
    """One Maigret entry as a recce site definition, or None if recce can't
    run it the way Maigret would."""
    entry = _with_engine(entry, engines)
    check = entry.get("checkType")
    if entry.get("disabled") or check not in ("status_code", "message", "response_url"):
        return None
    if entry.get("type", "username") != "username" or entry.get("protocol"):
        return None
    if entry.get("activation") or entry.get("similarSearch") or entry.get("errorUrl"):
        return None
    if (entry.get("requestMethod") or "GET").upper() != "GET" or entry.get("requestPayload"):
        return None
    regex = entry.get("regexCheck")
    if regex:
        try:
            if re.search(regex, _SAMPLE_CANARY) is None:
                return None
        except re.error:
            return None
    url_template = entry.get("url")
    if not url_template:
        return None
    # Maigret's own "prevent slash errors" step, applied to the display URL.
    url = re.sub("(?<!:)/+", "/", _fill(url_template, entry))
    probe = _fill(entry["urlProbe"], entry) if entry.get("urlProbe") else url
    if "{u}" not in probe or re.search(r"\{(?!u\})", url + probe):
        return None
    if not url.startswith(("http://", "https://")) or not probe.startswith(("http://", "https://")):
        return None

    site: dict[str, Any] = {
        "name": name,
        "category": _category(entry.get("tags") or []),
        "url": url,
        "method": "maigret",
        "check": check,
        "source": SOURCE,
    }
    if probe != url:
        site["probe"] = probe
    if entry.get("presenseStrs"):
        site["presence"] = list(entry["presenseStrs"])
    if entry.get("absenceStrs"):
        site["absence"] = list(entry["absenceStrs"])
    if entry.get("errors"):
        site["errors"] = dict(entry["errors"])
    if entry.get("ignore403"):
        site["ignore403"] = True
    if check == "status_code" and entry.get("requestHeadOnly") is True:
        site["head_request"] = True
    if check == "response_url":
        site["no_redirect"] = True
    if entry.get("headers"):
        site["headers"] = dict(entry["headers"])
    if regex:
        site["regex"] = regex
    if entry.get("usernameClaimed"):
        site["known"] = [entry["usernameClaimed"]]
    return site


def translate_all(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Every importable site in a Maigret data.json, one per domain."""
    engines = data.get("engines") or {}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, entry in (data.get("sites") or {}).items():
        if not isinstance(entry, dict):
            continue
        site = translate(name, entry, engines)
        if site is None:
            continue
        domains = site_domains(site)
        if domains & seen:
            continue  # a second Maigret entry for the same site
        seen |= domains
        out.append(site)
    return out


# ---------------------------------------------------------------------------
# De-duplication against WMN / custom sites
# ---------------------------------------------------------------------------

def normalised_domain(template: str) -> str:
    """The host a URL template points at, lower-cased, without ``www.`` and
    without a username label (``{u}.tumblr.com`` -> ``tumblr.com``)."""
    host = urlparse(template.replace("{u}", _PLACEHOLDER)).hostname or ""
    labels = [label for label in host.lower().strip(".").split(".") if _PLACEHOLDER not in label]
    host = ".".join(labels)
    return host.removeprefix("www.")


def site_domains(site: dict[str, Any]) -> set[str]:
    """Normalised domains of a definition's profile URL and probe URL."""
    out = {normalised_domain(site.get("url") or "")}
    if site.get("probe"):
        out.add(normalised_domain(site["probe"]))
    out.discard("")
    return out


def merge(existing: list[dict[str, Any]], maigret_sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The Maigret sites that cover something `existing` (WMN + custom)
    doesn't: no shared normalised domain and no name clash (selftest verdicts
    are keyed by name)."""
    taken: set[str] = set()
    names = {s["name"].lower() for s in existing}
    for site in existing:
        taken |= site_domains(site)
    return [
        s for s in maigret_sites
        if s["name"].lower() not in names and not (site_domains(s) & taken)
    ]


# ---------------------------------------------------------------------------
# Loading and refresh
# ---------------------------------------------------------------------------

def _bundled_raw() -> str:
    data = resources.files("recce.data").joinpath(BUNDLED_NAME).read_bytes()
    return lzma.decompress(data).decode("utf-8")


@lru_cache(maxsize=4)
def _load(path: str, mtime: float | None) -> tuple[dict[str, Any], ...]:
    raw: str | None = None
    if mtime is not None:
        try:
            raw = Path(path).read_text()
            data = json.loads(raw)
            if not isinstance(data.get("sites"), dict):
                raw = None
        except (OSError, json.JSONDecodeError, AttributeError):
            raw = None
    if raw is None:
        data = json.loads(_bundled_raw())
    return tuple(translate_all(data))


def load_sites() -> list[dict[str, Any]]:
    """Importable Maigret sites: the refreshed cache if it parses, else the
    bundled snapshot. Callers get fresh copies they may modify."""
    try:
        mtime: float | None = CACHED_MAIGRET.stat().st_mtime
    except OSError:
        mtime = None
    return [dict(s) for s in _load(str(CACHED_MAIGRET), mtime)]


def cache_status() -> dict[str, Any]:
    if not CACHED_MAIGRET.exists():
        return {"path": str(CACHED_MAIGRET), "exists": False, "valid": None, "sites": None}
    try:
        data = json.loads(CACHED_MAIGRET.read_text())
        sites = data.get("sites")
    except (OSError, json.JSONDecodeError, AttributeError) as e:
        return {"path": str(CACHED_MAIGRET), "exists": True, "valid": False, "sites": None, "error": str(e)[:120]}
    return {
        "path": str(CACHED_MAIGRET),
        "exists": True,
        "valid": isinstance(sites, dict),
        "sites": len(sites) if isinstance(sites, dict) else None,
    }


def clear_cache() -> bool:
    if not CACHED_MAIGRET.exists():
        return False
    CACHED_MAIGRET.unlink()
    return True


async def refresh_data(client: HttpClient) -> tuple[int, int]:
    """Fetch Maigret's latest data.json into the cache. Returns the number of
    importable sites before and after."""
    before = len(load_sites())
    resp = await client.get(MAIGRET_REMOTE)
    if resp is None or resp.status_code != 200:
        code = "?" if resp is None else resp.status_code
        raise RuntimeError(f"Maigret download failed (HTTP {code})")
    payload = resp.text
    parsed = json.loads(payload)
    if not isinstance(parsed.get("sites"), dict) or not isinstance(parsed.get("engines", {}), dict):
        raise RuntimeError("Maigret response is not in the expected shape")
    after = len(translate_all(parsed))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=CACHE_DIR, delete=False) as fh:
        fh.write(payload)
        tmp_path = Path(fh.name)
    tmp_path.replace(CACHED_MAIGRET)
    return before, after
