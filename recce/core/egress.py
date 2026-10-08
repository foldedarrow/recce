# SPDX-License-Identifier: AGPL-3.0-or-later
"""Egress control: which network exit each module's traffic leaves through.

Most username probes that still come back "unknown" are IP-reputation blocks:
the deployment box exits via a VPN that Cloudflare and others wall off. An
*exit* is a proxy URL (or direct). recce picks one per module and records it
on every report, so a result can be read in light of where it came from.

Configuration, highest precedence first:

- `--proxy` on the command (a URL, an exit name, or `direct`);
- `RECCE_<MODULE>_PROXY` (`RECCE_USERNAME_PROXY`, `RECCE_EMAIL_PROXY`, ...);
- `RECCE_PROXY` for every module;
- direct.

Exit names come from `RECCE_EXITS`, e.g.
`RECCE_EXITS="tor=socks5h://127.0.0.1:9050;home=socks5h://10.0.0.2:1080"`,
so `--proxy tor` works anywhere a URL does. Username searches can also retry
bot-walled probes (HTTP 401/403/429) through fallback exits, tried in order,
each only for probes the previous exits left blocked:
`--fallback-proxy tor,home` or `RECCE_USERNAME_FALLBACK_PROXY=tor,home`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MODULES = ("username", "email", "phone", "domain")
DIRECT = "direct"
EGRESS_SOURCES = ("https://ipinfo.io/json", "https://api.ipify.org?format=json")
_SCHEMES = ("http", "https", "socks5", "socks5h", "socks4", "socks4a")


@dataclass(frozen=True)
class Exit:
    """A network exit: a proxy URL, or None for the host's own route."""

    name: str
    proxy: str | None = None

    @property
    def label(self) -> str:
        if self.proxy is None:
            return DIRECT
        redacted = redact_proxy(self.proxy)
        return redacted if self.name == redacted else f"{self.name} ({redacted})"


DIRECT_EXIT = Exit(DIRECT)


@dataclass(frozen=True)
class ExitChain:
    """Fallback exits tried in order (e.g. Tor, then a home connection)."""

    exits: tuple[Exit, ...]

    @property
    def label(self) -> str:
        return " → ".join(exit_.label for exit_ in self.exits)


def fallback_exits(fallback: Exit | ExitChain | None) -> tuple[Exit, ...]:
    """The ordered exits in a fallback setting (none, one, or a chain)."""
    if fallback is None:
        return ()
    return fallback.exits if isinstance(fallback, ExitChain) else (fallback,)


def redact_proxy(url: str) -> str:
    """Proxy URL with any password masked, safe to store in a report."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    netloc = f"{parts.username}:***@{host}" if parts.username else f"***@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def named_exits(env: dict[str, str] | None = None) -> dict[str, str]:
    """`RECCE_EXITS` as {name: proxy URL}. Entries split on `;` or `,`."""
    raw = (env if env is not None else os.environ).get("RECCE_EXITS", "")
    out: dict[str, str] = {}
    for entry in raw.replace(",", ";").split(";"):
        name, sep, url = entry.partition("=")
        if sep and name.strip() and url.strip():
            out[name.strip().lower()] = url.strip()
    return out


def parse_exit(value: str | None, exits: dict[str, str] | None = None) -> Exit | None:
    """An exit from a URL, a configured name, or `direct`; None if unset."""
    if value is None or not value.strip():
        return None
    value = value.strip()
    if value.lower() == DIRECT:
        return DIRECT_EXIT
    exits = named_exits() if exits is None else exits
    if value.lower() in exits:
        return Exit(value.lower(), exits[value.lower()])
    scheme = value.split("://", 1)[0].lower() if "://" in value else ""
    if scheme not in _SCHEMES:
        known = ", ".join(sorted(exits)) or "none configured"
        raise ValueError(
            f"unknown exit {value!r}: use a proxy URL ({'/'.join(_SCHEMES)}), "
            f"'direct', or an exit name from RECCE_EXITS ({known})"
        )
    return Exit(redact_proxy(value), value)


def resolve_exit(
    module: str, override: str | None = None, env: dict[str, str] | None = None
) -> Exit:
    """The exit `module` should use: override > RECCE_<MODULE>_PROXY > RECCE_PROXY > direct."""
    env = env if env is not None else dict(os.environ)
    exits = named_exits(env)
    for value in (override, env.get(f"RECCE_{module.upper()}_PROXY"), env.get("RECCE_PROXY")):
        chosen = parse_exit(value, exits)
        if chosen is not None:
            return chosen
    return DIRECT_EXIT


def resolve_fallback(
    override: str | None = None, env: dict[str, str] | None = None
) -> Exit | ExitChain | None:
    """The exit(s) for retrying bot-walled username probes, if any.

    A comma/semicolon list ("tor,home") becomes an ExitChain tried in order;
    a single value stays a plain Exit.
    """
    env = env if env is not None else dict(os.environ)
    exits = named_exits(env)
    for value in (override, env.get("RECCE_USERNAME_FALLBACK_PROXY")):
        if value is None or not value.strip():
            continue
        parts = [part for part in value.replace(";", ",").split(",") if part.strip()]
        chosen = [exit_ for exit_ in (parse_exit(part, exits) for part in parts) if exit_ is not None]
        if len(chosen) == 1:
            return chosen[0]
        if chosen:
            return ExitChain(tuple(chosen))
    return None


def configured_exits(env: dict[str, str] | None = None) -> list[tuple[str, Exit]]:
    """Every exit the configuration mentions, with what uses it (for `doctor`)."""
    env = env if env is not None else dict(os.environ)
    rows: list[tuple[str, Exit]] = [(module, resolve_exit(module, env=env)) for module in MODULES]
    chain = fallback_exits(resolve_fallback(env=env))
    for position, fallback in enumerate(chain, start=1):
        rows.append((f"username fallback {position}" if len(chain) > 1 else "username fallback", fallback))
    used = {e.proxy for _, e in rows}
    for name, url in named_exits(env).items():
        if url not in used:
            rows.append(("unused", Exit(name, url)))
    return rows


def exit_label(proxy: str | None) -> str:
    """Label for a client's proxy setting when only the URL is known."""
    if not proxy:
        return DIRECT
    for name, url in named_exits().items():
        if url == proxy:
            return Exit(name, url).label
    return redact_proxy(proxy)


async def egress_info(client: Any) -> dict[str, Any]:
    """Where a client's requests appear to come from: IP, and country/org when
    the echo service says. Blocks depend on it (VPN exits are often on
    bot-wall deny lists), so selftest reports and `doctor` record it."""
    for url in EGRESS_SOURCES:
        try:
            resp = await client.get(url)
        except Exception:
            continue
        if resp is None or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if data.get("ip"):
            return {k: data[k] for k in ("ip", "country", "org") if data.get(k)}
    return {"ip": None}
