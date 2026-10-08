# SPDX-License-Identifier: AGPL-3.0-or-later
"""Thin async HTTP wrapper with sane defaults, retries, and concurrency control."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx

log = logging.getLogger("recce.http")


class HttpClient:
    """Async HTTP client with retry, semaphore-bounded concurrency, browser-ish UA."""

    def __init__(
        self,
        user_agent: str,
        timeout: float = 12.0,
        max_concurrency: int = 30,
        retries: int = 1,
        proxy: str | None = None,
    ) -> None:
        self._sem = asyncio.Semaphore(max_concurrency)
        self._retries = retries
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.proxy = proxy
        self.user_agent = user_agent
        client_kwargs: dict[str, Any] = dict(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 6.0)),
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.9",
            },
            follow_redirects=True,
            http2=True,
            limits=httpx.Limits(
                max_connections=max_concurrency * 2,
                max_keepalive_connections=max_concurrency,
            ),
        )
        if proxy:
            # httpx accepts http/https/socks5 URLs here. SOCKS support
            # requires the optional `httpx[socks]` install.
            client_kwargs["proxy"] = proxy
        self._client = httpx.AsyncClient(**client_kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: Any | None = None,
        follow_redirects: bool = True,
        timeout: float | None = None,
    ) -> httpx.Response | None:
        resp, _ = await self.request_detailed(
            method,
            url,
            headers=headers,
            params=params,
            json=json,
            data=data,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )
        return resp

    async def request_detailed(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: Any | None = None,
        follow_redirects: bool = True,
        timeout: float | None = None,
    ) -> tuple[httpx.Response | None, str | None]:
        """Like `request`, but on failure also returns a short reason
        ("DNS lookup failed", "timeout", ...) instead of a bare None.

        `timeout` overrides the client's read timeout for this request (for
        slow APIs such as the Wayback CDX)."""
        extra: dict[str, Any] = {}
        if timeout is not None:
            extra["timeout"] = httpx.Timeout(timeout, connect=min(timeout, 6.0))
        last_exc: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                async with self._sem:
                    resp = await self._client.request(
                        method,
                        url,
                        headers=headers,
                        params=params,
                        json=json,
                        data=data,
                        follow_redirects=follow_redirects,
                        **extra,
                    )
                return resp, None
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as e:
                last_exc = e
                if attempt < self._retries:
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
                log.debug("HTTP %s %s failed after retries: %s", method, url, e)
                return None, describe_transport_error(e)
        log.debug("HTTP gave up: %s", last_exc)
        return None, describe_transport_error(last_exc) if last_exc else "network error"

    async def get(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("HEAD", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kw)


class ImpersonatingClient:
    """HTTP client that presents a real Chrome TLS/HTTP2 fingerprint via
    curl_cffi. Many sites (Cloudflare, Akamai, DataDome) reject Python HTTP
    stacks on fingerprint alone; live testing unblocked ~35% of username
    probes that httpx got 403 on. Same interface as `HttpClient`.

    Note this also sends Chrome's User-Agent, so it is used only where the
    caller opts in (username probes by default, `--no-impersonate` to stop).
    """

    def __init__(
        self,
        timeout: float = 12.0,
        max_concurrency: int = 30,
        retries: int = 1,
        proxy: str | None = None,
        impersonate: str = "chrome",
        ipv4: bool = False,
    ) -> None:
        from curl_cffi.requests import AsyncSession

        self._sem = asyncio.Semaphore(max_concurrency)
        self._retries = retries
        self._timeout = timeout
        options = {}
        if ipv4:
            # Resolve targets to IPv4 only: an exit with no IPv6 route (e.g.
            # a SOCKS tunnel to a v4-only host) fails on sites with AAAA records.
            from curl_cffi import CurlOpt

            options[CurlOpt.IPRESOLVE] = 1  # CURL_IPRESOLVE_V4
        self._session = AsyncSession(
            impersonate=impersonate, proxy=proxy, timeout=timeout, curl_options=options or None
        )

    @classmethod
    def from_client(cls, client: HttpClient) -> ImpersonatingClient:
        return cls(timeout=client.timeout, max_concurrency=client.max_concurrency, proxy=client.proxy)

    async def aclose(self) -> None:
        await self._session.close()

    async def request_detailed(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: Any | None = None,
        follow_redirects: bool = True,
        timeout: float | None = None,
    ) -> tuple[Any, str | None]:
        from curl_cffi.requests.exceptions import RequestException

        extra: dict[str, Any] = {"timeout": timeout} if timeout is not None else {}

        last_exc: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                async with self._sem:
                    resp = await self._session.request(
                        method,
                        url,
                        headers=headers,
                        params=params,
                        json=json,
                        data=data,
                        allow_redirects=follow_redirects,
                        **extra,
                    )
                return resp, None
            except RequestException as e:
                last_exc = e
                if attempt < self._retries:
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
                log.debug("HTTP %s %s failed after retries: %s", method, url, e)
        return None, describe_transport_error(last_exc) if last_exc else "network error"

    async def request(self, method: str, url: str, **kw: Any) -> Any:
        resp, _ = await self.request_detailed(method, url, **kw)
        return resp

    async def get(self, url: str, **kw: Any) -> Any:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw: Any) -> Any:
        return await self.request("HEAD", url, **kw)

    async def post(self, url: str, **kw: Any) -> Any:
        return await self.request("POST", url, **kw)


def impersonation_available() -> bool:
    try:
        import curl_cffi  # noqa: F401
    except ImportError:
        return False
    return True


_DNS_ERROR_MARKERS = (
    "name or service not known",
    "nodename nor servname",
    "temporary failure in name resolution",
    "no address associated",
    "getaddrinfo failed",
    "[errno -2]",
    "[errno -3]",
    "[errno 8]",
    "could not resolve host",
)


def describe_transport_error(exc: BaseException) -> str:
    """Turn an httpx exception into a short, user-facing failure reason."""
    text = str(exc).lower()
    if isinstance(exc, httpx.TimeoutException) or "timed out" in text or "timeout" in type(exc).__name__.lower():
        return "timeout"
    if any(marker in text for marker in _DNS_ERROR_MARKERS):
        return "DNS lookup failed (blocked by local resolver, or domain gone)"
    if "certificate" in text or "ssl" in text or "tls" in text:
        return "TLS/certificate error"
    if "refused" in text:
        return "connection refused"
    if "reset" in text or "disconnected" in text or "closed" in text:
        return "connection reset by server"
    if isinstance(exc, httpx.ConnectError):
        return "connection failed"
    return "network error"


@asynccontextmanager
async def http_client(
    user_agent: str,
    timeout: float = 12.0,
    max_concurrency: int = 30,
    proxy: str | None = None,
) -> AsyncIterator[HttpClient]:
    client = HttpClient(
        user_agent=user_agent,
        timeout=timeout,
        max_concurrency=max_concurrency,
        proxy=proxy,
    )
    try:
        yield client
    finally:
        await client.aclose()
