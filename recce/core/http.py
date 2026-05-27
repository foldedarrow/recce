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
    ) -> httpx.Response | None:
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
                    )
                return resp
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as e:
                last_exc = e
                if attempt < self._retries:
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
                log.debug("HTTP %s %s failed after retries: %s", method, url, e)
                return None
        log.debug("HTTP gave up: %s", last_exc)
        return None

    async def get(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("HEAD", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kw)


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
