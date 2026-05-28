# SPDX-License-Identifier: AGPL-3.0-or-later
"""Microsoft 365 realm source."""

from __future__ import annotations

import time

from recce.core.result import Hit, Status

from .common import xml_tag
from .registry import SourceContext


async def query(domain: str, ctx: SourceContext) -> Hit:
    url = "https://login.microsoftonline.com/getuserrealm.srf"
    started = time.perf_counter()
    resp = await ctx.client.get(url, params={"login": f"anyuser@{domain}", "xml": "1"})
    elapsed = int((time.perf_counter() - started) * 1000)
    if resp is None:
        return Hit(source="Microsoft 365 realm", category="email", status=Status.ERROR, error="network", elapsed_ms=elapsed)
    if resp.status_code >= 400:
        return Hit(
            source="Microsoft 365 realm",
            category="email",
            status=Status.UNKNOWN,
            summary=f"HTTP {resp.status_code}",
            elapsed_ms=elapsed,
        )
    text = resp.text
    namespace = xml_tag(text, "NameSpaceType")
    brand = xml_tag(text, "FederationBrandName")
    cloud = xml_tag(text, "CloudInstanceName")
    sts = xml_tag(text, "STSAuthURL")
    if namespace in {"Managed", "Federated"}:
        summary = f"{namespace}"
        if brand:
            summary += f" · {brand}"
        if cloud:
            summary += f" · {cloud}"
        if sts:
            summary += f" · STS {sts}"
        return Hit(
            source="Microsoft 365 realm",
            category="email",
            status=Status.FOUND,
            url=url,
            summary=summary,
            extra={"namespace": namespace, "brand": brand, "cloud": cloud, "sts": sts, "raw": text[:2000]},
            confidence=0.85,
            elapsed_ms=elapsed,
        )
    return Hit(
        source="Microsoft 365 realm",
        category="email",
        status=Status.NOT_FOUND,
        url=url,
        summary=f"No M365 tenant detected ({namespace or 'unknown'})",
        extra={"namespace": namespace, "raw": text[:2000]},
        elapsed_ms=elapsed,
    )
