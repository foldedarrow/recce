# SPDX-License-Identifier: AGPL-3.0-or-later
"""TLS certificate source."""

from __future__ import annotations

import socket
import ssl
from email.utils import parsedate_to_datetime
from typing import Any

from recce.core.result import Hit, Status


def certificate(domain: str) -> dict[str, Any] | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as sock:
                cert = sock.getpeercert()
    except OSError:
        return None
    subject = ", ".join("=".join(item) for part in cert.get("subject", []) for item in part)
    issuer = ", ".join("=".join(item) for part in cert.get("issuer", []) for item in part)
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    not_after = cert.get("notAfter")
    summary = f"issuer: {issuer or '-'}"
    if not_after:
        summary += f" · expires: {_cert_date(not_after)}"
    if sans:
        summary += f" · {len(sans)} SAN(s)"
    return {"subject": subject, "issuer": issuer, "not_after": not_after, "sans": sans[:200], "summary": summary}


def hit(domain: str) -> Hit | None:
    cert = certificate(domain)
    if not cert:
        return None
    return Hit(
        source="TLS certificate",
        category="web",
        status=Status.FOUND,
        summary=cert["summary"],
        extra=cert,
        confidence=0.85,
    )


def _cert_date(value: str) -> str:
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError):
        return value
