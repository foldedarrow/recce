# SPDX-License-Identifier: AGPL-3.0-or-later
"""Port-43 whois ownership source."""

from __future__ import annotations

import re
import socket

from recce.core.result import Hit, Status


def query(domain: str) -> Hit:
    text = _whois_lookup(domain)
    if text:
        return Hit(
            source="Whois",
            category="ownership",
            status=Status.FOUND,
            summary=_summarise_whois(text),
            extra={"sample": text[:3000]},
            confidence=0.65,
        )
    return Hit(source="Whois", category="ownership", status=Status.UNKNOWN, summary="No whois response")


def _whois_lookup(domain: str) -> str:
    tld = domain.rsplit(".", 1)[-1]
    server = _whois_query("whois.iana.org", tld)
    match = re.search(r"whois:\s*(\S+)", server, flags=re.I)
    whois_server = match.group(1) if match else "whois.iana.org"
    return _whois_query(whois_server, domain)


def _whois_query(server: str, query: str) -> str:
    try:
        with socket.create_connection((server, 43), timeout=6) as sock:
            sock.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode(errors="replace")
    except OSError:
        return ""


def _summarise_whois(text: str) -> str:
    fields = []
    for label in (
        "Registrar",
        "Creation Date",
        "Registry Expiry Date",
        "Updated Date",
        "Registrant Organization",
        "Registrant Country",
    ):
        match = re.search(rf"^{re.escape(label)}:\s*(.+)$", text, flags=re.I | re.M)
        if match:
            fields.append(f"{label}: {match.group(1).strip()}")
    return " · ".join(fields[:5]) if fields else "Whois response returned"
