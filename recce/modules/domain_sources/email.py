# SPDX-License-Identifier: AGPL-3.0-or-later
"""Email infrastructure domain source."""

from __future__ import annotations

import re

from recce.core.result import Hit, Status

from . import m365
from .common import dns_lookup, txt_tag
from .registry import SourceContext

COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "mail")


async def query(domain: str, ctx: SourceContext) -> list[Hit]:
    hits: list[Hit] = []
    mx_records, mx_error = await dns_lookup(domain, "MX")
    has_null_mx = any(re.fullmatch(r"0\s*\.?", record.strip()) for record in mx_records)
    if mx_records and not has_null_mx:
        provider = _classify_mx(mx_records)
        hits.append(
            Hit(
                source="DNS MX",
                category="email",
                status=Status.FOUND,
                summary=f"{provider or 'unknown provider'} · " + ", ".join(mx_records[:4]),
                extra={"records": mx_records, "provider": provider},
                confidence=0.9,
            )
        )
    else:
        summary = "Null MX: domain does not accept email" if has_null_mx else mx_error
        hits.append(Hit(source="DNS MX", category="email", status=Status.NOT_FOUND, summary=summary))
    txt_records, _ = await dns_lookup(domain, "TXT")
    spf = [r for r in txt_records if r.lower().startswith("v=spf1")]
    if spf:
        includes = sorted(set(re.findall(r"\binclude:([^\s]+)", " ".join(spf), flags=re.I)))
        hits.append(
            Hit(
                source="SPF",
                category="email",
                status=Status.FOUND,
                summary=("SPF present" + (f" · includes: {', '.join(includes[:6])}" if includes else "")),
                extra={"records": spf, "includes": includes},
                confidence=0.85,
            )
        )
    else:
        hits.append(Hit(source="SPF", category="email", status=Status.NOT_FOUND, summary="No SPF TXT record"))
    dmarc_records, _ = await dns_lookup(f"_dmarc.{domain}", "TXT")
    dmarc = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
    if dmarc:
        policy = txt_tag(dmarc[0], "p") or "unknown"
        hits.append(
            Hit(
                source="DMARC",
                category="email",
                status=Status.FOUND,
                summary=f"policy: {policy}",
                extra={"record": dmarc[0], "policy": policy},
                confidence=0.85,
            )
        )
    else:
        hits.append(Hit(source="DMARC", category="email", status=Status.NOT_FOUND, summary="No DMARC policy"))
    selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        records, _ = await dns_lookup(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            selectors.append(selector)
    hits.append(
        Hit(
            source="DKIM selectors",
            category="email",
            status=Status.FOUND if selectors else Status.NOT_FOUND,
            summary=", ".join(selectors) if selectors else "No common DKIM selectors resolved",
            extra={"selectors": selectors},
            confidence=0.7,
        )
    )
    autodiscover, _ = await dns_lookup(f"autodiscover.{domain}", "CNAME")
    if autodiscover:
        hits.append(
            Hit(
                source="Autodiscover",
                category="email",
                status=Status.FOUND,
                summary=", ".join(autodiscover),
                extra={"records": autodiscover},
                confidence=0.75,
            )
        )
    hits.append(await m365.query(domain, ctx))
    return hits


def _classify_mx(records: list[str]) -> str | None:
    joined = " ".join(records).lower()
    table = [
        ("mail.protection.outlook.com", "Microsoft 365"),
        ("outlook.com", "Microsoft 365 / Outlook"),
        ("aspmx.l.google.com", "Google Workspace"),
        ("googlemail.com", "Google Workspace"),
        ("protection.proofpoint.com", "Proofpoint"),
        ("pphosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("zoho", "Zoho"),
        ("protonmail", "Proton Mail"),
        ("fastmail", "Fastmail"),
        ("amazonses", "Amazon SES"),
        ("sendgrid", "SendGrid"),
        ("mailgun", "Mailgun"),
    ]
    for needle, label in table:
        if needle in joined:
            return label
    return None
