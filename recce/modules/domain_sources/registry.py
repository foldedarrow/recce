# SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain source registry."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from recce.config import Settings
from recce.core.http import HttpClient
from recce.core.result import Hit


@dataclass(frozen=True)
class SourceContext:
    client: HttpClient
    settings: Settings
    validate_subdomains: bool = True


DomainSource = Callable[[str, SourceContext], Awaitable[list[Hit]]]

DOMAIN_CATEGORIES = {"ownership", "network", "email", "web", "subs", "companies", "wayback"}


def source_registry() -> list[tuple[str, DomainSource]]:
    from . import companies, dns, email, ownership, subdomains, wayback, web

    return [
        ("ownership", ownership.query),
        ("network", dns.query),
        ("email", email.query),
        ("web", web.query),
        ("subs", subdomains.query),
        ("companies", companies.query),
        ("wayback", wayback.query),
    ]
