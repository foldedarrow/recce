# SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain source adapters."""

from __future__ import annotations

from .registry import DOMAIN_CATEGORIES, DomainSource, SourceContext, source_registry

__all__ = ["DOMAIN_CATEGORIES", "DomainSource", "SourceContext", "source_registry"]
