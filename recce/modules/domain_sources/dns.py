# SPDX-License-Identifier: AGPL-3.0-or-later
"""DNS/network source adapter.

Kept as a named source module for the adapter split; implementation lives in
`network.py` because it also performs PTR/ASN enrichment.
"""

from __future__ import annotations

from .network import query

__all__ = ["query"]
