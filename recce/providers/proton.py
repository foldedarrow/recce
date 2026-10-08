# SPDX-License-Identifier: AGPL-3.0-or-later
"""Proton Mail public key server — is this a Proton account, and since when?"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from recce.core.result import Hit, Status

from .base import Provider, ProviderContext


class ProtonKeyProvider(Provider):
    def __init__(self) -> None:
        super().__init__(
            id="proton",
            name="Proton key server",
            tier="free",
            enriches=("email",),
            config_keys=(),
            setting_attrs=(),
            homepage="https://proton.me/support/pgp-key-management",
            notes="confirms Proton accounts (incl. custom domains) and key creation date",
            key_optional=True,
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        if target_type != "email":
            return []
        started = time.perf_counter()
        resp = await ctx.client.get(
            "https://api.protonmail.ch/pks/lookup", params={"op": "index", "search": target}
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        if resp is None:
            return [self.make_hit("profile", Status.ERROR, error="network", elapsed_ms=elapsed)]
        if resp.status_code != 200:
            return [self.make_hit("profile", Status.UNKNOWN, summary=f"HTTP {resp.status_code}", elapsed_ms=elapsed)]

        keys = _parse_index(resp.text)
        if not keys:
            return [self.make_hit("profile", Status.NOT_FOUND, summary="not a Proton address", elapsed_ms=elapsed)]
        oldest = min(keys, key=lambda key: key["created"] or float("inf"))
        parts = [f"Proton account · {len(keys)} public key(s)"]
        if oldest["created"]:
            created = datetime.fromtimestamp(oldest["created"], tz=timezone.utc).date().isoformat()
            parts.append(f"oldest key created {created} (≈ account age)")
        return [
            self.make_hit(
                "profile",
                Status.FOUND,
                summary=" · ".join(parts),
                confidence=0.95,
                elapsed_ms=elapsed,
                extra={"keys": keys},
            )
        ]


def _parse_index(text: str) -> list[dict[str, object]]:
    """Parse HKP machine-readable index output (`pub:` / `uid:` lines)."""
    keys: list[dict[str, object]] = []
    for line in text.splitlines():
        fields = line.split(":")
        if fields[0] == "pub" and len(fields) >= 5:
            created = int(fields[4]) if fields[4].isdigit() else None
            keys.append({"fingerprint": fields[1], "algorithm": fields[2], "bits": fields[3], "created": created, "uids": []})
        elif fields[0] == "uid" and len(fields) >= 2 and keys:
            keys[-1]["uids"].append(fields[1])  # type: ignore[union-attr]
    return keys
