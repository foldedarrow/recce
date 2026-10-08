# SPDX-License-Identifier: AGPL-3.0-or-later
"""Provider contracts for optional API integrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from recce.config import Settings
from recce.core.http import HttpClient
from recce.core.result import Hit, Report, Status
from recce.licensing import has_pro_entitlement

ProviderState = Literal["active", "not_configured", "inactive_pro", "disabled"]


@dataclass(frozen=True)
class ProviderStatus:
    state: ProviderState
    detail: str


@dataclass(frozen=True)
class ProviderContext:
    settings: Settings
    client: HttpClient


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    tier: Literal["free", "pro"]
    enriches: tuple[str, ...]
    config_keys: tuple[str, ...]
    setting_attrs: tuple[str, ...]
    homepage: str
    notes: str = ""
    key_optional: bool = False

    @property
    def pro_required(self) -> bool:
        return self.tier == "pro"

    def is_configured(self, settings: Settings) -> bool:
        if self.key_optional:
            return True
        if not self.setting_attrs:
            return True
        return all(bool(getattr(settings, attr, None)) for attr in self.setting_attrs)

    def status(self, settings: Settings) -> ProviderStatus:
        if not settings.provider_integrations_enabled:
            return ProviderStatus("disabled", "disabled by --no-providers")
        if not self.is_configured(settings):
            keys = ", ".join(self.config_keys)
            return ProviderStatus("not_configured", f"set {keys}")
        if self.pro_required and not has_pro_entitlement():
            return ProviderStatus("inactive_pro", "configured but Recce Pro entitlement is inactive")
        detail = self.notes or "ready"
        return ProviderStatus("active", detail)

    def pro_gate_hit(self, target_type: str) -> Hit | None:
        if not self.pro_required or target_type not in self.enriches:
            return None
        return Hit(
            source=self.name,
            category="provider",
            status=Status.SKIPPED,
            summary="Recce Pro entitlement required for this provider",
            confidence=0.0,
            extra={"provider_id": self.id, "tier": self.tier, "enriches": list(self.enriches)},
        )

    def not_configured_hit(self) -> Hit:
        keys = ", ".join(self.config_keys)
        return Hit(
            source=self.name,
            category="provider",
            status=Status.SKIPPED,
            summary=f"set {keys} to enable this provider",
            confidence=0.0,
            extra={"provider_id": self.id, "tier": self.tier},
        )

    def disabled_hit(self) -> Hit:
        return Hit(
            source=self.name,
            category="provider",
            status=Status.SKIPPED,
            summary="provider integrations disabled",
            confidence=0.0,
            extra={"provider_id": self.id, "tier": self.tier},
        )

    async def query(self, target: str, target_type: str, ctx: ProviderContext) -> list[Hit]:
        del target, target_type, ctx
        return []

    def make_hit(self, category: str, status: Status, **kwargs: object) -> Hit:
        """Build a Hit for this provider, tagging `extra` with its provider id."""
        extra = dict(kwargs.pop("extra", None) or {})  # type: ignore[call-overload]
        extra.setdefault("provider_id", self.id)
        return Hit(source=self.name, category=category, status=status, extra=extra, **kwargs)  # type: ignore[arg-type]


def append_provider_gate_hits(
    report: Report,
    settings: Settings,
    providers: list[Provider],
    *,
    skip_provider_ids: set[str] | None = None,
) -> None:
    if not settings.provider_integrations_enabled:
        return
    skipped = skip_provider_ids or set()
    existing_provider_ids = {
        hit.extra.get("provider_id")
        for hit in report.hits
        if isinstance(hit.extra, dict) and hit.extra.get("provider_id")
    }
    for provider in providers:
        if provider.id in skipped:
            continue
        if provider.id in existing_provider_ids:
            continue
        if not provider.is_configured(settings):
            continue
        if provider.status(settings).state != "inactive_pro":
            continue
        hit = provider.pro_gate_hit(report.query_type)
        if hit:
            report.add(hit)
