"""Typed result containers used by every module."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Status(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"


class Hit(BaseModel):
    """A single piece of evidence — one platform / source returning something."""

    source: str
    category: str = "general"
    status: Status = Status.UNKNOWN
    url: str | None = None
    summary: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    extra: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    elapsed_ms: int | None = None

    @property
    def is_found(self) -> bool:
        return self.status is Status.FOUND


class Report(BaseModel):
    """Top-level report from a single query."""

    query: str
    query_type: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    hits: list[Hit] = Field(default_factory=list)

    @property
    def found(self) -> list[Hit]:
        return [h for h in self.hits if h.is_found]

    @property
    def errors(self) -> list[Hit]:
        return [h for h in self.hits if h.status is Status.ERROR]

    @property
    def duration_ms(self) -> int | None:
        if self.completed_at is None:
            return None
        return int((self.completed_at - self.started_at).total_seconds() * 1000)

    def add(self, hit: Hit) -> None:
        self.hits.append(hit)

    def finish(self) -> None:
        self.completed_at = datetime.now(timezone.utc)
