# SPDX-License-Identifier: AGPL-3.0-or-later
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


class PivotOrigin(BaseModel):
    """Why a follow-up search ran: the hit in an earlier report that named it."""

    from_query: str
    from_type: str
    source: str
    field: str
    hit_url: str | None = None
    depth: int = 1


class ClusterMember(BaseModel):
    source: str
    url: str | None = None
    created_at: str | None = None
    query: str | None = None  # the search(es) that found it; set on cross-report identities


class Cluster(BaseModel):
    """FOUND hits whose public data says they are probably one person."""

    id: int
    confidence: float = Field(ge=0.0, le=1.0)
    members: list[ClusterMember] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    timeline: list[ClusterMember] = Field(default_factory=list)


class Report(BaseModel):
    """Top-level report from a single query."""

    query: str
    query_type: str
    pivot: PivotOrigin | None = None
    exit: str | None = None  # network exit the query left through (see core/egress.py)
    clusters: list[Cluster] = Field(default_factory=list)
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
