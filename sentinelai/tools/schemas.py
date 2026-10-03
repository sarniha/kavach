"""
sentinelai/tools/schemas.py
───────────────────────────
Pydantic schemas for deterministic tool results (Section 6).

Every tool returns a compact Pydantic result that includes the ``event_ids``
it is based on. Result sizes are capped (default 50 rows) with truncation flags.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Base class for all deterministic tool results."""
    event_ids: list[str] = Field(
        default_factory=list,
        description="IDs of all events that contributed to this result.",
    )
    truncated: bool = Field(
        default=False,
        description="True if the result was truncated due to row limits.",
    )
    total_matched: int = Field(
        default=0,
        description="Total number of matching events before truncation.",
    )


class QueryEventsResult(ToolResult):
    """Result of query_events."""
    events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of matching normalized event records.",
    )
    count: int = Field(
        default=0,
        description="Number of event records returned in this slice.",
    )


class FailedLoginsResult(ToolResult):
    """Result of count_failed_logins."""
    user: str | None = None
    ip: str | None = None
    window_minutes: int = 10
    total_failures: int = 0
    burst_count: int = Field(
        default=0,
        description="Maximum failures observed within any single window.",
    )
    time_span_seconds: float = 0.0


class SuccessAfterFailuresResult(ToolResult):
    """Result of login_success_after_failures."""
    detected: bool = False
    user: str | None = None
    ip: str | None = None
    failure_count: int = 0
    success_event_id: str | None = None
    failure_event_ids: list[str] = Field(default_factory=list)
    success_timestamp: datetime | None = None
    window_minutes: int = 60


class UnusualLoginTimesResult(ToolResult):
    """Result of unusual_login_times."""
    user: str
    baseline_hours: list[int] = Field(
        default_factory=lambda: list(range(8, 19)),
        description="Standard business hours (default 08:00 - 18:00 UTC).",
    )
    off_hours_count: int = 0
    off_hours_events: list[dict[str, Any]] = Field(default_factory=list)


class PrivilegeChangesResult(ToolResult):
    """Result of privilege_changes."""
    user: str | None = None
    count: int = 0
    changes: list[dict[str, Any]] = Field(default_factory=list)


class IPActivitySummaryResult(ToolResult):
    """Result of ip_activity_summary."""
    ip: str
    total_events: int = 0
    targeted_users: list[str] = Field(default_factory=list)
    targeted_hosts: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class EntityEventsResult(ToolResult):
    """Result of get_events_for_entity."""
    kind: str
    value: str
    count: int = 0
    events: list[dict[str, Any]] = Field(default_factory=list)


class TimelineResult(ToolResult):
    """Result of build_timeline."""
    entity: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    count: int = 0
    entries: list[dict[str, Any]] = Field(default_factory=list)


class SequenceAnalysisResult(ToolResult):
    """Result of detect_sequence_gaps_and_bursts."""
    bursts: list[dict[str, Any]] = Field(
        default_factory=list,
        description="High-frequency clusters exceeding burst threshold.",
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Inactivity gaps exceeding gap threshold.",
    )


class RelatedEntitiesResult(ToolResult):
    """Result of find_related_entities."""
    root_kind: str
    root_value: str
    hops: int = 1
    related_ips: list[str] = Field(default_factory=list)
    related_users: list[str] = Field(default_factory=list)
    related_hosts: list[str] = Field(default_factory=list)


class LateralMovementCandidate(BaseModel):
    """Single candidate lateral movement trail."""
    user: str
    ip: str | None = None
    hosts: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_ids: list[str] = Field(default_factory=list)


class LateralMovementResult(ToolResult):
    """Result of lateral_movement_candidates."""
    detected: bool = False
    candidates: list[LateralMovementCandidate] = Field(default_factory=list)


class EventExistsResult(ToolResult):
    """Result of event_exists."""
    event_id: str
    exists: bool = False


class GetEventResult(ToolResult):
    """Result of get_event."""
    event_id: str
    found: bool = False
    event: dict[str, Any] | None = None
