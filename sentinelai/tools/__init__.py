"""
sentinelai/tools/__init__.py
────────────────────────────
Deterministic tool layer for SentinelAI agents (Section 6).
"""
from __future__ import annotations

from sentinelai.store.log_store import LogStore
from sentinelai.tools.auth_tools import (
    count_failed_logins,
    login_success_after_failures,
    privilege_changes,
    unusual_login_times,
)
from sentinelai.tools.entity_tools import (
    find_related_entities,
    get_events_for_entity,
    ip_activity_summary,
    lateral_movement_candidates,
)
from sentinelai.tools.query import query_events
from sentinelai.tools.registry import Tool, ToolRegistry, wrap_log_data_safely
from sentinelai.tools.schemas import (
    EntityEventsResult,
    EventExistsResult,
    FailedLoginsResult,
    GetEventResult,
    IPActivitySummaryResult,
    LateralMovementCandidate,
    LateralMovementResult,
    PrivilegeChangesResult,
    QueryEventsResult,
    RelatedEntitiesResult,
    SequenceAnalysisResult,
    SuccessAfterFailuresResult,
    TimelineResult,
    ToolResult,
    UnusualLoginTimesResult,
)
from sentinelai.tools.timeline_tools import (
    build_timeline,
    detect_sequence_gaps_and_bursts,
)
from sentinelai.tools.validator_tools import event_exists, get_event


def create_default_registry(store: LogStore | None = None) -> ToolRegistry:
    """Create and return a ToolRegistry populated with all Section 6 deterministic tools."""
    registry = ToolRegistry(store=store)

    registry.register(
        Tool(
            name="query_events",
            description="Query events from the store with structured filters and bounded limit.",
            func=query_events,
            tags=["query", "general"],
        )
    )
    registry.register(
        Tool(
            name="count_failed_logins",
            description="Count failed authentication attempts and calculate burst metrics.",
            func=count_failed_logins,
            tags=["auth"],
        )
    )
    registry.register(
        Tool(
            name="login_success_after_failures",
            description="Detect authentication successes shortly following authentication failures.",
            func=login_success_after_failures,
            tags=["auth"],
        )
    )
    registry.register(
        Tool(
            name="unusual_login_times",
            description="Detect off-hours logins outside of user standard baseline business hours.",
            func=unusual_login_times,
            tags=["auth"],
        )
    )
    registry.register(
        Tool(
            name="privilege_changes",
            description="Detect privilege changes and elevation activities (sudo, su, root).",
            func=privilege_changes,
            tags=["auth", "privilege"],
        )
    )
    registry.register(
        Tool(
            name="ip_activity_summary",
            description="Summarize targeted users, hosts, event types, and timestamps for an IP.",
            func=ip_activity_summary,
            tags=["entity", "ip"],
        )
    )
    registry.register(
        Tool(
            name="get_events_for_entity",
            description="Retrieve bounded event slice touching a specific entity (ip, user, host).",
            func=get_events_for_entity,
            tags=["entity"],
        )
    )
    registry.register(
        Tool(
            name="build_timeline",
            description="Build chronologically ordered sequence of events, optionally filtered.",
            func=build_timeline,
            tags=["timeline"],
        )
    )
    registry.register(
        Tool(
            name="detect_sequence_gaps_and_bursts",
            description="Detect high-frequency bursts and inactivity gaps in event timeline.",
            func=detect_sequence_gaps_and_bursts,
            tags=["timeline"],
        )
    )
    registry.register(
        Tool(
            name="find_related_entities",
            description="Discover entity graph neighbors (IP <-> User <-> Host) starting from root.",
            func=find_related_entities,
            tags=["entity", "graph"],
        )
    )
    registry.register(
        Tool(
            name="lateral_movement_candidates",
            description="Identify users or IPs authenticating across multiple distinct hosts.",
            func=lateral_movement_candidates,
            tags=["entity", "lateral_movement"],
        )
    )
    registry.register(
        Tool(
            name="event_exists",
            description="Check if an event ID exists in the store.",
            func=event_exists,
            tags=["validator"],
        )
    )
    registry.register(
        Tool(
            name="get_event",
            description="Retrieve full event record by event ID.",
            func=get_event,
            tags=["validator"],
        )
    )

    return registry


__all__ = [
    "create_default_registry",
    "Tool",
    "ToolRegistry",
    "wrap_log_data_safely",
    "query_events",
    "count_failed_logins",
    "login_success_after_failures",
    "unusual_login_times",
    "privilege_changes",
    "ip_activity_summary",
    "get_events_for_entity",
    "build_timeline",
    "detect_sequence_gaps_and_bursts",
    "find_related_entities",
    "lateral_movement_candidates",
    "event_exists",
    "get_event",
    "ToolResult",
    "QueryEventsResult",
    "FailedLoginsResult",
    "SuccessAfterFailuresResult",
    "UnusualLoginTimesResult",
    "PrivilegeChangesResult",
    "IPActivitySummaryResult",
    "EntityEventsResult",
    "TimelineResult",
    "SequenceAnalysisResult",
    "RelatedEntitiesResult",
    "LateralMovementCandidate",
    "LateralMovementResult",
    "EventExistsResult",
    "GetEventResult",
]
