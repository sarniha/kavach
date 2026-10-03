"""
sentinelai/tools/entity_tools.py
────────────────────────────────
Entity correlation and graph exploration tools (Section 6).

Covers IP activity summaries, entity event retrieval, entity relationship
expansion, and lateral movement detection.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sentinelai.store.log_store import LogStore
from sentinelai.tools.schemas import (
    EntityEventsResult,
    IPActivitySummaryResult,
    LateralMovementCandidate,
    LateralMovementResult,
    RelatedEntitiesResult,
)


def ip_activity_summary(store: LogStore, ip: str) -> IPActivitySummaryResult:
    """
    Summarize all activity involving an IP address (src or dst).

    Parameters
    ----------
    store:
        The LogStore instance.
    ip:
        IP address to investigate.
    """
    sql = """
    SELECT event_id, timestamp, host, "user", src_ip, dst_ip, event_type
    FROM events
    WHERE src_ip = ? OR dst_ip = ?
    ORDER BY timestamp ASC
    """
    rows = store.query(sql, [ip, ip])

    if not rows:
        return IPActivitySummaryResult(
            ip=ip,
            total_events=0,
            targeted_users=[],
            targeted_hosts=[],
            event_types=[],
            first_seen=None,
            last_seen=None,
            event_ids=[],
            total_matched=0,
        )

    users: set[str] = {r["user"] for r in rows if r["user"]}
    hosts: set[str] = {r["host"] for r in rows if r["host"]}
    event_types: set[str] = {r["event_type"] for r in rows if r["event_type"]}
    event_ids = [r["event_id"] for r in rows]

    first_seen = datetime.fromisoformat(str(rows[0]["timestamp"]).replace("Z", "+00:00"))
    last_seen = datetime.fromisoformat(str(rows[-1]["timestamp"]).replace("Z", "+00:00"))

    return IPActivitySummaryResult(
        ip=ip,
        total_events=len(rows),
        targeted_users=sorted(users),
        targeted_hosts=sorted(hosts),
        event_types=sorted(event_types),
        first_seen=first_seen,
        last_seen=last_seen,
        event_ids=event_ids,
        total_matched=len(rows),
    )


def get_events_for_entity(
    store: LogStore,
    kind: str,
    value: str,
    limit: int = 50,
) -> EntityEventsResult:
    """
    Retrieve bounded event slice touching a specific entity.

    Parameters
    ----------
    store:
        The LogStore instance.
    kind:
        Entity kind: 'ip', 'user', or 'host'.
    value:
        Entity value (e.g. '192.0.2.10', 'admin', 'web-01.internal').
    limit:
        Maximum events to return (default 50).
    """
    kind = kind.lower().strip()
    if kind == "ip":
        where_sql = "WHERE src_ip = ? OR dst_ip = ?"
        params: list[Any] = [value, value]
    elif kind == "user":
        where_sql = 'WHERE "user" = ?'
        params = [value]
    elif kind == "host":
        where_sql = "WHERE host = ?"
        params = [value]
    else:
        raise ValueError(f"Unknown entity kind {kind!r}. Expected 'ip', 'user', or 'host'.")

    count_sql = f"SELECT COUNT(*) FROM events {where_sql}"
    total_matched = int(store.connection.execute(count_sql, params).fetchone()[0])

    fetch_sql = f"""
    SELECT event_id, timestamp, source, host, "user", src_ip, dst_ip, event_type, outcome, raw, fields_json
    FROM events
    {where_sql}
    ORDER BY timestamp ASC
    LIMIT ?
    """
    rows = store.query(fetch_sql, params + [limit])

    parsed_events: list[dict[str, Any]] = []
    event_ids: list[str] = []
    for r in rows:
        event_ids.append(r["event_id"])
        item = dict(r)
        if "fields_json" in item and isinstance(item["fields_json"], str):
            try:
                item["fields"] = json.loads(item["fields_json"])
            except Exception:
                item["fields"] = {}
        parsed_events.append(item)

    return EntityEventsResult(
        kind=kind,
        value=value,
        count=len(parsed_events),
        total_matched=total_matched,
        truncated=total_matched > limit,
        events=parsed_events,
        event_ids=event_ids,
    )


def find_related_entities(
    store: LogStore,
    kind: str,
    value: str,
    hops: int = 1,
) -> RelatedEntitiesResult:
    """
    Discover entity graph neighbors (IP <-> User <-> Host) starting from a root entity.

    Parameters
    ----------
    store:
        The LogStore instance.
    kind:
        Root entity kind: 'ip', 'user', or 'host'.
    value:
        Root entity identifier.
    hops:
        Graph traversal depth (1 or 2).
    """
    discovered_ips: set[str] = set()
    discovered_users: set[str] = set()
    discovered_hosts: set[str] = set()
    all_event_ids: set[str] = set()

    current_ips: set[str] = {value} if kind == "ip" else set()
    current_users: set[str] = {value} if kind == "user" else set()
    current_hosts: set[str] = {value} if kind == "host" else set()

    for _ in range(max(1, min(hops, 3))):
        conditions: list[str] = []
        params: list[Any] = []

        if current_ips:
            ip_clause = " OR ".join(["src_ip = ?" for _ in current_ips] + ["dst_ip = ?" for _ in current_ips])
            conditions.append(f"({ip_clause})")
            params.extend(list(current_ips) * 2)

        if current_users:
            user_clause = " OR ".join(['"user" = ?' for _ in current_users])
            conditions.append(f"({user_clause})")
            params.extend(list(current_users))

        if current_hosts:
            host_clause = " OR ".join(["host = ?" for _ in current_hosts])
            conditions.append(f"({host_clause})")
            params.extend(list(current_hosts))

        if not conditions:
            break

        where_sql = f"WHERE {' OR '.join(conditions)}"
        sql = f"""
        SELECT event_id, host, "user", src_ip, dst_ip
        FROM events
        {where_sql}
        """
        rows = store.query(sql, params)

        next_ips: set[str] = set()
        next_users: set[str] = set()
        next_hosts: set[str] = set()

        for r in rows:
            all_event_ids.add(r["event_id"])
            for ip_val in (r["src_ip"], r["dst_ip"]):
                if ip_val and ip_val != value:
                    if ip_val not in discovered_ips:
                        next_ips.add(ip_val)
                    discovered_ips.add(ip_val)
            if r["user"] and r["user"] != value:
                if r["user"] not in discovered_users:
                    next_users.add(r["user"])
                discovered_users.add(r["user"])
            if r["host"] and r["host"] != value:
                if r["host"] not in discovered_hosts:
                    next_hosts.add(r["host"])
                discovered_hosts.add(r["host"])

        current_ips, current_users, current_hosts = next_ips, next_users, next_hosts

    return RelatedEntitiesResult(
        root_kind=kind,
        root_value=value,
        hops=hops,
        related_ips=sorted(discovered_ips),
        related_users=sorted(discovered_users),
        related_hosts=sorted(discovered_hosts),
        event_ids=sorted(all_event_ids),
        total_matched=len(all_event_ids),
    )


def lateral_movement_candidates(
    store: LogStore,
    window_minutes: int = 60,
    min_hosts: int = 2,
) -> LateralMovementResult:
    """
    Identify potential lateral movement trails (one user or IP authenticating to multiple hosts).

    Parameters
    ----------
    store:
        The LogStore instance.
    window_minutes:
        Time window for activity clustering.
    min_hosts:
        Minimum distinct target hosts to qualify as lateral movement (default 2).
    """
    sql = """
    SELECT event_id, timestamp, "user", src_ip, host
    FROM events
    WHERE (event_type LIKE '%auth%' AND outcome = 'success') AND host IS NOT NULL
    ORDER BY timestamp ASC
    """
    rows = store.query(sql)

    # Group by user (and primary IP)
    user_groups: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        user = r["user"] or "unknown"
        user_groups.setdefault(user, []).append(r)

    candidates: list[LateralMovementCandidate] = []
    all_event_ids: set[str] = set()

    for user, u_rows in user_groups.items():
        hosts = [r["host"] for r in u_rows if r["host"]]
        distinct_hosts = sorted(set(hosts))

        if len(distinct_hosts) >= min_hosts:
            eids = [r["event_id"] for r in u_rows]
            all_event_ids.update(eids)

            # Determine primary src_ip
            ips = [r["src_ip"] for r in u_rows if r["src_ip"]]
            primary_ip = max(set(ips), key=ips.count) if ips else None

            first_seen = datetime.fromisoformat(str(u_rows[0]["timestamp"]).replace("Z", "+00:00"))
            last_seen = datetime.fromisoformat(str(u_rows[-1]["timestamp"]).replace("Z", "+00:00"))

            candidates.append(
                LateralMovementCandidate(
                    user=user,
                    ip=primary_ip,
                    hosts=distinct_hosts,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_ids=eids,
                )
            )

    return LateralMovementResult(
        detected=len(candidates) > 0,
        candidates=candidates,
        event_ids=sorted(all_event_ids),
        total_matched=len(all_event_ids),
    )
