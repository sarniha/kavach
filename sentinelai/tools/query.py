"""
sentinelai/tools/query.py
─────────────────────────
Generic event query tool over DuckDB LogStore.
"""
from __future__ import annotations

import json
from typing import Any

from sentinelai.store.log_store import LogStore
from sentinelai.tools.schemas import QueryEventsResult


def query_events(
    store: LogStore,
    filters: dict[str, Any] | None = None,
    limit: int = 50,
) -> QueryEventsResult:
    """
    Query events from the LogStore with structured filters.

    Parameters
    ----------
    store:
        The LogStore instance.
    filters:
        Dictionary of field filters:
        - user, host, src_ip, dst_ip, source, event_type, outcome
        - start_time, end_time (ISO string or datetime)
        - raw_contains (substring search in raw log)
    limit:
        Maximum number of events to return (default 50).
    """
    filters = filters or {}
    clauses: list[str] = []
    params: list[Any] = []

    for key, val in filters.items():
        if val is None:
            continue
        if key == "user":
            clauses.append('"user" = ?')
            params.append(val)
        elif key in ("host", "src_ip", "dst_ip", "source", "event_type", "outcome"):
            clauses.append(f"{key} = ?")
            params.append(val)
        elif key == "start_time":
            clauses.append("timestamp >= ?")
            params.append(val.isoformat() if hasattr(val, "isoformat") else str(val))
        elif key == "end_time":
            clauses.append("timestamp <= ?")
            params.append(val.isoformat() if hasattr(val, "isoformat") else str(val))
        elif key == "raw_contains":
            clauses.append("raw ILIKE ?")
            params.append(f"%{val}%")

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    # Total count query
    count_sql = f"SELECT COUNT(*) FROM events {where_sql}"
    total_matched = int(store.connection.execute(count_sql, params).fetchone()[0])

    # Fetch bounded slice ordered chronologically
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

    return QueryEventsResult(
        event_ids=event_ids,
        events=parsed_events,
        count=len(parsed_events),
        total_matched=total_matched,
        truncated=total_matched > limit,
    )
