"""
sentinelai/tools/timeline_tools.py
──────────────────────────────────
Timeline reconstruction and sequence analysis tools (Section 6).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sentinelai.store.log_store import LogStore
from sentinelai.tools.schemas import SequenceAnalysisResult, TimelineResult


def build_timeline(
    store: LogStore,
    entity: str | None = None,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    limit: int = 50,
) -> TimelineResult:
    """
    Build a chronologically ordered sequence of events.

    Parameters
    ----------
    store:
        The LogStore instance.
    entity:
        Optional entity identifier matching user, host, src_ip, or dst_ip.
    start:
        Optional start timestamp boundary.
    end:
        Optional end timestamp boundary.
    limit:
        Maximum events to return in this slice (default 50).
    """
    clauses: list[str] = []
    params: list[Any] = []

    if entity:
        clauses.append('("user" = ? OR host = ? OR src_ip = ? OR dst_ip = ?)')
        params.extend([entity, entity, entity, entity])
    if start:
        clauses.append("timestamp >= ?")
        params.append(start.isoformat() if hasattr(start, "isoformat") else str(start))
    if end:
        clauses.append("timestamp <= ?")
        params.append(end.isoformat() if hasattr(end, "isoformat") else str(end))

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

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

    entries: list[dict[str, Any]] = []
    event_ids: list[str] = []
    for r in rows:
        event_ids.append(r["event_id"])
        item = dict(r)
        if "fields_json" in item and isinstance(item["fields_json"], str):
            try:
                item["fields"] = json.loads(item["fields_json"])
            except Exception:
                item["fields"] = {}
        entries.append(item)

    parsed_start = (
        datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        if start and not isinstance(start, datetime)
        else start
    )
    parsed_end = (
        datetime.fromisoformat(str(end).replace("Z", "+00:00"))
        if end and not isinstance(end, datetime)
        else end
    )

    return TimelineResult(
        entity=entity,
        start=parsed_start,
        end=parsed_end,
        count=len(entries),
        total_matched=total_matched,
        truncated=total_matched > limit,
        entries=entries,
        event_ids=event_ids,
    )


def detect_sequence_gaps_and_bursts(
    store: LogStore,
    burst_threshold_per_minute: int = 5,
    gap_threshold_seconds: int = 600,
) -> SequenceAnalysisResult:
    """
    Detect event bursts and quiet periods / gaps across chronological events.

    Parameters
    ----------
    store:
        The LogStore instance.
    burst_threshold_per_minute:
        Minimum events per 60-second window to qualify as a burst.
    gap_threshold_seconds:
        Minimum gap in seconds between consecutive events to qualify as quiet gap.
    """
    sql = """
    SELECT event_id, timestamp, event_type, "user", src_ip, host
    FROM events
    ORDER BY timestamp ASC
    """
    rows = store.query(sql)
    if not rows:
        return SequenceAnalysisResult(bursts=[], gaps=[], event_ids=[], total_matched=0)

    all_event_ids: set[str] = set()
    bursts: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []

    parsed_rows = [
        (
            r["event_id"],
            datetime.fromisoformat(str(r["timestamp"]).replace("Z", "+00:00")),
            r,
        )
        for r in rows
    ]

    # Detect gaps between consecutive events
    for i in range(len(parsed_rows) - 1):
        eid_curr, t_curr, _ = parsed_rows[i]
        eid_next, t_next, _ = parsed_rows[i + 1]
        gap_sec = (t_next - t_curr).total_seconds()
        if gap_sec >= gap_threshold_seconds:
            gaps.append({
                "start_time": t_curr.isoformat(),
                "end_time": t_next.isoformat(),
                "gap_seconds": gap_sec,
                "from_event_id": eid_curr,
                "to_event_id": eid_next,
            })
            all_event_ids.add(eid_curr)
            all_event_ids.add(eid_next)

    # Detect bursts with 60-second sliding window
    timestamps = [item[1].timestamp() for item in parsed_rows]
    left = 0
    seen_burst_windows: list[tuple[int, int]] = []
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > 60:
            left += 1
        count = right - left + 1
        if count >= burst_threshold_per_minute:
            # Check overlap with previous burst window
            if not seen_burst_windows or left > seen_burst_windows[-1][1]:
                seen_burst_windows.append((left, right))
            else:
                seen_burst_windows[-1] = (seen_burst_windows[-1][0], right)

    for b_start, b_end in seen_burst_windows:
        b_eids = [parsed_rows[idx][0] for idx in range(b_start, b_end + 1)]
        bursts.append({
            "start_time": parsed_rows[b_start][1].isoformat(),
            "end_time": parsed_rows[b_end][1].isoformat(),
            "event_count": len(b_eids),
            "event_ids": b_eids,
        })
        all_event_ids.update(b_eids)

    return SequenceAnalysisResult(
        bursts=bursts,
        gaps=gaps,
        event_ids=sorted(all_event_ids),
        total_matched=len(all_event_ids),
    )
