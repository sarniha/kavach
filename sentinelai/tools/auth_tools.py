"""
sentinelai/tools/auth_tools.py
──────────────────────────────
Authentication investigation tools (Section 6).

Covers failed logins, brute-force-then-success, off-hours logins,
and privilege changes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from sentinelai.store.log_store import LogStore
from sentinelai.tools.schemas import (
    FailedLoginsResult,
    PrivilegeChangesResult,
    SuccessAfterFailuresResult,
    UnusualLoginTimesResult,
)


def count_failed_logins(
    store: LogStore,
    user: str | None = None,
    ip: str | None = None,
    window_minutes: int = 10,
) -> FailedLoginsResult:
    """
    Count failed authentication attempts and calculate burst metrics.

    Parameters
    ----------
    store:
        The LogStore instance.
    user:
        Target username filter (optional).
    ip:
        Source IP address filter (optional).
    window_minutes:
        Window size for sliding burst calculation.
    """
    clauses = ["(event_type = 'auth_failure' OR outcome = 'failure')"]
    params: list[Any] = []

    if user:
        clauses.append('"user" = ?')
        params.append(user)
    if ip:
        clauses.append("src_ip = ?")
        params.append(ip)

    where_sql = f"WHERE {' AND '.join(clauses)}"
    sql = f"""
    SELECT event_id, timestamp, "user", src_ip
    FROM events
    {where_sql}
    ORDER BY timestamp ASC
    """
    rows = store.query(sql, params)
    total_failures = len(rows)
    event_ids = [r["event_id"] for r in rows]

    if not rows:
        return FailedLoginsResult(
            user=user,
            ip=ip,
            window_minutes=window_minutes,
            total_failures=0,
            burst_count=0,
            time_span_seconds=0.0,
            event_ids=[],
            total_matched=0,
        )

    # Convert timestamps to unix epoch for sliding window burst analysis
    timestamps = [
        datetime.fromisoformat(str(r["timestamp"]).replace("Z", "+00:00")).timestamp()
        for r in rows
    ]
    time_span = max(timestamps) - min(timestamps)

    # Sliding window burst calculation
    window_secs = window_minutes * 60
    burst_count = 1
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window_secs:
            left += 1
        burst_count = max(burst_count, right - left + 1)

    return FailedLoginsResult(
        user=user,
        ip=ip,
        window_minutes=window_minutes,
        total_failures=total_failures,
        burst_count=burst_count,
        time_span_seconds=time_span,
        event_ids=event_ids,
        total_matched=total_failures,
    )


def login_success_after_failures(
    store: LogStore,
    user: str | None = None,
    ip: str | None = None,
    window_minutes: int = 60,
) -> SuccessAfterFailuresResult:
    """
    Detect authentication successes that occurred shortly after authentication failures.

    Parameters
    ----------
    store:
        The LogStore instance.
    user:
        Target username (optional).
    ip:
        Source IP address (optional).
    window_minutes:
        Lookback window in minutes before the successful login.
    """
    clauses = ["(event_type = 'auth_success' OR outcome = 'success')"]
    params: list[Any] = []

    if user:
        clauses.append('"user" = ?')
        params.append(user)
    if ip:
        clauses.append("src_ip = ?")
        params.append(ip)

    where_sql = f"WHERE {' AND '.join(clauses)}"
    succ_sql = f"""
    SELECT event_id, timestamp, "user", src_ip
    FROM events
    {where_sql}
    ORDER BY timestamp ASC
    """
    success_rows = store.query(succ_sql, params)

    for succ in success_rows:
        succ_time = datetime.fromisoformat(str(succ["timestamp"]).replace("Z", "+00:00"))
        succ_user = succ["user"]
        succ_ip = succ["src_ip"]

        # Look for failures for this user or IP within window_minutes preceding this success
        fail_start = succ_time - timedelta(minutes=window_minutes)
        fail_clauses = [
            "(event_type = 'auth_failure' OR outcome = 'failure')",
            "timestamp <= ?",
            "timestamp >= ?",
        ]
        fail_params: list[Any] = [succ_time.isoformat(), fail_start.isoformat()]

        if succ_user and succ_ip:
            fail_clauses.append('("user" = ? OR src_ip = ?)')
            fail_params.extend([succ_user, succ_ip])
        elif succ_user:
            fail_clauses.append('"user" = ?')
            fail_params.append(succ_user)
        elif succ_ip:
            fail_clauses.append("src_ip = ?")
            fail_params.append(succ_ip)

        fail_sql = f"""
        SELECT event_id, timestamp
        FROM events
        WHERE {' AND '.join(fail_clauses)}
        ORDER BY timestamp ASC
        """
        fail_rows = store.query(fail_sql, fail_params)

        if fail_rows:
            fail_eids = [r["event_id"] for r in fail_rows]
            all_eids = fail_eids + [succ["event_id"]]
            return SuccessAfterFailuresResult(
                detected=True,
                user=succ_user,
                ip=succ_ip,
                failure_count=len(fail_rows),
                success_event_id=succ["event_id"],
                failure_event_ids=fail_eids,
                success_timestamp=succ_time,
                window_minutes=window_minutes,
                event_ids=all_eids,
                total_matched=len(all_eids),
            )

    return SuccessAfterFailuresResult(
        detected=False,
        user=user,
        ip=ip,
        window_minutes=window_minutes,
        event_ids=[],
        total_matched=0,
    )


def unusual_login_times(
    store: LogStore,
    user: str,
    baseline_hours: list[int] | None = None,
) -> UnusualLoginTimesResult:
    """
    Detect off-hours logins outside of user's standard business baseline hours.

    Parameters
    ----------
    store:
        The LogStore instance.
    user:
        Username to analyze.
    baseline_hours:
        List of typical hour integers (0-23) in UTC. Defaults to 8-18 (8 AM - 6 PM).
    """
    baseline_hours = baseline_hours if baseline_hours is not None else list(range(8, 19))

    sql = """
    SELECT event_id, timestamp, "user", src_ip, host, event_type, outcome, raw
    FROM events
    WHERE "user" = ? AND (event_type LIKE '%auth%' OR outcome IN ('success', 'failure'))
    ORDER BY timestamp ASC
    """
    rows = store.query(sql, [user])

    off_hours: list[dict[str, Any]] = []
    event_ids: list[str] = []

    for r in rows:
        ts = datetime.fromisoformat(str(r["timestamp"]).replace("Z", "+00:00"))
        if ts.hour not in baseline_hours:
            item = dict(r)
            item["hour"] = ts.hour
            off_hours.append(item)
            event_ids.append(r["event_id"])

    return UnusualLoginTimesResult(
        user=user,
        baseline_hours=baseline_hours,
        off_hours_count=len(off_hours),
        off_hours_events=off_hours,
        event_ids=event_ids,
        total_matched=len(off_hours),
    )


def privilege_changes(
    store: LogStore,
    user: str | None = None,
) -> PrivilegeChangesResult:
    """
    Detect privilege changes and elevation activities (sudo, su, new_user root).

    Parameters
    ----------
    store:
        The LogStore instance.
    user:
        Target user filter (optional).
    """
    clauses = [
        """(
            event_type = 'privilege_change'
            OR raw ILIKE '%sudo%'
            OR raw ILIKE '%privilege%'
            OR fields_json ILIKE '%root%'
        )"""
    ]
    params: list[Any] = []

    if user:
        clauses.append('"user" = ?')
        params.append(user)

    sql = f"""
    SELECT event_id, timestamp, source, host, "user", src_ip, event_type, outcome, raw, fields_json
    FROM events
    WHERE {' AND '.join(clauses)}
    ORDER BY timestamp ASC
    """
    rows = store.query(sql, params)

    changes: list[dict[str, Any]] = []
    event_ids: list[str] = []

    for r in rows:
        event_ids.append(r["event_id"])
        item = dict(r)
        if "fields_json" in item and isinstance(item["fields_json"], str):
            try:
                item["fields"] = json.loads(item["fields_json"])
            except Exception:
                item["fields"] = {}
        changes.append(item)

    return PrivilegeChangesResult(
        user=user,
        count=len(changes),
        changes=changes,
        event_ids=event_ids,
        total_matched=len(changes),
    )
