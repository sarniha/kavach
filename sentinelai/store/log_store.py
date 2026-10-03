"""
sentinelai/store/log_store.py
─────────────────────────────
DuckDB-backed log store for the SentinelAI investigation tier.

The ``LogStore`` is the single source of truth for log events during an
investigation.  All deterministic tools (Section 6) query it; agents never
see raw event dumps.

Design decisions (documented in docs/DECISIONS.md):
- In-memory DuckDB for tests (path=":memory:").
- ``events`` and ``background_events`` are separate tables so baseline
  comparisons (off-hours logins) can use a wider historical window without
  polluting the incident event set.
- All timestamps are stored as UTC ISO strings and compared as strings
  (DuckDB parses them correctly with TIMESTAMPTZ casts).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import duckdb

from sentinelai.schemas import NormalizedEvent


_CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    event_id    VARCHAR PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    source      VARCHAR NOT NULL,
    host        VARCHAR,
    "user"      VARCHAR,
    src_ip      VARCHAR,
    dst_ip      VARCHAR,
    event_type  VARCHAR NOT NULL,
    outcome     VARCHAR,
    raw         VARCHAR NOT NULL,
    fields_json VARCHAR DEFAULT '{}'
)
"""

_CREATE_BACKGROUND_EVENTS = """
CREATE TABLE IF NOT EXISTS background_events (
    event_id    VARCHAR PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    source      VARCHAR NOT NULL,
    host        VARCHAR,
    "user"      VARCHAR,
    src_ip      VARCHAR,
    dst_ip      VARCHAR,
    event_type  VARCHAR NOT NULL,
    outcome     VARCHAR,
    raw         VARCHAR NOT NULL,
    fields_json VARCHAR DEFAULT '{}'
)
"""


class LogStore:
    """
    DuckDB-backed store for normalised log events.

    Parameters
    ----------
    path:
        Path to the DuckDB database file, or ``":memory:"`` for an
        in-process, ephemeral store (default for tests).

    Examples
    --------
    >>> store = LogStore()                       # in-memory
    >>> store.load_incident(incident)            # load all events
    >>> rows = store.query("SELECT * FROM events WHERE event_type = 'auth_failure'")
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        self._lock = threading.RLock()
        self._conn = duckdb.connect(database=path)
        self._setup_tables()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _setup_tables(self) -> None:
        self._conn.execute(_CREATE_EVENTS)
        self._conn.execute(_CREATE_BACKGROUND_EVENTS)

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_events(
        self,
        events: list[NormalizedEvent],
        *,
        background: bool = False,
    ) -> int:
        """
        Insert normalised events into the store.

        Parameters
        ----------
        events:
            List of :class:`~sentinelai.schemas.NormalizedEvent` objects.
        background:
            If ``True``, insert into ``background_events`` (for baselining).

        Returns
        -------
        int
            Number of rows inserted (duplicates are ignored via ``OR IGNORE``).
        """
        import json

        table = "background_events" if background else "events"
        rows = [
            (
                e.event_id,
                e.timestamp.isoformat(),
                e.source,
                e.host,
                e.user,
                e.src_ip,
                e.dst_ip,
                e.event_type,
                e.outcome,
                e.raw,
                json.dumps(e.fields),
            )
            for e in events
        ]
        if not rows:
            return 0

        with self._lock:
            self._conn.executemany(
                f"""
                INSERT OR IGNORE INTO {table}
                    (event_id, timestamp, source, host, "user",
                     src_ip, dst_ip, event_type, outcome, raw, fields_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            return len(rows)

    def load_incident(self, incident: Any) -> int:
        """
        Convenience: load all events from an :class:`~sentinelai.schemas.IncidentInput`.

        Returns the number of events loaded.
        """
        from sentinelai.schemas import IncidentInput

        if isinstance(incident, IncidentInput):
            return self.load_events(incident.events)
        raise TypeError(f"Expected IncidentInput, got {type(incident)}")

    # ── Querying ──────────────────────────────────────────────────────────────

    def query(
        self,
        sql: str,
        params: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute an arbitrary SQL query and return results as a list of dicts.

        Parameters
        ----------
        sql:
            SQL query string.  Use ``?`` placeholders for parameters.
        params:
            Positional parameters matching ``?`` placeholders.

        Returns
        -------
        list[dict]
        """
        with self._lock:
            result = self._conn.cursor().execute(sql, params or [])
            columns = [desc[0] for desc in result.description]
            return [dict(zip(columns, row)) for row in result.fetchall()]

    def event_exists(self, event_id: str) -> bool:
        """Return True if the event_id exists in the events table."""
        with self._lock:
            rows = self._conn.cursor().execute(
                "SELECT 1 FROM events WHERE event_id = ?", [event_id]
            ).fetchall()
            return len(rows) > 0

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        """Fetch a single event by ID, or None if not found."""
        rows = self.query(
            "SELECT * FROM events WHERE event_id = ?", [event_id]
        )
        return rows[0] if rows else None

    def count_events(self, *, background: bool = False) -> int:
        """Return the total number of events in the store."""
        table = "background_events" if background else "events"
        with self._lock:
            row = self._conn.cursor().execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            return int(row[0]) if row else 0

    def all_event_ids(self) -> list[str]:
        """Return all event IDs currently in the events table."""
        with self._lock:
            rows = self._conn.cursor().execute("SELECT event_id FROM events").fetchall()
            return [r[0] for r in rows]

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Delete all rows from both event tables (useful between tests)."""
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM background_events")

    def close(self) -> None:
        """Close the DuckDB connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "LogStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ── Introspection ─────────────────────────────────────────────────────────

    @property
    def connection(self) -> duckdb.DuckDBPyConnection:
        """Direct access to the underlying DuckDB connection (for tools)."""
        return self._conn

    def __repr__(self) -> str:
        return f"LogStore(path={self._path!r}, events={self.count_events()})"
