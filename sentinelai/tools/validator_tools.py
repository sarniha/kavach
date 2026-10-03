"""
sentinelai/tools/validator_tools.py
───────────────────────────────────
Validation support tools used by the Evidence Validator (Section 6 & Section 7.6).
"""
from __future__ import annotations

import json
from sentinelai.store.log_store import LogStore
from sentinelai.tools.schemas import EventExistsResult, GetEventResult


def event_exists(store: LogStore, event_id: str) -> EventExistsResult:
    """
    Check if a specific event ID exists in the store.

    Parameters
    ----------
    store:
        The LogStore instance.
    event_id:
        The event identifier to verify.
    """
    exists = store.event_exists(event_id)
    return EventExistsResult(
        event_id=event_id,
        exists=exists,
        event_ids=[event_id] if exists else [],
        total_matched=1 if exists else 0,
    )


def get_event(store: LogStore, event_id: str) -> GetEventResult:
    """
    Retrieve full details for a specific event by ID.

    Parameters
    ----------
    store:
        The LogStore instance.
    event_id:
        The event identifier to fetch.
    """
    raw_event = store.get_event(event_id)
    if not raw_event:
        return GetEventResult(
            event_id=event_id,
            found=False,
            event=None,
            event_ids=[],
            total_matched=0,
        )

    item = dict(raw_event)
    if "fields_json" in item and isinstance(item["fields_json"], str):
        try:
            item["fields"] = json.loads(item["fields_json"])
        except Exception:
            item["fields"] = {}

    return GetEventResult(
        event_id=event_id,
        found=True,
        event=item,
        event_ids=[event_id],
        total_matched=1,
    )
