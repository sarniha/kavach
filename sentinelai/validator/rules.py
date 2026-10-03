"""
sentinelai/validator/rules.py
─────────────────────────────
Stage 1: Deterministic rule checks (Section 7.6).

Plain Python, no LLM calls.
Enforces 7 deterministic rules:
1. Every finding cites at least one event ID.
2. Every cited event ID exists in the log store.
3. Every entity named in the finding appears in at least one cited event.
4. Numeric claims are verified against cited events.
5. Time-order claims are consistent with event timestamps.
6. Confidence cap: a finding with a single cited event cannot exceed 0.60.
7. Deduplication of identical findings.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from sentinelai.config import Settings, settings as global_settings
from sentinelai.schemas import ClaimVerdict, Finding, ValidatedFinding
from sentinelai.store.log_store import LogStore


def validate_stage1(
    findings: list[Finding],
    store: LogStore,
    config: Settings | None = None,
) -> list[ValidatedFinding]:
    """
    Execute Stage 1 deterministic validation checks over a list of findings.

    Returns a list of ValidatedFinding objects with initial verdicts,
    identified issues, and adjusted confidence scores.
    """
    config = config or global_settings
    results: list[ValidatedFinding] = []

    # Rule 7: Deduplicate near-duplicate findings
    seen_keys: set[tuple[str, str]] = set()
    unique_findings: list[Finding] = []
    for f in findings:
        key = (f.claim.strip().lower(), ",".join(sorted(f.evidence_event_ids)))
        if key not in seen_keys:
            seen_keys.add(key)
            unique_findings.append(f)

    for finding in unique_findings:
        issues: list[str] = []
        confidence = finding.confidence
        verdict = ClaimVerdict.SUPPORTED

        # Rule 1: Every finding cites at least one event ID
        if not finding.evidence_event_ids:
            issues.append("Finding cites zero evidence event IDs.")
            results.append(
                ValidatedFinding(
                    finding=finding,
                    verdict=ClaimVerdict.UNSUPPORTED,
                    issues=issues,
                    adjusted_confidence=0.0,
                )
            )
            continue

        # Rule 2: Every cited event ID exists in the log store
        valid_events: list[dict[str, Any]] = []
        missing_eids: list[str] = []

        for eid in finding.evidence_event_ids:
            evt = store.get_event(eid)
            if evt is not None:
                valid_events.append(evt)
            else:
                missing_eids.append(eid)

        if missing_eids:
            issues.append(f"Cited event IDs do not exist in LogStore: {missing_eids}")
            if not valid_events:
                # Completely fabricated
                results.append(
                    ValidatedFinding(
                        finding=finding,
                        verdict=ClaimVerdict.UNSUPPORTED,
                        issues=issues,
                        adjusted_confidence=0.0,
                    )
                )
                continue
            else:
                verdict = ClaimVerdict.WEAK
                confidence = min(confidence, 0.50)

        # Rule 3: Every entity named in the finding appears in at least one cited event
        cited_users: set[str] = {e["user"] for e in valid_events if e.get("user")}
        cited_hosts: set[str] = {e["host"] for e in valid_events if e.get("host")}
        cited_ips: set[str] = set()
        for e in valid_events:
            if e.get("src_ip"):
                cited_ips.add(e["src_ip"])
            if e.get("dst_ip"):
                cited_ips.add(e["dst_ip"])

        for u in finding.entities.users:
            if u not in cited_users:
                issues.append(f"User entity '{u}' does not appear in any cited event.")
                verdict = ClaimVerdict.WEAK
                confidence = min(confidence, 0.65)

        for h in finding.entities.hosts:
            if h not in cited_hosts:
                issues.append(f"Host entity '{h}' does not appear in any cited event.")
                verdict = ClaimVerdict.WEAK
                confidence = min(confidence, 0.65)

        for ip in finding.entities.ips:
            if ip not in cited_ips:
                issues.append(f"IP entity '{ip}' does not appear in any cited event.")
                verdict = ClaimVerdict.WEAK
                confidence = min(confidence, 0.65)

        # Rule 4: Numeric claims compared with cited evidence
        # Look for numbers in claim e.g. "30 failed logins", "3 attempts", "5 hosts"
        number_matches = re.findall(r"\b(\d+)\s+(?:failed|failures|logins|attempts|events)\b", finding.claim, re.I)
        for num_str in number_matches:
            claimed_num = int(num_str)
            # If claimed number exceeds cited events by more than 2x and > 3
            if claimed_num > len(valid_events) and len(valid_events) <= 2:
                issues.append(
                    f"Claim asserts {claimed_num} attempts/failures, but only "
                    f"{len(valid_events)} events are cited."
                )
                verdict = ClaimVerdict.WEAK
                confidence = min(confidence, 0.60)

        # Rule 5: Time-order claims consistent with event timestamps
        parsed_timestamps = [
            datetime.fromisoformat(str(e["timestamp"]).replace("Z", "+00:00"))
            for e in valid_events
        ]
        # Check if success followed by failure or reverse
        if "followed by" in finding.claim.lower() or "success" in finding.claim.lower():
            failures = [e for e in valid_events if e.get("event_type") == "auth_failure" or e.get("outcome") == "failure"]
            successes = [e for e in valid_events if e.get("event_type") == "auth_success" or e.get("outcome") == "success"]
            if failures and successes:
                latest_failure = max(datetime.fromisoformat(str(f["timestamp"]).replace("Z", "+00:00")) for f in failures)
                earliest_success = min(datetime.fromisoformat(str(s["timestamp"]).replace("Z", "+00:00")) for s in successes)
                if earliest_success < latest_failure and "success followed by failure" not in finding.claim.lower():
                    issues.append("Success event occurred prior to the latest failure event.")
                    verdict = ClaimVerdict.WEAK
                    confidence = min(confidence, 0.50)

        # Rule 6: Single-event confidence cap
        if len(valid_events) == 1:
            if confidence > config.single_event_confidence_cap:
                issues.append(
                    f"Single-event evidence confidence capped at {config.single_event_confidence_cap} "
                    f"(was {confidence:.2f})."
                )
                confidence = min(confidence, config.single_event_confidence_cap)

        # Ensure confidence bounded [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        results.append(
            ValidatedFinding(
                finding=finding,
                verdict=verdict,
                issues=issues,
                adjusted_confidence=confidence,
            )
        )

    return results
