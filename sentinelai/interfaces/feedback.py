"""
sentinelai/interfaces/feedback.py
──────────────────────────────────
Phase 8: Analyst feedback hook (Section 9).

Updates trace records with human analyst ground-truth assessments:
- verdict: true_positive | false_positive | needs_more_work
- severity_correct: bool | None
- notes: analyst commentary
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sentinelai.schemas import AnalystFeedback


def record_feedback(
    fb: AnalystFeedback,
    trace_dir: str | Path | None = None,
) -> Path:
    """
    Record analyst verdict for an incident and attach to trace if available.
    """
    base_dir = Path(trace_dir or "reports")
    incident_dir = base_dir / fb.incident_id
    incident_dir.mkdir(parents=True, exist_ok=True)

    trace_file = incident_dir / "trace.json"
    feedback_file = incident_dir / "feedback.json"

    feedback_data = {
        "incident_id": fb.incident_id,
        "verdict": fb.verdict,
        "severity_correct": fb.severity_correct,
        "notes": fb.notes,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }

    # If trace exists, update it in-place
    if trace_file.exists():
        try:
            trace_content = json.loads(trace_file.read_text(encoding="utf-8"))
            trace_content["analyst_feedback"] = feedback_data
            trace_content["analyst_verdict"] = fb.verdict
            trace_file.write_text(json.dumps(trace_content, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

    # Always write dedicated feedback file
    feedback_file.write_text(json.dumps(feedback_data, indent=2), encoding="utf-8")
    return feedback_file
