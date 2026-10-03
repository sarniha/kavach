"""
sentinelai/tracing/local_trace.py
──────────────────────────────────
Phase 8: Incident Trace Export & Logging (Section 9 & 12).

Creates structured `trace.json` containing execution metrics needed for:
1. Auditability & Explainability
2. RL Reward Shaping:
   - agents_executed
   - tool_calls_per_agent
   - loops_used
   - tokens
   - estimated_cost
   - wall_clock_time
   - validator_verdicts
   - overall_confidence
   - analyst_verdict (once feedback arrives)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelai.schemas import AnalystFeedback, InvestigationReport, ValidationResult


class LocalTraceManager:
    """
    Manages structured incident traces on disk.
    """

    def __init__(self, base_dir: str | Path = "reports") -> None:
        self.base_dir = Path(base_dir)

    def export_trace(
        self,
        incident_id: str,
        risk_level: str,
        agents_executed: list[str],
        tool_calls_per_agent: dict[str, int],
        loops_used: int,
        tokens: int,
        estimated_cost: float,
        wall_clock_time: float,
        overall_confidence: float,
        validator_verdicts: list[dict[str, Any]],
        raw_trace: dict[str, Any] | None = None,
        report: InvestigationReport | None = None,
    ) -> Path:
        """
        Assemble and persist trace.json under {base_dir}/{incident_id}/trace.json.
        """
        incident_dir = self.base_dir / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)
        out_file = incident_dir / "trace.json"

        trace_payload = {
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_level": risk_level,
            # RL reward shaping attributes
            "agents_executed": agents_executed,
            "tool_calls_per_agent": tool_calls_per_agent,
            "loops_used": loops_used,
            "tokens": tokens,
            "estimated_cost": round(estimated_cost, 6),
            "wall_clock_time": round(wall_clock_time, 3),
            "overall_confidence": round(overall_confidence, 2),
            "validator_verdicts": validator_verdicts,
            "analyst_verdict": None,
            "report_summary": {
                "findings_count": len(report.findings) if report else 0,
                "mitre_techniques": [m.get("technique_id") for m in (report.mitre_mapping if report else [])],
                "limitations_count": len(report.limitations) if report else 0,
            } if report else None,
            "raw_agent_trace": raw_trace or {},
        }

        out_file.write_text(json.dumps(trace_payload, indent=2, default=str), encoding="utf-8")
        return out_file

    def get_trace(self, incident_id: str) -> dict[str, Any] | None:
        """Read existing trace JSON for an incident if present."""
        trace_file = self.base_dir / incident_id / "trace.json"
        if not trace_file.exists():
            return None
        return json.loads(trace_file.read_text(encoding="utf-8"))

    def attach_feedback(self, fb: AnalystFeedback) -> Path | None:
        """Attach analyst verdict to the incident's trace.json."""
        trace_file = self.base_dir / fb.incident_id / "trace.json"
        if not trace_file.exists():
            return None

        trace = json.loads(trace_file.read_text(encoding="utf-8"))
        trace["analyst_verdict"] = fb.verdict
        trace["feedback"] = {
            "verdict": fb.verdict,
            "severity_correct": fb.severity_correct,
            "notes": fb.notes,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        trace_file.write_text(json.dumps(trace, indent=2, default=str), encoding="utf-8")
        return trace_file
