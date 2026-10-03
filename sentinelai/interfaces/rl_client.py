"""
sentinelai/interfaces/rl_client.py
───────────────────────────────────
Phase 8: Teammate interfaces (RL Triage Engine stub).

Defines:
- RLClient (Protocol): Teammate interface specification.
- FileRLClient: File-backed implementation for local testing and standalone runs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from sentinelai.schemas import AnalystFeedback, IncidentInput


@runtime_checkable
class RLClient(Protocol):
    """
    Protocol defining interaction with the Reinforcement Learning triage engine (Section 9).
    In production, the RL engine pushes incidents and collects feedback for reward shaping.
    """

    def get_incident(self) -> IncidentInput:
        """Fetch the next incident triaged for multi-agent investigation."""
        ...

    def submit_feedback(self, fb: AnalystFeedback, trace: dict[str, Any]) -> None:
        """Submit human analyst feedback alongside the investigation trace for RL reward update."""
        ...


class FileRLClient:
    """
    File-backed RL client (Section 9).
    Reads incident JSON files from a directory, and writes feedback + trace pairs
    to disk for offline analysis and RL model training without running a live server.
    """

    def __init__(
        self,
        incident_dir: str | Path,
        feedback_dir: str | Path | None = None,
    ) -> None:
        self.incident_dir = Path(incident_dir)
        self.feedback_dir = Path(feedback_dir or self.incident_dir / "feedback")
        self.feedback_dir.mkdir(parents=True, exist_ok=True)

    def get_incident(self, incident_id: str | None = None) -> IncidentInput:
        """
        Load an incident from disk. If incident_id is not specified, returns the first JSON found.
        """
        if not self.incident_dir.exists():
            raise FileNotFoundError(f"Incident directory not found: {self.incident_dir}")

        if incident_id:
            target_path = self.incident_dir / f"{incident_id}.json"
            if not target_path.exists():
                # Also try looking directly
                target_path = self.incident_dir / incident_id
            if not target_path.exists():
                raise FileNotFoundError(f"Incident file not found: {incident_id}")
            data = json.loads(target_path.read_text(encoding="utf-8"))
            return IncidentInput.model_validate(data)

        # Pick first available incident file
        incident_files = sorted(self.incident_dir.glob("*.json"))
        if not incident_files:
            raise FileNotFoundError(f"No incident JSON files in {self.incident_dir}")

        data = json.loads(incident_files[0].read_text(encoding="utf-8"))
        return IncidentInput.model_validate(data)

    def submit_feedback(self, fb: AnalystFeedback, trace: dict[str, Any]) -> Path:
        """
        Write analyst feedback paired with execution trace for reward shaping.
        """
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        out_file = self.feedback_dir / f"{fb.incident_id}_feedback.json"

        payload = {
            "incident_id": fb.incident_id,
            "verdict": fb.verdict,
            "severity_correct": fb.severity_correct,
            "notes": fb.notes,
            "rl_reward_features": {
                "agents_executed": trace.get("agents_executed", []),
                "tool_calls_per_agent": trace.get("tool_calls_per_agent", {}),
                "loops_used": trace.get("loops_used", 0),
                "total_tokens": trace.get("tokens", 0),
                "wall_clock_time": trace.get("wall_clock_time", 0.0),
                "overall_confidence": trace.get("overall_confidence", 0.0),
            },
            "full_trace": trace,
        }

        out_file.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return out_file
