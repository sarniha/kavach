"""
tests/test_interfaces.py
─────────────────────────
Phase 8 acceptance tests:
  - RLClient protocol & FileRLClient (incident retrieval, feedback submission, reward shaping payload)
  - record_feedback hook (trace update, analyst verdict)
  - LocalTraceManager (metrics for RL reward shaping: agents, tool calls, loops, confidence, tokens)
  - Public investigate() entrypoint (medium investigation, archive decision, disk export)
  - CLI commands: investigate and feedback via CliRunner

Acceptance criteria (Section 12 Phase 8):
* One command/function takes an incident JSON to a report plus a trace.
* A feedback command/function updates the trace with the analyst's verdict.
* FileRLClient functions end-to-end without a live RL server.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from data.synthetic.generators import benign_false_positive, brute_force_then_success
from sentinelai.cli import main as cli_main
from sentinelai.interfaces.feedback import record_feedback
from sentinelai.interfaces.rl_client import FileRLClient, RLClient
from sentinelai.investigation import investigate
from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse
from sentinelai.schemas import AnalystFeedback, IncidentInput, NormalizedEvent, RiskLevel
from sentinelai.tracing.local_trace import LocalTraceManager


# ─────────────────────────────────────────────────────────────────────────────
# 1. RLClient & FileRLClient
# ─────────────────────────────────────────────────────────────────────────────

class TestFileRLClient:
    """Test FileRLClient reading incident files and writing feedback/reward traces."""

    def test_protocol_conformance(self):
        client = FileRLClient(incident_dir=".")
        assert isinstance(client, RLClient)

    def test_get_incident_from_directory(self, tmp_path):
        incident_dir = tmp_path / "incidents"
        incident_dir.mkdir()

        inc = brute_force_then_success(n_failures=3).incident
        inc_file = incident_dir / f"{inc.incident_id}.json"
        inc_file.write_text(inc.model_dump_json(indent=2), encoding="utf-8")

        client = FileRLClient(incident_dir=incident_dir)
        loaded = client.get_incident(inc.incident_id)

        assert loaded.incident_id == inc.incident_id
        assert loaded.risk_level == inc.risk_level
        assert len(loaded.events) == len(inc.events)

    def test_submit_feedback_creates_reward_payload(self, tmp_path):
        client = FileRLClient(incident_dir=tmp_path)
        fb = AnalystFeedback(
            incident_id="inc-test-fb",
            verdict="true_positive",
            severity_correct=True,
            notes="Confirmed brute force attack from known scanner",
        )
        sample_trace = {
            "agents_executed": ["auth", "timeline"],
            "tool_calls_per_agent": {"auth": 3, "timeline": 2},
            "loops_used": 0,
            "tokens": 850,
            "wall_clock_time": 1.45,
            "overall_confidence": 0.92,
        }

        out_file = client.submit_feedback(fb, sample_trace)
        assert out_file.exists()

        content = json.loads(out_file.read_text(encoding="utf-8"))
        assert content["incident_id"] == "inc-test-fb"
        assert content["verdict"] == "true_positive"
        assert content["rl_reward_features"]["overall_confidence"] == 0.92
        assert content["rl_reward_features"]["total_tokens"] == 850


# ─────────────────────────────────────────────────────────────────────────────
# 2. LocalTraceManager & record_feedback
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalTraceManager:
    """Test trace export and analyst feedback attachment."""

    def test_export_trace_contains_all_rl_fields(self, tmp_path):
        mgr = LocalTraceManager(base_dir=tmp_path)
        trace_path = mgr.export_trace(
            incident_id="inc-trace-001",
            risk_level="high",
            agents_executed=["auth", "timeline", "correlation"],
            tool_calls_per_agent={"auth": 4, "timeline": 3, "correlation": 2},
            loops_used=1,
            tokens=1500,
            estimated_cost=0.003,
            wall_clock_time=2.15,
            overall_confidence=0.88,
            validator_verdicts=[{"finding_id": "F-1", "claim": "bf", "verdict": "supported", "confidence": 0.88}],
        )

        assert trace_path.exists()
        data = json.loads(trace_path.read_text(encoding="utf-8"))
        assert data["incident_id"] == "inc-trace-001"
        assert data["agents_executed"] == ["auth", "timeline", "correlation"]
        assert data["loops_used"] == 1
        assert data["tokens"] == 1500
        assert data["analyst_verdict"] is None

    def test_record_feedback_updates_trace(self, tmp_path):
        mgr = LocalTraceManager(base_dir=tmp_path)
        mgr.export_trace(
            incident_id="inc-trace-002",
            risk_level="medium",
            agents_executed=["auth", "timeline"],
            tool_calls_per_agent={"auth": 2, "timeline": 2},
            loops_used=0,
            tokens=600,
            estimated_cost=0.001,
            wall_clock_time=1.1,
            overall_confidence=0.80,
            validator_verdicts=[],
        )

        fb = AnalystFeedback(
            incident_id="inc-trace-002",
            verdict="false_positive",
            severity_correct=False,
            notes="Legitimate admin testing new script",
        )
        feedback_path = record_feedback(fb, trace_dir=tmp_path)
        assert feedback_path.exists()

        # Check that trace.json was updated with analyst verdict
        trace_file = tmp_path / "inc-trace-002" / "trace.json"
        trace_data = json.loads(trace_file.read_text(encoding="utf-8"))
        assert trace_data["analyst_verdict"] == "false_positive"
        assert trace_data["analyst_feedback"]["notes"] == "Legitimate admin testing new script"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Public investigate() Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

class TestInvestigateAPI:
    """Test top-level investigate(incident, out_dir=...) function."""

    def test_investigate_archive_for_low_risk(self, tmp_path):
        """Low risk incident archives with zero agent calls and exports report."""
        low_incident = IncidentInput(
            incident_id="inc-low-archive",
            risk_level=RiskLevel.LOW,
            created_at=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
            events=[
                NormalizedEvent(
                    event_id="evt-low-001",
                    timestamp=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
                    source="syslog",
                    event_type="auth_failure",
                    raw="Single failure",
                )
            ],
        )

        client = FakeLLMClient()
        report = investigate(
            incident=low_incident,
            llm_client=client,
            out_dir=tmp_path,
        )

        assert report.incident_id == "inc-low-archive"
        assert report.overall_confidence == 1.0
        assert "archived" in report.executive_summary.lower()

        # Files must be written to disk
        inc_dir = tmp_path / "inc-low-archive"
        assert (inc_dir / "report.md").exists()
        assert (inc_dir / "trace.json").exists()

    def test_investigate_medium_incident_full_cycle(self, tmp_path):
        """Medium incident executes agents, validates, synthesizes report, exports files."""
        scenario = benign_false_positive()
        client = FakeLLMClient()

        report = investigate(
            incident=scenario.incident,
            llm_client=client,
            out_dir=tmp_path,
        )

        assert report.incident_id == scenario.incident.incident_id
        assert isinstance(report.overall_confidence, float)

        inc_dir = tmp_path / scenario.incident.incident_id
        assert (inc_dir / "report.md").exists()
        assert (inc_dir / "trace.json").exists()


# ─────────────────────────────────────────────────────────────────────────────
# 4. CLI Commands (investigate & feedback)
# ─────────────────────────────────────────────────────────────────────────────

class TestCLI:
    """Test command-line commands via Click CliRunner."""

    def test_cli_investigate_command(self, tmp_path):
        runner = CliRunner()
        inc = brute_force_then_success(n_failures=3).incident
        inc_file = tmp_path / "incident.json"
        inc_file.write_text(inc.model_dump_json(indent=2), encoding="utf-8")

        reports_dir = tmp_path / "cli_reports"

        result = runner.invoke(
            cli_main,
            ["investigate", str(inc_file), "--out", str(reports_dir)],
        )

        assert result.exit_code == 0
        assert "Investigation completed successfully" in result.output
        assert (reports_dir / inc.incident_id / "report.md").exists()
        assert (reports_dir / inc.incident_id / "trace.json").exists()

    def test_cli_feedback_command(self, tmp_path):
        runner = CliRunner()
        reports_dir = tmp_path / "cli_reports"
        inc_dir = reports_dir / "inc-cli-001"
        inc_dir.mkdir(parents=True)
        (inc_dir / "trace.json").write_text(
            json.dumps({"incident_id": "inc-cli-001", "agents_executed": ["auth"]}),
            encoding="utf-8",
        )

        result = runner.invoke(
            cli_main,
            [
                "feedback",
                "inc-cli-001",
                "--verdict", "true_positive",
                "--notes", "Legitimate alert, account reset",
                "--out", str(reports_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Analyst feedback recorded successfully" in result.output
        assert (inc_dir / "feedback.json").exists()
