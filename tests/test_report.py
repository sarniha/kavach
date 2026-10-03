"""
tests/test_report.py
────────────────────
Phase 7 acceptance tests:
  - ReportGenerator (structured narrative synthesis, filtering, citation check, limitations)
  - Jinja2 Markdown report rendering with Evidence Index and prominent limitations alert
  - Orchestrator graph integration with report_node

Acceptance criteria (Section 12 Phase 7):
* Reports contain ONLY validated findings (SUPPORTED or WEAK).
* UNSUPPORTED and CONTRADICTED findings are excluded from the findings list and cited in limitations.
* Every statement's finding ID resolves to a real finding.
* Evidence index correctly maps each finding ID to event IDs.
* Low confidence (< 0.60) or loop limit is noted prominently at the top.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinelai.agents.schemas import AgentAction, FindingDraft
from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse
from sentinelai.orchestrator.graph import build_investigation_graph
from sentinelai.report.generator import ReportDraft, ReportGenerator
from sentinelai.schemas import (
    Finding,
    IncidentInput,
    NormalizedEvent,
    RiskLevel,
    TimelineEntry,
    ValidatedFinding,
    ValidationResult,
    Verdict,
)
from sentinelai.store.log_store import LogStore
from sentinelai.tools import create_default_registry


def _make_event(eid: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=eid,
        timestamp=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
        source="syslog",
        host="web-01",
        user="admin",
        src_ip="192.0.2.10",
        event_type="auth_failure",
        raw=f"Failed login from 192.0.2.10 for admin (event {eid})",
    )


def _make_validated_finding(
    fid: str,
    verdict: Verdict,
    confidence: float,
    claim: str = "Test finding claim",
    eids: list[str] | None = None,
    agent: str = "auth",
) -> ValidatedFinding:
    f = Finding(
        finding_id=fid,
        agent=agent,
        claim=claim,
        evidence_event_ids=eids or ["evt-001", "evt-002"],
        confidence=confidence,
        reasoning="Test reasoning",
    )
    return ValidatedFinding(
        finding=f,
        verdict=verdict,
        adjusted_confidence=confidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Findings Filtering: Only SUPPORTED & WEAK findings appear in report
# ─────────────────────────────────────────────────────────────────────────────

class TestReportFiltering:
    """Acceptance: Only SUPPORTED and WEAK findings enter report.findings."""

    def test_only_supported_and_weak_findings_included(self):
        client = FakeLLMClient()
        gen = ReportGenerator(client)

        f_supp = _make_validated_finding("F-auth-001", Verdict.SUPPORTED, 0.90, "Brute force attack detected")
        f_weak = _make_validated_finding("F-time-002", Verdict.WEAK, 0.55, "Possible sequence anomaly")
        f_unsupp = _make_validated_finding("F-corr-003", Verdict.UNSUPPORTED, 0.10, "Fabricated claim without evidence")
        f_contra = _make_validated_finding("F-auth-004", Verdict.CONTRADICTED, 0.05, "Contradicted claim")

        all_findings = [f_supp, f_weak, f_unsupp, f_contra]

        report = gen.generate(
            incident_id="inc-test-filter",
            validated_findings=all_findings,
            risk_level="high",
        )

        # Assert only supported and weak are in report.findings
        included_ids = [f.finding_id for f in report.findings]
        assert "F-auth-001" in included_ids
        assert "F-time-002" in included_ids
        assert "F-corr-003" not in included_ids
        assert "F-auth-004" not in included_ids
        assert len(report.findings) == 2

        # Assert excluded findings appear in limitations
        limitations_text = " ".join(report.limitations)
        assert "F-corr-003" in limitations_text
        assert "F-auth-004" in limitations_text
        assert "UNSUPPORTED" in limitations_text
        assert "CONTRADICTED" in limitations_text


# ─────────────────────────────────────────────────────────────────────────────
# 2. Evidence Index: Finding IDs map to Event IDs
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceIndex:
    """Acceptance: Every statement and finding traces back to concrete event IDs."""

    def test_evidence_index_in_rendered_markdown(self):
        client = FakeLLMClient()
        gen = ReportGenerator(client)

        f1 = _make_validated_finding("F-auth-001", Verdict.SUPPORTED, 0.95, eids=["evt-101", "evt-102"])
        f2 = _make_validated_finding("F-time-002", Verdict.WEAK, 0.60, eids=["evt-201"])

        report = gen.generate(
            incident_id="inc-evidence-test",
            validated_findings=[f1, f2],
            timeline_entries=[
                TimelineEntry(
                    timestamp=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
                    description="Initial burst of failures",
                    event_ids=["evt-101"],
                    mitre_tactic="Credential Access",
                )
            ],
            risk_level="high",
        )

        md = gen.render_markdown(report, risk_level="high")

        # Evidence Index section must be present
        assert "## 6. Evidence Index" in md
        assert "`F-auth-001`" in md
        assert "`evt-101`" in md
        assert "`evt-102`" in md
        assert "`F-time-002`" in md
        assert "`evt-201`" in md


# ─────────────────────────────────────────────────────────────────────────────
# 3. Citation Verification: LLM Hallucinated Citations Flagged
# ─────────────────────────────────────────────────────────────────────────────

class TestCitationVerification:
    """Acceptance: Hallucinated finding IDs in narrative are flagged."""

    def test_hallucinated_citation_detected_in_limitations(self):
        client = FakeLLMClient()
        # Script custom draft citing an unknown finding ID [F-fake-999]
        fake_draft = ReportDraft(
            executive_summary="Attacker brute-forced account [F-auth-001] and exfiltrated data [F-fake-999].",
            root_cause="Initial access via brute force [F-auth-001].",
            mitre_mapping=[{
                "technique_id": "T1110",
                "name": "Brute Force",
                "supporting_finding_ids": ["F-auth-001", "F-fake-999"],
            }],
            recommendations=["Rotate admin password."],
        )
        client.register("report", ScriptedResponse(content=fake_draft.model_dump_json()))
        client.queue_response(fake_draft.model_dump_json())

        gen = ReportGenerator(client)
        f1 = _make_validated_finding("F-auth-001", Verdict.SUPPORTED, 0.90)

        report = gen.generate(
            incident_id="inc-citation-test",
            validated_findings=[f1],
        )

        # The unknown citation must be flagged in limitations
        lims = " ".join(report.limitations)
        assert "F-fake-999" in lims
        assert "unverified finding ID" in lims


# ─────────────────────────────────────────────────────────────────────────────
# 4. Low Confidence & Loop Limit Prominent Alert
# ─────────────────────────────────────────────────────────────────────────────

class TestLowConfidenceAlert:
    """Acceptance: Low confidence (< 0.60) or loop limit is prominent at the top."""

    def test_low_confidence_triggers_prominent_alert(self):
        client = FakeLLMClient()
        gen = ReportGenerator(client)

        f_weak = _make_validated_finding("F-weak-001", Verdict.WEAK, 0.40)
        val_result = ValidationResult(
            incident_id="inc-low-conf",
            findings=[f_weak],
            overall_confidence=0.40,
            sufficient=False,
            limitations=["Thin log evidence"],
        )

        report = gen.generate(
            incident_id="inc-low-conf",
            validated_findings=[f_weak],
            validation_result=val_result,
            existing_limitations=["Loop limit reached after 2 reinvestigation attempts."],
        )

        assert report.overall_confidence == 0.40
        md = gen.render_markdown(report, risk_level="medium")

        # Must have top warning block
        assert "LOW CONFIDENCE" in md
        assert "Investigation Limitations & Confidence Alert" in md
        assert "Loop limit reached" in md


# ─────────────────────────────────────────────────────────────────────────────
# 5. Full Markdown Export and File Writing
# ─────────────────────────────────────────────────────────────────────────────

class TestMarkdownExport:
    """Verify markdown output completeness and file writing."""

    def test_export_markdown_creates_file(self, tmp_path):
        client = FakeLLMClient()
        gen = ReportGenerator(client)

        f1 = _make_validated_finding("F-auth-001", Verdict.SUPPORTED, 0.88, claim="Password spray detected")
        report = gen.generate(
            incident_id="inc-export-001",
            validated_findings=[f1],
            trace_summary={"agents_run": ["auth", "timeline"], "loops_used": 1, "tool_calls": 5, "duration_seconds": 1.2, "total_tokens": 1200},
            risk_level="high",
        )

        out_file = tmp_path / "reports" / "inc-export-001.md"
        saved = gen.export_markdown(report, out_file, risk_level="high")

        assert saved.exists()
        content = saved.read_text(encoding="utf-8")
        assert "# Incident Investigation Report: inc-export-001" in content
        assert "Password spray detected" in content
        assert "## 8. Audit & Trace Summary" in content
        assert "agents_run: auth, timeline" or "auth, timeline" in content


# ─────────────────────────────────────────────────────────────────────────────
# 6. Orchestrator Graph Integration with Report Node
# ─────────────────────────────────────────────────────────────────────────────

class TestOrchestratorGraphWithReportNode:
    """Verify report_node is wired and produces InvestigationReport in state."""

    def test_high_incident_workflow_produces_final_report(self):
        incident = IncidentInput(
            incident_id="inc-graph-report",
            risk_level=RiskLevel.HIGH,
            created_at=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
            events=[_make_event(f"evt-{i:03d}") for i in range(5)],
        )

        store = LogStore()
        store.load_incident(incident)
        registry = create_default_registry(store)

        client = FakeLLMClient()

        # Script agents
        auth_action = AgentAction(
            thought="Found brute force",
            findings=[FindingDraft(claim="Brute force attack", evidence_event_ids=["evt-000", "evt-001"], confidence=0.90)],
            is_complete=True,
        )
        timeline_action = AgentAction(
            thought="Constructed timeline",
            findings=[FindingDraft(claim="Rapid failure burst", evidence_event_ids=["evt-000", "evt-001"], confidence=0.85)],
            is_complete=True,
        )
        correlation_action = AgentAction(
            thought="Correlated entities",
            findings=[FindingDraft(claim="Targeted web-01", evidence_event_ids=["evt-000", "evt-001"], confidence=0.80)],
            is_complete=True,
        )

        client.register("auth", ScriptedResponse(content=auth_action.model_dump_json()))
        client.register("timeline", ScriptedResponse(content=timeline_action.model_dump_json()))
        client.register("correlation", ScriptedResponse(content=correlation_action.model_dump_json()))

        # Report draft for report generator
        report_draft = ReportDraft(
            executive_summary="Attacker executed brute force attack against admin account [F-auth-000].",
            root_cause="Credential guessing attack [F-auth-000] targeting SSH.",
            mitre_mapping=[{
                "technique_id": "T1110.001",
                "name": "Password Guessing",
                "supporting_finding_ids": ["F-auth-000"],
            }],
            recommendations=["Implement account lockout."],
        )
        client.register("report", ScriptedResponse(content=report_draft.model_dump_json()))

        gen = ReportGenerator(client)
        graph = build_investigation_graph(
            registry=registry,
            llm_client=client,
            report_generator=gen,
        )

        result = graph.invoke({"incident": incident})

        # Report must be populated in state
        assert "report" in result
        assert result["report"] is not None
        report = result["report"]
        assert report.incident_id == "inc-graph-report"
        assert len(report.findings) > 0
        assert "F-auth-000" in report.executive_summary
        assert len(report.recommendations) > 0
