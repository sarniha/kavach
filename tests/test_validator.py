"""
tests/test_validator.py
───────────────────────
Phase 5 acceptance tests for the Evidence Validator.

Tests cover:
- Stage 1 deterministic rules (fabricated citations, single-event cap,
  entity presence, numeric claims)
- Stage 2 LLM-as-judge (FakeLLMClient scripted responses)
- Contradiction detection
- FollowUpRequest generation for thin evidence
- Validation result sufficiency flags
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse
from sentinelai.schemas import (
    ClaimVerdict,
    Entities,
    Finding,
    FollowUpRequest,
    IncidentInput,
    NormalizedEvent,
    RiskLevel,
    ValidatedFinding,
    ValidationResult,
)
from sentinelai.store.log_store import LogStore
from sentinelai.validator.rules import validate_stage1
from sentinelai.validator.judge import validate_stage2
from sentinelai.validator.validator import EvidenceValidator


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_NOW = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def _make_event(
    event_id: str,
    user: str = "alice",
    src_ip: str = "192.0.2.1",
    event_type: str = "auth_failure",
    outcome: str = "failure",
    ts: datetime | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts or _NOW,
        source="test",
        event_type=event_type,
        user=user,
        src_ip=src_ip,
        host="server1",
        outcome=outcome,
        raw="{}",
    )


def _make_finding(
    claim: str,
    evidence_ids: list[str],
    confidence: float = 0.85,
    user: str = "alice",
    src_ip: str = "192.0.2.1",
) -> Finding:
    return Finding(
        agent="auth",
        claim=claim,
        evidence_event_ids=evidence_ids,
        entities=Entities(users=[user], ips=[src_ip]),
        confidence=confidence,
        reasoning="Test reasoning.",
    )


def _make_store_with_events(events: list[NormalizedEvent]) -> LogStore:
    store = LogStore(":memory:")
    store.load_events(events)
    return store


def _make_incident(events: list[NormalizedEvent]) -> IncidentInput:
    return IncidentInput(
        risk_level=RiskLevel.HIGH,
        events=events,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 Rule Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestStage1FabricatedCitation:
    """Rule 2: Fabricated event IDs that don't exist in the LogStore."""

    def setup_method(self):
        self.evt = _make_event("real-evt-001")
        self.store = _make_store_with_events([self.evt])

    def test_fabricated_event_id_is_rejected(self):
        finding = _make_finding(
            claim="User alice attempted 5 failures.",
            evidence_ids=["fake-evt-999"],
        )
        results = validate_stage1([finding], self.store)
        assert len(results) == 1
        vf = results[0]
        assert vf.verdict == ClaimVerdict.UNSUPPORTED
        assert vf.adjusted_confidence == 0.0
        assert any("do not exist" in i.lower() for i in vf.issues)

    def test_real_event_id_is_accepted(self):
        finding = _make_finding(
            claim="User alice failed to login.",
            evidence_ids=["real-evt-001"],
        )
        results = validate_stage1([finding], self.store)
        assert results[0].verdict != ClaimVerdict.UNSUPPORTED

    def test_mixed_real_and_fake_ids_is_weak(self):
        """Partial fabrication: some real, some fake => WEAK not UNSUPPORTED."""
        finding = _make_finding(
            claim="User alice failed to login.",
            evidence_ids=["real-evt-001", "fake-evt-000"],
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert vf.verdict == ClaimVerdict.WEAK
        assert vf.adjusted_confidence <= 0.50


class TestStage1SingleEventCap:
    """Rule 6: Single-event evidence cannot claim confidence > 0.60."""

    def setup_method(self):
        self.evt = _make_event("evt-single-001")
        self.store = _make_store_with_events([self.evt])

    def test_high_confidence_with_single_event_is_capped(self):
        finding = _make_finding(
            claim="User alice shows suspicious activity.",
            evidence_ids=["evt-single-001"],
            confidence=0.95,
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert vf.adjusted_confidence <= 0.60
        assert any("capped" in i.lower() for i in vf.issues)

    def test_low_confidence_with_single_event_is_unchanged(self):
        finding = _make_finding(
            claim="User alice shows suspicious activity.",
            evidence_ids=["evt-single-001"],
            confidence=0.40,
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert vf.adjusted_confidence <= 0.60
        assert not any("capped" in i.lower() for i in vf.issues)


class TestStage1EntityPresence:
    """Rule 3: Entities named in findings must appear in cited events."""

    def setup_method(self):
        self.evt = _make_event("evt-entity-001", user="alice", src_ip="192.0.2.1")
        self.store = _make_store_with_events([self.evt])

    def test_wrong_user_entity_degrades_finding(self):
        finding = Finding(
            agent="auth",
            claim="User bob failed login.",
            evidence_event_ids=["evt-entity-001"],
            entities=Entities(users=["bob"], ips=["192.0.2.1"]),
            confidence=0.85,
            reasoning="bob logged in.",
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert vf.verdict == ClaimVerdict.WEAK
        assert any("bob" in i for i in vf.issues)

    def test_correct_entities_pass(self):
        finding = Finding(
            agent="auth",
            claim="User alice failed login from 192.0.2.1.",
            evidence_event_ids=["evt-entity-001"],
            entities=Entities(users=["alice"], ips=["192.0.2.1"]),
            confidence=0.75,
            reasoning="alice attempted login.",
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert vf.verdict != ClaimVerdict.UNSUPPORTED
        assert not any("does not appear" in i for i in vf.issues)


class TestStage1NumericClaims:
    """Rule 4: Numeric claims must not wildly exceed cited events."""

    def setup_method(self):
        self.evt = _make_event("evt-num-001")
        self.store = _make_store_with_events([self.evt])

    def test_overclaimed_failures_are_weak(self):
        finding = _make_finding(
            claim="User alice made 50 failed logins.",
            evidence_ids=["evt-num-001"],
            confidence=0.90,
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert vf.verdict == ClaimVerdict.WEAK
        assert vf.adjusted_confidence <= 0.60
        assert any("50" in i for i in vf.issues)

    def test_matching_count_is_fine(self):
        finding = _make_finding(
            claim="User alice made 1 failed logins.",
            evidence_ids=["evt-num-001"],
            confidence=0.55,
        )
        results = validate_stage1([finding], self.store)
        vf = results[0]
        assert not any("Claim asserts" in i for i in vf.issues)


class TestStage1Deduplication:
    """Rule 7: Identical findings are deduplicated."""

    def setup_method(self):
        self.evt = _make_event("evt-dup-001")
        self.store = _make_store_with_events([self.evt])

    def test_duplicate_findings_produce_single_result(self):
        f1 = _make_finding("alice failed login.", ["evt-dup-001"])
        f2 = _make_finding("alice failed login.", ["evt-dup-001"])
        results = validate_stage1([f1, f2], self.store)
        assert len(results) == 1

    def test_different_findings_are_both_kept(self):
        f1 = _make_finding("alice failed login.", ["evt-dup-001"])
        f2 = _make_finding("alice succeeded login.", ["evt-dup-001"])
        results = validate_stage1([f1, f2], self.store)
        assert len(results) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 Judge Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestStage2Judge:
    """Stage 2: LLM-as-judge using FakeLLMClient scripted responses."""

    def setup_method(self):
        self.evt = _make_event("evt-judge-001", user="alice")
        self.store = _make_store_with_events([self.evt])

    def _stage1_pass(self, confidence: float = 0.55) -> list[ValidatedFinding]:
        finding = _make_finding(
            "alice shows suspicious auth pattern.", ["evt-judge-001"], confidence=confidence
        )
        return validate_stage1([finding], self.store)

    def test_judge_supports_strong_claim(self):
        stage1 = self._stage1_pass(0.55)
        llm = FakeLLMClient()
        llm.queue_response(
            '{"verdict": "supported", "issues": [], "adjusted_confidence": 0.75, "reasoning": "Claim is backed."}'
        )
        results = validate_stage2(stage1, self.store, llm)
        assert results[0].verdict == ClaimVerdict.SUPPORTED
        assert results[0].adjusted_confidence == pytest.approx(0.75, abs=0.01)

    def test_judge_downgrades_weak_claim(self):
        stage1 = self._stage1_pass(0.55)
        llm = FakeLLMClient()
        llm.queue_response(
            '{"verdict": "weak", "issues": ["Claim partially supported."], "adjusted_confidence": 0.45, "reasoning": "Only partial."}'
        )
        results = validate_stage2(stage1, self.store, llm)
        assert results[0].verdict == ClaimVerdict.WEAK
        assert results[0].adjusted_confidence <= 0.50

    def test_judge_preserves_stage1_result_on_llm_error(self):
        """If LLM returns garbage, fall back gracefully to Stage 1 result."""
        stage1 = self._stage1_pass(0.55)
        llm = FakeLLMClient()
        llm.queue_response("THIS IS NOT JSON")
        llm.queue_response("ALSO NOT JSON")
        results = validate_stage2(stage1, self.store, llm)
        assert len(results) == 1
        assert any("error" in i.lower() or "stage 2" in i.lower() for i in results[0].issues)

    def test_unsupported_stage1_skips_llm(self):
        """Completely fabricated citations => UNSUPPORTED from Stage 1, LLM is not called."""
        finding = _make_finding("alice fake claim.", ["nonexistent-id"])
        stage1 = validate_stage1([finding], self.store)
        assert stage1[0].verdict == ClaimVerdict.UNSUPPORTED

        llm = FakeLLMClient()
        results = validate_stage2(stage1, self.store, llm)
        assert len(llm.call_log) == 0
        assert results[0].verdict == ClaimVerdict.UNSUPPORTED


# ─────────────────────────────────────────────────────────────────────────────
# Contradiction Detection Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestContradictionDetection:
    """Cross-finding contradiction checker."""

    def setup_method(self):
        evts = [
            _make_event("evt-con-001", user="alice", src_ip="10.0.0.1",
                        event_type="auth_success", outcome="success"),
            _make_event("evt-con-002", user="alice", src_ip="10.0.0.1",
                        event_type="auth_failure", outcome="failure"),
        ]
        self.store = _make_store_with_events(evts)

    def test_contradicting_findings_are_downgraded(self):
        from sentinelai.validator.judge import _check_cross_finding_contradictions
        vf1 = ValidatedFinding(
            finding=_make_finding("successful login from alice.", ["evt-con-001"],
                                  confidence=0.8, user="alice", src_ip="10.0.0.1"),
            verdict=ClaimVerdict.SUPPORTED,
            adjusted_confidence=0.8,
        )
        vf2 = ValidatedFinding(
            finding=_make_finding("no successful login for alice was possible.", ["evt-con-002"],
                                  confidence=0.8, user="alice", src_ip="10.0.0.1"),
            verdict=ClaimVerdict.SUPPORTED,
            adjusted_confidence=0.8,
        )
        result = _check_cross_finding_contradictions([vf1, vf2])
        assert result[0].verdict == ClaimVerdict.CONTRADICTED
        assert result[1].verdict == ClaimVerdict.CONTRADICTED
        assert result[0].adjusted_confidence <= 0.40
        assert result[1].adjusted_confidence <= 0.40

    def test_non_contradicting_findings_pass_unchanged(self):
        from sentinelai.validator.judge import _check_cross_finding_contradictions
        vf1 = ValidatedFinding(
            finding=_make_finding("alice failed to login.", ["evt-con-001"],
                                  user="alice", src_ip="10.0.0.1"),
            verdict=ClaimVerdict.SUPPORTED,
            adjusted_confidence=0.75,
        )
        vf2 = ValidatedFinding(
            finding=_make_finding("alice accessed from unusual IP.", ["evt-con-002"],
                                  user="bob", src_ip="192.168.1.1"),
            verdict=ClaimVerdict.SUPPORTED,
            adjusted_confidence=0.70,
        )
        result = _check_cross_finding_contradictions([vf1, vf2])
        assert result[0].verdict == ClaimVerdict.SUPPORTED
        assert result[1].verdict == ClaimVerdict.SUPPORTED


# ─────────────────────────────────────────────────────────────────────────────
# EvidenceValidator Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceValidatorIntegration:
    """Full pipeline: Stage 1 -> Stage 2 -> sufficiency check."""

    def setup_method(self):
        self.events = [
            _make_event(f"evt-int-{i:03d}", user="alice", src_ip="10.0.0.1")
            for i in range(5)
        ]
        self.store = _make_store_with_events(self.events)
        self.incident = _make_incident(self.events)

    def test_supported_findings_are_sufficient(self):
        llm = FakeLLMClient()
        llm.queue_response(
            '{"verdict": "supported", "issues": [], "adjusted_confidence": 0.82, "reasoning": "Backed by evidence."}'
        )
        validator = EvidenceValidator(store=self.store, llm_client=llm)

        findings = [
            _make_finding(
                "alice made 5 failed login attempts from 10.0.0.1.",
                ["evt-int-000", "evt-int-001", "evt-int-002"],
                confidence=0.85,
            )
        ]
        result = validator.validate(findings, self.incident)
        assert result.sufficient is True
        assert result.overall_confidence > 0.0
        assert len(result.validated) == 1

    def test_no_findings_triggers_follow_up(self):
        """Empty findings set + thin evidence => follow-up requested => insufficient."""
        single_event = [_make_event("evt-thin-001")]
        store = _make_store_with_events(single_event)
        incident = _make_incident(single_event)

        llm = FakeLLMClient()
        validator = EvidenceValidator(store=store, llm_client=llm)
        result = validator.validate([], incident)

        assert result.sufficient is False
        assert len(result.follow_ups) >= 1
        assert result.follow_ups[0].target_agent == "auth"

    def test_all_unsupported_triggers_follow_up(self):
        """All findings fabricated => all UNSUPPORTED => follow-up generated."""
        llm = FakeLLMClient()
        validator = EvidenceValidator(store=self.store, llm_client=llm)

        findings = [
            _make_finding("alice did something.", ["totally-fake-id"], confidence=0.9)
        ]
        result = validator.validate(findings, self.incident)
        assert len(result.follow_ups) >= 1

    def test_validation_result_has_limitations_for_rejected_findings(self):
        llm = FakeLLMClient()
        llm.queue_response(
            '{"verdict": "supported", "issues": [], "adjusted_confidence": 0.80, "reasoning": "ok"}'
        )
        validator = EvidenceValidator(store=self.store, llm_client=llm)
        findings = [
            _make_finding("alice fake.", ["nonexistent-999"]),
            _make_finding("alice real.", ["evt-int-000", "evt-int-001", "evt-int-002"],
                          confidence=0.75),
        ]
        result = validator.validate(findings, self.incident)
        assert any("unsupported" in lim.lower() or "rejected" in lim.lower()
                   for lim in result.limitations)

    def test_validated_findings_alias_works(self):
        """ValidationResult.findings is a property alias for ValidationResult.validated."""
        vf = ValidatedFinding(
            finding=_make_finding("test claim.", ["evt-int-000"]),
            verdict=ClaimVerdict.SUPPORTED,
            adjusted_confidence=0.75,
        )
        vr = ValidationResult(
            validated=[vf], sufficient=True, overall_confidence=0.75,
        )
        assert vr.findings == vr.validated
        assert len(vr.findings) == 1


# ─────────────────────────────────────────────────────────────────────────────
# FollowUpRequest schema tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFollowUpRequest:
    def test_basic_follow_up_request(self):
        fr = FollowUpRequest(
            target_agent="auth",
            question="How many failed logins from 10.0.0.1 in the past 24h?",
            reason="Need count to verify brute force claim.",
        )
        assert fr.target_agent == "auth"
        assert "10.0.0.1" in fr.question

    def test_follow_up_with_suggested_tools(self):
        fr = FollowUpRequest(
            target_agent="timeline",
            question="What events occurred for user alice after the last failure?",
            suggested_tools=["query_events", "build_timeline"],
        )
        assert "query_events" in fr.suggested_tools

    def test_follow_up_reason_is_optional(self):
        """reason field defaults to empty string."""
        fr = FollowUpRequest(
            target_agent="auth",
            question="Any privilege escalations?",
        )
        assert fr.reason == ""


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 Acceptance Gate: Thin Evidence Re-Investigation Loop
# ─────────────────────────────────────────────────────────────────────────────

class TestThinEvidenceReinvestigationLoop:
    """Acceptance criterion: Thin-evidence scenario loops up to MAX_VALIDATION_LOOPS."""

    def test_thin_evidence_loops_up_to_max_validation_loops(self):
        from data.synthetic.generators import thin_evidence
        from sentinelai.agents.schemas import AgentAction
        from sentinelai.orchestrator.graph import build_investigation_graph
        from sentinelai.tools import create_default_registry

        scenario = thin_evidence()
        store = LogStore(":memory:")
        store.load_incident(scenario.incident)
        registry = create_default_registry(store)
        client = FakeLLMClient()

        # Agents report thin / empty findings
        empty_action = AgentAction(
            thought="Only 1 event available, nothing concrete found.",
            findings=[],
            is_complete=True,
        )

        client.register("auth", ScriptedResponse(content=empty_action.model_dump_json()))
        client.register("timeline", ScriptedResponse(content=empty_action.model_dump_json()))

        # For subsequent loops, auth agent receives follow-up questions
        for _ in range(10):
            client.enqueue(ScriptedResponse(content=empty_action.model_dump_json()))

        graph = build_investigation_graph(registry, client, max_validation_loops=2)
        state = graph.invoke({"incident": scenario.incident})

        # Acceptance gate 1: Bounded loop reached MAX_VALIDATION_LOOPS = 2
        assert state.get("loop_count") == 2

        # Acceptance gate 2: Validation result reflects thin evidence
        val = state.get("validation")
        assert val is not None
        assert val.sufficient is False
        assert val.overall_confidence <= 0.50

        # Acceptance gate 3: Limitations track validation loop invocations
        limitations = state.get("limitations", [])
        assert any("loop" in lim.lower() for lim in limitations)

