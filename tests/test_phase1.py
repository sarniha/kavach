"""
tests/test_phase1.py
────────────────────
Phase 1 acceptance tests.

Acceptance criteria
-------------------
* All schemas validate correctly (happy paths and error paths).
* All six synthetic scenarios load into the DuckDB LogStore.
* FakeLLMClient works: scripted responses, malformed-output path,
  concurrency behaviour.
* StructuredOutputError is raised correctly by chat_json on double failure.
* Config reads from environment variables and has safe offline defaults.
* Groq-specific: rate-limiter and StructuredOutputError are importable
  without the groq SDK causing failures (the SDK is optional at test time
  because LLM_PROVIDER=fake).

Run with:
    pytest tests/test_phase1.py -v
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sentinelai.config import LLMProvider, Settings
from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse
from sentinelai.llm.protocol import LLMMessage, StructuredOutputError
from sentinelai.schemas import (
    AnalystFeedback,
    ArchiveDecision,
    ClaimVerdict,
    Entities,
    Finding,
    FollowUpRequest,
    IncidentInput,
    InvestigationReport,
    NormalizedEvent,
    RiskLevel,
    RuleMatch,
    TimelineEntry,
    ValidatedFinding,
    ValidationResult,
    _merge_findings,
    _merge_limitations,
    _merge_token_usage,
)
from sentinelai.store.log_store import LogStore
from data.synthetic.generators import (
    brute_force_then_success,
    password_spraying,
    lateral_movement,
    benign_false_positive,
    thin_evidence,
    prompt_injection,
    get_all_scenarios,
)

_UTC = timezone.utc
_NOW = datetime(2025, 6, 1, 0, 0, 0, tzinfo=_UTC)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def store() -> LogStore:
    """In-memory log store, fresh per test."""
    return LogStore(":memory:")


@pytest.fixture()
def brute_force():
    return brute_force_then_success()


@pytest.fixture()
def fake_llm() -> FakeLLMClient:
    return FakeLLMClient()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Schema validation
# ─────────────────────────────────────────────────────────────────────────────

class TestSchemas:
    def test_normalized_event_valid(self):
        e = NormalizedEvent(
            event_id="evt-001",
            timestamp=_NOW,
            source="syslog",
            host="web-01",
            user="admin",
            src_ip="192.0.2.1",
            event_type="auth_failure",
            outcome="failure",
            raw="Failed password for admin from 192.0.2.1",
        )
        assert e.event_id == "evt-001"
        assert e.fields == {}

    def test_finding_requires_evidence_ids(self):
        """A Finding with an empty evidence list must be rejected."""
        with pytest.raises(ValidationError):
            Finding(
                agent="auth",
                claim="something happened",
                evidence_event_ids=[],   # violates min_length=1
                confidence=0.8,
                reasoning="test",
            )

    def test_finding_rejects_blank_event_id(self):
        """Evidence IDs must not be empty strings."""
        with pytest.raises(ValidationError):
            Finding(
                agent="auth",
                claim="something happened",
                evidence_event_ids=["   "],  # blank string
                confidence=0.8,
                reasoning="test",
            )

    def test_finding_valid(self):
        f = Finding(
            agent="auth",
            claim="30 failed logins from 192.0.2.10 in 60 seconds",
            evidence_event_ids=["evt-001", "evt-002"],
            confidence=0.9,
            mitre_hint="T1110",
            reasoning="Count of auth_failure events matches brute-force pattern",
        )
        assert f.confidence == 0.9
        assert f.mitre_hint == "T1110"

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            Finding(
                agent="auth",
                claim="x",
                evidence_event_ids=["e1"],
                confidence=1.5,  # > 1
                reasoning="x",
            )

    def test_incident_input_valid(self):
        evt = NormalizedEvent(
            event_id="e1", timestamp=_NOW, source="syslog",
            event_type="auth_failure", raw="raw log",
        )
        inc = IncidentInput(
            incident_id="inc-001",
            risk_level=RiskLevel.HIGH,
            created_at=_NOW,
            events=[evt],
        )
        assert inc.risk_level == RiskLevel.HIGH
        assert len(inc.events) == 1

    def test_incident_requires_at_least_one_event(self):
        with pytest.raises(ValidationError):
            IncidentInput(
                incident_id="inc-empty",
                risk_level=RiskLevel.MEDIUM,
                created_at=_NOW,
                events=[],
            )

    def test_entities_merge(self):
        a = Entities(ips=["1.1.1.1"], users=["alice"])
        b = Entities(ips=["2.2.2.2"], users=["alice", "bob"])
        merged = a.merge(b)
        assert "1.1.1.1" in merged.ips
        assert "2.2.2.2" in merged.ips
        assert merged.users.count("alice") == 1  # deduplication

    def test_rule_match(self):
        rm = RuleMatch(
            rule_id="sigma-001",
            title="Test Rule",
            level="high",
            matched_event_ids=["e1", "e2"],
        )
        assert rm.rule_id == "sigma-001"

    def test_archive_decision(self):
        ad = ArchiveDecision(incident_id="inc-001", risk_level=RiskLevel.LOW)
        assert "LLM" in ad.reason

    def test_analyst_feedback(self):
        fb = AnalystFeedback(
            incident_id="inc-001",
            verdict="true_positive",
            severity_correct=True,
        )
        assert fb.verdict == "true_positive"

    def test_validated_finding(self):
        f = Finding(
            agent="auth", claim="x", evidence_event_ids=["e1"],
            confidence=0.7, reasoning="y",
        )
        vf = ValidatedFinding(
            finding=f,
            verdict=ClaimVerdict.SUPPORTED,
            adjusted_confidence=0.7,
        )
        assert vf.verdict == ClaimVerdict.SUPPORTED

    def test_validation_result(self):
        f = Finding(
            agent="auth", claim="x", evidence_event_ids=["e1"],
            confidence=0.7, reasoning="y",
        )
        vf = ValidatedFinding(
            finding=f, verdict=ClaimVerdict.WEAK, adjusted_confidence=0.5
        )
        fr = FollowUpRequest(
            target_agent="auth",
            question="How many total failures from 192.0.2.1?",
            reason="Need count to verify the claim",
        )
        vr = ValidationResult(
            validated=[vf], sufficient=False,
            follow_ups=[fr], overall_confidence=0.5,
        )
        assert not vr.sufficient
        assert len(vr.follow_ups) == 1

    def test_timeline_entry_requires_event_ids(self):
        with pytest.raises(ValidationError):
            TimelineEntry(
                timestamp=_NOW,
                description="something",
                event_ids=[],  # min_length=1
            )


# ─────────────────────────────────────────────────────────────────────────────
# 2. LangGraph reducer helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestReducers:
    def _make_finding(self, agent: str, eid: str) -> Finding:
        return Finding(
            agent=agent, claim="x", evidence_event_ids=[eid],
            confidence=0.5, reasoning="y",
        )

    def test_merge_findings_appends(self):
        f1 = self._make_finding("auth", "e1")
        f2 = self._make_finding("timeline", "e2")
        merged = _merge_findings([f1], [f2])
        assert len(merged) == 2
        assert merged[0].agent == "auth"
        assert merged[1].agent == "timeline"

    def test_merge_limitations(self):
        merged = _merge_limitations(["loop cap hit"], ["token budget exceeded"])
        assert len(merged) == 2

    def test_merge_token_usage(self):
        a = {"auth": 100, "timeline": 200}
        b = {"auth": 50, "correlation": 300}
        merged = _merge_token_usage(a, b)
        assert merged["auth"] == 150
        assert merged["timeline"] == 200
        assert merged["correlation"] == 300


# ─────────────────────────────────────────────────────────────────────────────
# 3. LogStore
# ─────────────────────────────────────────────────────────────────────────────

class TestLogStore:
    def test_load_and_count(self, store: LogStore, brute_force):
        n = store.load_incident(brute_force.incident)
        assert n == len(brute_force.incident.events)
        assert store.count_events() == n

    def test_event_exists(self, store: LogStore, brute_force):
        store.load_incident(brute_force.incident)
        assert store.event_exists("bf-success-001")
        assert not store.event_exists("nonexistent-id")

    def test_get_event(self, store: LogStore, brute_force):
        store.load_incident(brute_force.incident)
        row = store.get_event("bf-success-001")
        assert row is not None
        assert row["event_type"] == "auth_success"
        assert row["outcome"] == "success"

    def test_idempotent_load(self, store: LogStore, brute_force):
        """Loading the same incident twice must not duplicate rows."""
        n1 = store.load_incident(brute_force.incident)
        n2 = store.load_incident(brute_force.incident)
        assert n1 == n2
        assert store.count_events() == n1  # not doubled

    def test_query(self, store: LogStore, brute_force):
        store.load_incident(brute_force.incident)
        rows = store.query(
            "SELECT event_id FROM events WHERE event_type = ?",
            ["auth_success"],
        )
        assert len(rows) == 1
        assert rows[0]["event_id"] == "bf-success-001"

    def test_background_events_separate(self, store: LogStore, brute_force):
        store.load_incident(brute_force.incident)
        store.load_events(brute_force.incident.events, background=True)
        # Incident events in 'events', background events in 'background_events'
        assert store.count_events(background=False) > 0
        assert store.count_events(background=True) > 0

    def test_all_event_ids(self, store: LogStore, brute_force):
        store.load_incident(brute_force.incident)
        ids = store.all_event_ids()
        assert "bf-success-001" in ids
        assert len(ids) == store.count_events()

    def test_clear(self, store: LogStore, brute_force):
        store.load_incident(brute_force.incident)
        store.clear()
        assert store.count_events() == 0

    def test_context_manager(self, brute_force):
        with LogStore(":memory:") as s:
            s.load_incident(brute_force.incident)
            assert s.count_events() > 0

    def test_bad_incident_type_raises(self, store: LogStore):
        with pytest.raises(TypeError):
            store.load_incident({"not": "an incident"})


# ─────────────────────────────────────────────────────────────────────────────
# 4. Synthetic scenarios load into the store
# ─────────────────────────────────────────────────────────────────────────────

class TestSyntheticScenarios:
    @pytest.mark.parametrize("gen,expected_min_events", [
        (brute_force_then_success, 10),
        (password_spraying, 20),
        (lateral_movement, 5),
        (benign_false_positive, 4),
        (thin_evidence, 1),
        (prompt_injection, 6),
    ])
    def test_scenario_loads_into_store(self, gen, expected_min_events):
        scenario = gen()
        store = LogStore(":memory:")
        n = store.load_incident(scenario.incident)
        assert n >= expected_min_events
        assert store.count_events() == n
        store.close()

    def test_all_scenarios_have_at_least_one_event(self):
        for scenario in get_all_scenarios():
            assert len(scenario.incident.events) >= 1

    def test_all_scenarios_have_unique_event_ids(self):
        for scenario in get_all_scenarios():
            ids = [e.event_id for e in scenario.incident.events]
            assert len(ids) == len(set(ids)), f"Duplicate IDs in {scenario.ground_truth.scenario}"

    def test_brute_force_has_failures_then_success(self):
        s = brute_force_then_success()
        event_types = [e.event_type for e in s.incident.events]
        assert "auth_failure" in event_types
        assert "auth_success" in event_types
        # Success must come AFTER all failures
        failures_ts = [e.timestamp for e in s.incident.events if e.event_type == "auth_failure"]
        success_ts = [e.timestamp for e in s.incident.events if e.event_type == "auth_success"]
        assert max(failures_ts) < min(success_ts)

    def test_brute_force_ground_truth(self):
        s = brute_force_then_success()
        assert s.ground_truth.expected_verdict == "true_positive"
        assert "T1110" in s.ground_truth.expected_mitre_techniques

    def test_prompt_injection_contains_injection_string(self):
        s = prompt_injection()
        raw_texts = [e.raw for e in s.incident.events]
        injection_found = any("ignore previous instructions" in r for r in raw_texts)
        assert injection_found, "Injection event not found in scenario"

    def test_benign_fp_should_suppress_escalation(self):
        s = benign_false_positive()
        assert s.ground_truth.should_suppress_escalation

    def test_thin_evidence_should_trigger_follow_up(self):
        s = thin_evidence()
        assert s.ground_truth.should_trigger_follow_up
        assert len(s.incident.events) == 1

    def test_lateral_movement_is_critical(self):
        s = lateral_movement()
        assert s.incident.risk_level == RiskLevel.CRITICAL


# ─────────────────────────────────────────────────────────────────────────────
# 5. FakeLLMClient
# ─────────────────────────────────────────────────────────────────────────────

class TestFakeLLMClient:
    def test_default_response(self, fake_llm: FakeLLMClient):
        msg = LLMMessage(role="user", content="hello")
        resp = fake_llm.chat([msg])
        assert resp.content == '{"status": "ok"}'
        assert resp.model == "fake-llm"

    def test_flat_queue(self, fake_llm: FakeLLMClient):
        fake_llm.enqueue(ScriptedResponse(content='{"finding": "brute_force"}'))
        resp = fake_llm.chat([LLMMessage(role="user", content="analyse")])
        assert resp.content == '{"finding": "brute_force"}'

    def test_keyed_queue(self, fake_llm: FakeLLMClient):
        fake_llm.register("auth", ScriptedResponse(content='{"agent": "auth"}'))
        resp = fake_llm.chat([LLMMessage(role="user", content="x")], key="auth")
        assert resp.content == '{"agent": "auth"}'

    def test_fallback_to_flat_when_key_empty(self, fake_llm: FakeLLMClient):
        fake_llm.enqueue_json({"fallback": True})
        resp = fake_llm.chat([LLMMessage(role="user", content="x")], key="nonexistent")
        data = json.loads(resp.content)
        assert data["fallback"] is True

    def test_call_log_records_calls(self, fake_llm: FakeLLMClient):
        fake_llm.chat([LLMMessage(role="user", content="test")])
        assert fake_llm.total_calls == 1
        assert len(fake_llm.call_log) == 1

    def test_reset_clears_state(self, fake_llm: FakeLLMClient):
        fake_llm.enqueue_json({"x": 1})
        fake_llm.chat([LLMMessage(role="user", content="x")])
        fake_llm.reset()
        assert fake_llm.total_calls == 0
        assert len(fake_llm.call_log) == 0

    def test_chat_json_success(self, fake_llm: FakeLLMClient):
        from pydantic import BaseModel

        class MyModel(BaseModel):
            value: int

        fake_llm.enqueue_json({"value": 42})
        result = fake_llm.chat_json(
            [LLMMessage(role="user", content="give me json")],
            MyModel,
        )
        assert result.value == 42

    def test_chat_json_malformed_then_valid(self, fake_llm: FakeLLMClient):
        """First response malformed, second valid → success after retry."""
        from pydantic import BaseModel

        class MyModel(BaseModel):
            value: int

        fake_llm.enqueue_malformed()                   # first call: bad JSON
        fake_llm.enqueue_json({"value": 99})           # retry: good JSON

        result = fake_llm.chat_json(
            [LLMMessage(role="user", content="give me json")],
            MyModel,
        )
        assert result.value == 99
        assert fake_llm.total_calls == 2               # consumed 2 calls

    def test_chat_json_double_malformed_raises(self, fake_llm: FakeLLMClient):
        """Both responses malformed → StructuredOutputError."""
        from pydantic import BaseModel

        class MyModel(BaseModel):
            value: int

        fake_llm.enqueue_malformed()
        fake_llm.enqueue_malformed()

        with pytest.raises(StructuredOutputError):
            fake_llm.chat_json(
                [LLMMessage(role="user", content="give me json")],
                MyModel,
            )

    def test_model_name(self, fake_llm: FakeLLMClient):
        assert fake_llm.model_name == "fake-llm"

    def test_use_fast_model_does_not_change_behaviour(self, fake_llm: FakeLLMClient):
        """use_fast_model is a no-op for FakeLLMClient."""
        fake_llm.enqueue_json({"ok": True})
        resp = fake_llm.chat(
            [LLMMessage(role="user", content="x")],
            use_fast_model=True,
        )
        assert json.loads(resp.content)["ok"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 6. Config
# ─────────────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_provider_is_fake(self):
        s = Settings()
        assert s.llm_provider == LLMProvider.FAKE

    def test_offline_mode_by_default(self):
        s = Settings()
        assert s.is_offline_mode

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "groq")
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        s = Settings()
        assert s.llm_provider == LLMProvider.GROQ
        assert s.groq_api_key == "test-key"

    def test_max_tokens_positive(self):
        s = Settings()
        assert s.max_tokens_per_incident > 0

    def test_confidence_caps_in_range(self):
        s = Settings()
        assert 0 <= s.single_event_confidence_cap <= 1
        assert 0 <= s.intel_only_confidence_cap <= 1

    def test_groq_rate_limits_positive(self):
        s = Settings()
        assert s.groq_rpm_limit > 0
        assert s.groq_tpm_limit > 0
        assert s.max_concurrent_llm_calls >= 1


# ─────────────────────────────────────────────────────────────────────────────
# 7. Groq rate-limiter (importable without groq SDK; unit test only)
# ─────────────────────────────────────────────────────────────────────────────

class TestGroqRateLimiter:
    """Tests the _SlidingWindowRateLimiter in isolation."""

    def test_allows_under_rpm_limit(self):
        from sentinelai.llm.groq import _SlidingWindowRateLimiter

        limiter = _SlidingWindowRateLimiter(rpm=5, tpm=10_000)
        for _ in range(5):
            limiter.acquire(estimated_tokens=10)
        # Should complete without blocking

    def test_blocks_over_rpm_limit(self):
        import threading
        import time
        from sentinelai.llm.groq import _SlidingWindowRateLimiter

        limiter = _SlidingWindowRateLimiter(rpm=2, tpm=10_000)
        limiter.acquire()
        limiter.acquire()

        # Third acquire should block; test with short timeout raises error
        with pytest.raises(Exception):
            limiter.acquire(timeout=0.1)

    def test_reset_shared_resources(self):
        from sentinelai.llm.groq import reset_shared_resources, _get_shared_resources

        reset_shared_resources()
        lim1, sem1 = _get_shared_resources(10, 1000, 2)
        lim2, sem2 = _get_shared_resources(10, 1000, 2)
        assert lim1 is lim2  # same singleton
        assert sem1 is sem2
        reset_shared_resources()  # cleanup
