"""
tests/test_orchestrator.py
──────────────────────────
Phase 4 acceptance tests: Orchestrator, fan-out routing, and merge node.

Acceptance criteria
-------------------
* Low/Ignore incident routes to archive_node (no LLM calls, returns ArchiveDecision).
* Medium incident runs exactly 2 agents (auth, timeline).
* High/Critical incident runs exactly 3 agents (auth, timeline, correlation).
* RL metadata strategy override is respected.
* Findings from parallel agents merge without data loss.
* Duplicate findings are deduplicated by merge_node.
* Entities are aggregated into entities_index.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from data.synthetic.generators import (
    benign_false_positive,
    brute_force_then_success,
    lateral_movement,
)
from sentinelai.agents.schemas import AgentAction, FindingDraft
from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse
from sentinelai.orchestrator import (
    build_investigation_graph,
    plan_investigation,
)
from sentinelai.schemas import (
    Entities,
    IncidentInput,
    NormalizedEvent,
    RiskLevel,
    TimelineEntry,
)
from sentinelai.store.log_store import LogStore
from sentinelai.tools import create_default_registry


@pytest.fixture
def low_incident() -> IncidentInput:
    return IncidentInput(
        incident_id="incident-low-001",
        risk_level=RiskLevel.LOW,
        created_at=datetime.now(timezone.utc),
        events=[
            NormalizedEvent(
                event_id="low-evt-001",
                timestamp=datetime.now(timezone.utc),
                source="syslog",
                event_type="info",
                raw="informational ping",
            )
        ],
    )


class TestOrchestratorPlanningAndRouting:
    def test_low_incident_routes_to_archive(self, low_incident: IncidentInput) -> None:
        plan = plan_investigation(low_incident)
        assert plan["route"] == "archive"
        assert plan["selected_agents"] == []

    def test_medium_incident_plans_two_agents(self) -> None:
        scenario = benign_false_positive()  # risk_level is MEDIUM
        plan = plan_investigation(scenario.incident)
        assert plan["route"] == "fan_out"
        assert plan["selected_agents"] == ["auth", "timeline"]
        assert len(plan["selected_agents"]) == 2

    def test_high_incident_plans_three_agents(self) -> None:
        scenario = brute_force_then_success()  # risk_level is HIGH
        plan = plan_investigation(scenario.incident)
        assert plan["route"] == "fan_out"
        assert plan["selected_agents"] == ["auth", "timeline", "correlation"]
        assert len(plan["selected_agents"]) == 3

    def test_critical_incident_plans_three_agents(self) -> None:
        scenario = lateral_movement()  # risk_level is CRITICAL
        plan = plan_investigation(scenario.incident)
        assert plan["route"] == "fan_out"
        assert plan["selected_agents"] == ["auth", "timeline", "correlation"]
        assert len(plan["selected_agents"]) == 3

    def test_rl_strategy_override(self, low_incident: IncidentInput) -> None:
        # Override low incident to run custom strategy
        low_incident.rl_metadata["selected_strategy"] = ["auth", "correlation"]
        plan = plan_investigation(low_incident)
        assert plan["route"] == "fan_out"
        assert plan["selected_agents"] == ["auth", "correlation"]
        assert plan["source"] == "rl_override"


class TestInvestigationGraphExecution:
    def test_archive_workflow_no_llm_calls(self, low_incident: IncidentInput) -> None:
        store = LogStore()
        store.load_incident(low_incident)
        registry = create_default_registry(store)
        client = FakeLLMClient()

        graph = build_investigation_graph(registry, client)
        state = graph.invoke({"incident": low_incident})

        # Archive node ran
        assert state.get("archive_decision") is not None
        assert state["archive_decision"].incident_id == "incident-low-001"
        # Zero LLM calls used
        assert len(client.call_log) == 0
        assert len(state.get("findings", [])) == 0

    def test_medium_incident_runs_two_agents(self) -> None:
        scenario = benign_false_positive()  # Medium risk -> Auth + Timeline
        store = LogStore()
        store.load_incident(scenario.incident)
        registry = create_default_registry(store)
        client = FakeLLMClient()

        # Script responses for auth and timeline
        auth_action = AgentAction(
            thought="Auth analysis: low failed login count.",
            findings=[
                FindingDraft(
                    claim="User j.smith mistyped password 3 times then succeeded.",
                    evidence_event_ids=["fp-fail-0", "fp-success-001"],
                    entities=Entities(users=["j.smith"], ips=["198.51.100.100"]),
                    confidence=0.85,
                    reasoning="Normal mistyped login.",
                )
            ],
            is_complete=True,
        )

        timeline_action = AgentAction(
            thought="Timeline reconstruction complete.",
            findings=[
                FindingDraft(
                    claim="Authentication attempts spanned 35 seconds.",
                    evidence_event_ids=["fp-fail-0", "fp-success-001"],
                    entities=Entities(users=["j.smith"]),
                    confidence=0.90,
                    reasoning="Short duration sequence.",
                )
            ],
            timeline_entries=[
                TimelineEntry(
                    timestamp=scenario.incident.events[0].timestamp,
                    description="First failed login",
                    event_ids=["fp-fail-0"],
                    mitre_tactic="Initial Access",
                )
            ],
            is_complete=True,
        )

        client.register("auth", ScriptedResponse(content=auth_action.model_dump_json()))
        client.register("timeline", ScriptedResponse(content=timeline_action.model_dump_json()))

        graph = build_investigation_graph(registry, client)
        state = graph.invoke({"incident": scenario.incident})

        # Acceptance gate: Exactly 2 agents executed
        agents_run = state["trace"]["agents"]
        assert set(agents_run.keys()) == {"auth", "timeline"}
        assert len(agents_run) == 2

        # Acceptance gate: Findings merged without data loss
        findings = state["findings"]
        assert len(findings) == 2
        claims = [f.claim for f in findings]
        assert any("mistyped password" in c for c in claims)
        assert any("spanned 35 seconds" in c for c in claims)

        # Timeline entries collected
        assert len(state["timeline_entries"]) == 1
        assert state["timeline_entries"][0].event_ids == ["fp-fail-0"]

        # Entities indexed in entities_index
        assert "j.smith" in state["entities_index"].users
        assert "198.51.100.100" in state["entities_index"].ips

    def test_high_incident_runs_three_agents(self) -> None:
        scenario = brute_force_then_success(n_failures=5)  # High risk -> Auth, Timeline, Correlation
        store = LogStore()
        store.load_incident(scenario.incident)
        registry = create_default_registry(store)
        client = FakeLLMClient()

        # Script response for all 3 agents
        auth_action = AgentAction(
            thought="Auth: confirmed brute force.",
            findings=[
                FindingDraft(
                    claim="Brute force against admin.",
                    evidence_event_ids=["bf-fail-000", "bf-success-001"],
                    entities=Entities(users=["admin"], ips=["192.0.2.10"]),
                    confidence=0.95,
                    mitre_hint="T1110",
                    reasoning="Observed burst failures then success.",
                )
            ],
            is_complete=True,
        )

        timeline_action = AgentAction(
            thought="Timeline: sequence reconstruct.",
            findings=[
                FindingDraft(
                    claim="Attack progression over 12 seconds.",
                    evidence_event_ids=["bf-fail-000", "bf-success-001"],
                    entities=Entities(hosts=["web-01.internal"]),
                    confidence=0.85,
                    reasoning="Rapid event rate.",
                )
            ],
            is_complete=True,
        )

        correlation_action = AgentAction(
            thought="Correlation: IP to host mappings.",
            findings=[
                FindingDraft(
                    claim="IP 192.0.2.10 targeted host web-01.internal exclusively.",
                    evidence_event_ids=["bf-fail-000", "bf-success-001"],
                    entities=Entities(ips=["192.0.2.10"], hosts=["web-01.internal"]),
                    confidence=0.90,
                    reasoning="Single source to single destination.",
                )
            ],
            is_complete=True,
        )

        client.register("auth", ScriptedResponse(content=auth_action.model_dump_json()))
        client.register("timeline", ScriptedResponse(content=timeline_action.model_dump_json()))
        client.register("correlation", ScriptedResponse(content=correlation_action.model_dump_json()))

        graph = build_investigation_graph(registry, client)
        state = graph.invoke({"incident": scenario.incident})

        # Acceptance gate: Exactly 3 agents executed
        agents_run = state["trace"]["agents"]
        assert set(agents_run.keys()) == {"auth", "timeline", "correlation"}
        assert len(agents_run) == 3

        # Acceptance gate: Findings merged without data loss
        findings = state["findings"]
        assert len(findings) == 3

        # All entities combined into entities_index
        entities = state["entities_index"]
        assert "admin" in entities.users
        assert "192.0.2.10" in entities.ips
        assert "web-01.internal" in entities.hosts


class TestMergeNodeDeduplication:
    def test_merge_node_deduplicates_identical_findings(self) -> None:
        scenario = brute_force_then_success(n_failures=5)
        store = LogStore()
        store.load_incident(scenario.incident)
        registry = create_default_registry(store)
        client = FakeLLMClient()

        # Two agents emit the exact same claim and evidence IDs
        duplicate_finding = FindingDraft(
            claim="Brute force against admin.",
            evidence_event_ids=["bf-fail-000", "bf-success-001"],
            entities=Entities(users=["admin"]),
            confidence=0.9,
            reasoning="Same finding.",
        )

        client.register(
            "auth",
            ScriptedResponse(
                content=AgentAction(findings=[duplicate_finding], is_complete=True).model_dump_json()
            ),
        )
        client.register(
            "timeline",
            ScriptedResponse(
                content=AgentAction(findings=[duplicate_finding], is_complete=True).model_dump_json()
            ),
        )
        client.register(
            "correlation",
            ScriptedResponse(
                content=AgentAction(
                    findings=[
                        FindingDraft(
                            claim="Distinct correlation finding.",
                            evidence_event_ids=["bf-fail-000"],
                            confidence=0.6,
                            reasoning="Distinct claim.",
                        )
                    ],
                    is_complete=True,
                ).model_dump_json()
            ),
        )

        graph = build_investigation_graph(registry, client)
        state = graph.invoke({"incident": scenario.incident})

        # 3 findings were produced total, but 2 were identical, so merge_node deduplicates to 2
        findings = state["findings"]
        assert len(findings) == 2
        claims = [f.claim for f in findings]
        assert claims.count("Brute force against admin.") == 1
        assert "Distinct correlation finding." in claims
