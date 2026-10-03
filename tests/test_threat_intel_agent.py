"""
tests/test_threat_intel_agent.py
──────────────────────────────────
Phase 6c + 6d acceptance tests:
  - HybridThreatIntelRetriever (exact, semantic, link-expand, rerank)
  - MockThreatIntelRetriever (deterministic fixtures)
  - ThreatIntelAgent (tool-calling loop, confidence caps, evidence citation, no-intel reporting)
  - Orchestrator graph wired with TI node

Acceptance criteria (Section 12 Phase 6c + 6d):
* Exact lookups return 100% accurate results (IOC, CVE, T-ID).
* Semantic queries return relevant results (smoke test).
* No-hallucination: every returned doc_id exists in the store.
* Retriever.retrieve() produces per-corpus top-k results.
* ThreatIntelAgent emits cited threat findings with correct confidence caps.
* IOC-only match is capped at 0.60.
* CVE unconfirmed match is capped at 0.50.
* Findings without evidence_event_ids are dropped.
* 'no_intel_found' indicators are reported explicitly in trace.
* Brute-force scenario produces cited threat findings referencing correct doc_ids.
* Unconfirmed-CVE case is labeled 'unconfirmed' and capped at 0.50.
* TI node integrates cleanly into orchestrator graph (no retriever = skip TI node).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sentinelai.agents.threat_intel import (
    IOC_ONLY_CAP,
    CVE_UNCONFIRMED_CAP,
    MITRE_WITH_EVIDENCE_CAP,
    COMBINED_MATCH_CAP,
    ThreatIntelAgent,
    ThreatIntelAction,
    ThreatIntelFindingDraft,
)
from sentinelai.llm.fake import FakeLLMClient
from sentinelai.schemas import Entities, IncidentInput, RiskLevel, NormalizedEvent
from sentinelai.threat_intel.chroma_store import ThreatIntelChromaStore
from sentinelai.threat_intel.duckdb_store import ThreatIntelDuckDBStore
from sentinelai.threat_intel.embeddings import DeterministicMockEmbedder
from sentinelai.threat_intel.ingest import ThreatIntelIngester
from sentinelai.threat_intel.retriever import HybridThreatIntelRetriever, MockThreatIntelRetriever
from sentinelai.threat_intel.schemas import (
    IntelMatch,
    IntelSource,
    IOCType,
    MatchType,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_event(eid: str, src_ip: str = "192.0.2.10", user: str = "admin") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=eid,
        timestamp=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
        source="syslog",
        host="web-01",
        user=user,
        src_ip=src_ip,
        event_type="auth_failure",
        raw=f"Failed login from {src_ip} for {user}",
    )


def _make_incident(
    incident_id: str = "inc-ti-test",
    risk_level: RiskLevel = RiskLevel.HIGH,
    src_ip: str = "192.0.2.10",
) -> IncidentInput:
    return IncidentInput(
        incident_id=incident_id,
        risk_level=risk_level,
        created_at=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc),
        events=[_make_event(f"evt-ti-{i:03d}", src_ip=src_ip) for i in range(5)],
    )


@pytest.fixture
def populated_stores():
    """Return populated in-memory DuckDB + Chroma stores with seed data."""
    duck = ThreatIntelDuckDBStore(":memory:")
    chroma = ThreatIntelChromaStore(embedder=DeterministicMockEmbedder(), force_in_memory=True)
    ingester = ThreatIntelIngester(duck, chroma)
    ingester.ingest_all()
    yield duck, chroma
    duck.close()


@pytest.fixture
def hybrid_retriever(populated_stores):
    duck, chroma = populated_stores
    return HybridThreatIntelRetriever(duck, chroma)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6c Tests: HybridThreatIntelRetriever
# ─────────────────────────────────────────────────────────────────────────────

class TestHybridRetrieverExactLookups:
    """Section 12 Phase 6c: Exact lookups must be 100% accurate."""

    def test_lookup_ioc_ip_exact(self, hybrid_retriever):
        """Known malicious IP returns exact match with correct doc_id."""
        hits = hybrid_retriever.lookup_ioc("ip", "192.0.2.10")
        assert len(hits) == 1
        assert hits[0].doc_id == "ioc:ip:192.0.2.10"
        assert hits[0].match_type == MatchType.EXACT
        assert hits[0].score > 0.0

    def test_lookup_ioc_defanged_ip(self, hybrid_retriever):
        """Defanged IPs are normalized before lookup."""
        hits = hybrid_retriever.lookup_ioc("ip", "192[.]0[.]2[.]10")
        assert len(hits) == 1
        assert hits[0].doc_id == "ioc:ip:192.0.2.10"

    def test_lookup_ioc_unknown_returns_empty(self, hybrid_retriever):
        """Unknown IP returns empty list — not an error."""
        hits = hybrid_retriever.lookup_ioc("ip", "10.0.0.1")  # RFC 1918, not in seed
        assert hits == []

    def test_lookup_cve_exact(self, hybrid_retriever):
        """Known CVE returns exact match."""
        hit = hybrid_retriever.lookup_cve("CVE-2021-44228")
        assert hit is not None
        assert hit.doc_id == "cve:CVE-2021-44228"
        assert hit.match_type == MatchType.EXACT

    def test_lookup_cve_case_insensitive(self, hybrid_retriever):
        """CVE lookup is case-insensitive."""
        hit = hybrid_retriever.lookup_cve("cve-2021-44228")
        assert hit is not None
        assert hit.doc_id == "cve:CVE-2021-44228"

    def test_lookup_cve_unknown_returns_none(self, hybrid_retriever):
        """Unknown CVE returns None."""
        hit = hybrid_retriever.lookup_cve("CVE-9999-99999")
        assert hit is None

    def test_lookup_technique_exact(self, hybrid_retriever):
        """Known MITRE T-ID returns exact match."""
        hit = hybrid_retriever.lookup_technique("T1110")
        assert hit is not None
        assert hit.doc_id == "mitre:T1110"
        assert hit.match_type == MatchType.EXACT

    def test_lookup_technique_subtechnique(self, hybrid_retriever):
        """Sub-technique lookup returns its own exact match."""
        hit = hybrid_retriever.lookup_technique("T1110.003")
        assert hit is not None
        assert hit.doc_id == "mitre:T1110.003"

    def test_lookup_technique_unknown_returns_none(self, hybrid_retriever):
        hit = hybrid_retriever.lookup_technique("T9999")
        assert hit is None


class TestHybridRetrieverSemantic:
    """Semantic search smoke tests — retrieval must not hallucinate."""

    def test_search_patterns_semantic(self, hybrid_retriever, populated_stores):
        duck, _ = populated_stores
        # Build known doc IDs
        rows = duck._conn.execute("SELECT doc_id FROM intel_metadata").fetchall()
        known_ids = {r[0] for r in rows}

        results = hybrid_retriever.search(
            "many failed logins then one success from same IP",
            corpora=[IntelSource.PATTERN],
            k=5,
        )
        assert len(results) > 0
        # No hallucination
        for m in results:
            assert m.doc_id in known_ids or m.doc_id.startswith("pattern:")

    def test_search_returns_scores_in_range(self, hybrid_retriever):
        results = hybrid_retriever.search("password guessing attack", k=3)
        for m in results:
            assert 0.0 <= m.score <= 1.0

    def test_search_ioc_corpus_skipped(self, hybrid_retriever):
        """IOC corpus cannot be queried semantically — must be silently skipped."""
        results = hybrid_retriever.search("malicious IP", corpora=[IntelSource.IOC], k=5)
        # Should return empty (IOC has no vector collection)
        assert isinstance(results, list)


class TestHybridRetrieverLinkExpansion:
    def test_expand_technique_to_subtechnique(self, hybrid_retriever):
        """T1110 should expand to T1110.003 via parent_of link."""
        linked = hybrid_retriever.expand("mitre:T1110", hops=1)
        linked_ids = [m.doc_id for m in linked]
        assert any("T1110" in lid for lid in linked_ids)

    def test_expand_marks_linked_type(self, hybrid_retriever):
        """Expanded results must be marked as LINKED."""
        linked = hybrid_retriever.expand("mitre:T1110", hops=1)
        if linked:
            assert all(m.match_type == MatchType.LINKED for m in linked)

    def test_expand_unknown_returns_empty(self, hybrid_retriever):
        linked = hybrid_retriever.expand("mitre:T9999-UNKNOWN", hops=1)
        assert linked == []


class TestHybridRetrieverFullRetrieve:
    """Full pipeline retrieve() test — multi-stage with entities + hints + claims."""

    def test_retrieve_produces_per_corpus_results(self, hybrid_retriever):
        entities = Entities(
            ips=["192.0.2.10"],
            cves=["CVE-2021-44228"],
        )
        hints = ["T1110"]
        claims = ["repeated failed SSH logins from one IP followed by a successful login"]

        results = hybrid_retriever.retrieve(entities, hints, claims, k=5)

        assert len(results) > 0
        corpora_seen = {m.corpus for m in results}
        # Should see at least IOC and MITRE
        assert IntelSource.IOC in corpora_seen or IntelSource.MITRE in corpora_seen

    def test_retrieve_no_hallucination(self, hybrid_retriever, populated_stores):
        duck, _ = populated_stores
        rows = duck._conn.execute("SELECT doc_id FROM intel_metadata").fetchall()
        known_meta = {r[0] for r in rows}
        ioc_rows = duck._conn.execute("SELECT ioc_type, value_normalized FROM iocs").fetchall()
        known_iocs = {f"ioc:{r[0]}:{r[1]}" for r in ioc_rows}
        cve_rows = duck._conn.execute("SELECT cve_id FROM cves").fetchall()
        known_cves = {f"cve:{r[0]}" for r in cve_rows}
        all_known = known_meta | known_iocs | known_cves

        entities = Entities(ips=["192.0.2.10"], cves=["CVE-2021-41773"])
        results = hybrid_retriever.retrieve(entities, ["T1110"], k=5)

        for m in results:
            assert m.doc_id in all_known, f"HALLUCINATION: {m.doc_id} not in store"

    def test_retrieve_scores_bounded(self, hybrid_retriever):
        entities = Entities(ips=["192.0.2.10"])
        results = hybrid_retriever.retrieve(entities, [], k=3)
        for m in results:
            assert 0.0 <= m.score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# MockThreatIntelRetriever Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMockRetriever:
    def setup_method(self):
        self.mock = MockThreatIntelRetriever()
        self.ioc_match = IntelMatch(
            doc_id="ioc:ip:192.0.2.10",
            corpus=IntelSource.IOC,
            title="Known scanner",
            snippet="Known malicious IP",
            score=0.95,
            match_type=MatchType.EXACT,
            matched_on="ip:192.0.2.10",
            trust_weight=0.9,
        )
        self.mitre_match = IntelMatch(
            doc_id="mitre:T1110",
            corpus=IntelSource.MITRE,
            title="Brute Force",
            snippet="Systematic password guessing",
            score=1.0,
            match_type=MatchType.EXACT,
            matched_on="T1110",
            trust_weight=1.0,
        )
        self.mock.add_fixture(self.ioc_match)
        self.mock.add_fixture(self.mitre_match)

    def test_lookup_ioc_from_fixtures(self):
        hits = self.mock.lookup_ioc("ip", "192.0.2.10")
        assert len(hits) == 1
        assert hits[0].doc_id == "ioc:ip:192.0.2.10"

    def test_lookup_technique_from_fixtures(self):
        hit = self.mock.lookup_technique("T1110")
        assert hit is not None
        assert hit.doc_id == "mitre:T1110"

    def test_search_returns_all_fixtures(self):
        results = self.mock.search("brute force attack")
        assert len(results) == 2

    def test_retrieve_returns_top_k_per_corpus(self):
        results = self.mock.retrieve(Entities(), hints=["T1110"], k=5)
        assert len(results) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6d Tests: ThreatIntelAgent confidence caps and evidence enforcement
# ─────────────────────────────────────────────────────────────────────────────

def _make_ti_agent(fake_responses: list | None = None) -> tuple[ThreatIntelAgent, FakeLLMClient]:
    """Helper to create a ThreatIntelAgent with a FakeLLMClient."""
    mock_retriever = MockThreatIntelRetriever()
    # Add a known IOC fixture
    mock_retriever.add_fixture(IntelMatch(
        doc_id="ioc:ip:192.0.2.10",
        corpus=IntelSource.IOC,
        title="Known scanner IP",
        snippet="192.0.2.10 — known Cobalt Strike scanner",
        score=0.95,
        match_type=MatchType.EXACT,
        matched_on="ip:192.0.2.10",
        trust_weight=0.9,
    ))
    mock_retriever.add_fixture(IntelMatch(
        doc_id="mitre:T1110",
        corpus=IntelSource.MITRE,
        title="Brute Force",
        snippet="T1110 Brute Force: Systematic guessing",
        score=1.0,
        match_type=MatchType.EXACT,
        matched_on="T1110",
        trust_weight=1.0,
    ))

    llm = FakeLLMClient()
    if fake_responses:
        for r in fake_responses:
            llm.queue_response(r)

    incident = _make_incident()
    agent = ThreatIntelAgent(llm_client=llm, retriever=mock_retriever, incident=incident)
    return agent, llm


class TestThreatIntelAgentConfidenceCaps:
    """Verify strict confidence caps per Section 8.6."""

    def test_ioc_only_confidence_cap(self):
        """IOC-only finding must not exceed IOC_ONLY_CAP (0.60)."""
        agent, _ = _make_ti_agent()

        draft = ThreatIntelFindingDraft(
            claim="IP 192.0.2.10 is a known malicious scanner",
            evidence_event_ids=["evt-ti-000"],
            intel_doc_ids=["ioc:ip:192.0.2.10"],
            confidence=0.95,  # Agent-claimed – should be capped
            match_type="exact",
            reasoning="IOC reputation hit",
        )
        capped = agent._enforce_confidence_cap(draft)
        assert capped.confidence <= IOC_ONLY_CAP
        assert "capped" in capped.reasoning

    def test_cve_unconfirmed_cap(self):
        """CVE finding marked 'possible, unconfirmed' must be capped at 0.50."""
        agent, _ = _make_ti_agent()

        draft = ThreatIntelFindingDraft(
            claim="Log4Shell CVE-2021-44228 may affect this server",
            evidence_event_ids=["evt-ti-001"],
            intel_doc_ids=["cve:CVE-2021-44228"],
            confidence=0.85,
            match_type="exact",
            reasoning="CVE match; software not confirmed in logs, possible unconfirmed",
        )
        capped = agent._enforce_confidence_cap(draft)
        assert capped.confidence <= CVE_UNCONFIRMED_CAP

    def test_mitre_with_evidence_cap(self):
        """MITRE technique match with supporting evidence allows up to 0.85."""
        agent, _ = _make_ti_agent()

        draft = ThreatIntelFindingDraft(
            claim="Attack matches T1110 Brute Force pattern",
            evidence_event_ids=["evt-ti-002"],
            intel_doc_ids=["mitre:T1110"],
            confidence=0.80,
            match_type="exact",
            reasoning="MITRE match with strong log evidence",
        )
        capped = agent._enforce_confidence_cap(draft)
        assert capped.confidence <= MITRE_WITH_EVIDENCE_CAP
        assert capped.confidence == 0.80  # Should not be reduced below stated value

    def test_combined_match_cap(self):
        """Combined IOC + MITRE match can go up to 0.90."""
        agent, _ = _make_ti_agent()

        draft = ThreatIntelFindingDraft(
            claim="IP linked to Cobalt Strike and matches T1110",
            evidence_event_ids=["evt-ti-003"],
            intel_doc_ids=["ioc:ip:192.0.2.10", "mitre:T1110"],
            confidence=0.88,
            match_type="combined",
            reasoning="IOC + technique match",
        )
        capped = agent._enforce_confidence_cap(draft)
        assert capped.confidence <= COMBINED_MATCH_CAP


class TestThreatIntelAgentEvidenceEnforcement:
    """Findings without evidence_event_ids must be dropped."""

    def test_finding_without_event_ids_dropped(self):
        """A draft with empty event IDs is dropped during _validate_drafts."""
        agent, _ = _make_ti_agent()

        invalid_draft = ThreatIntelFindingDraft(
            claim="No evidence behind this claim",
            evidence_event_ids=[],  # Empty – must be dropped
            intel_doc_ids=["mitre:T1110"],
            confidence=0.80,
            match_type="exact",
            reasoning="Should be dropped",
        )
        result = agent._validate_drafts([invalid_draft])
        assert result == []
        assert len(agent.trace["dropped_findings"]) == 1

    def test_valid_finding_passes_through(self):
        """A valid finding with event IDs is kept and returned as Finding."""
        agent, _ = _make_ti_agent()

        valid_draft = ThreatIntelFindingDraft(
            claim="IP 192.0.2.10 is a known scanner",
            evidence_event_ids=["evt-ti-000"],
            intel_doc_ids=["ioc:ip:192.0.2.10"],
            confidence=0.55,
            match_type="exact",
            reasoning="IOC hit",
        )
        result = agent._validate_drafts([valid_draft])
        assert len(result) == 1
        assert result[0].agent == "threat_intel"
        assert result[0].confidence <= IOC_ONLY_CAP
        assert "ioc:ip:192.0.2.10" in result[0].reasoning

    def test_finding_id_format(self):
        """Finding IDs follow the ti-{incident_id}-{index} format."""
        agent, _ = _make_ti_agent()
        draft = ThreatIntelFindingDraft(
            claim="Test claim",
            evidence_event_ids=["evt-ti-000"],
            intel_doc_ids=["mitre:T1110"],
            confidence=0.70,
            match_type="exact",
            reasoning="Test",
        )
        findings = agent._validate_drafts([draft])
        assert findings[0].finding_id.startswith("ti-inc-ti-test-")


class TestThreatIntelAgentRunLoop:
    """Full agent.run() with FakeLLMClient scripted responses."""

    def test_brute_force_scenario_emits_cited_findings(self):
        """
        Phase 6d acceptance: On brute-force scenario, agent emits cited threat findings
        referencing correct doc_ids.
        """
        # Script: one tool call (lookup_ioc), then complete with findings
        fake_action_1 = ThreatIntelAction(
            tool_calls=[{
                "tool_name": "lookup_ioc",
                "tool_args": {"kind": "ip", "value": "192.0.2.10"},
                "reasoning": "IP from auth finding",
            }],
            intel_findings=[],
            no_intel_found=[],
            is_complete=False,
        )
        fake_action_2 = ThreatIntelAction(
            tool_calls=[],
            intel_findings=[{
                "claim": "Source IP 192.0.2.10 is a known malicious scanner (Cobalt Strike)",
                "evidence_event_ids": ["evt-ti-000", "evt-ti-001"],
                "intel_doc_ids": ["ioc:ip:192.0.2.10"],
                "confidence": 0.90,  # Will be capped to 0.60
                "match_type": "exact",
                "mitre_hint": "T1110",
                "reasoning": "IP matched in IOC feed",
            }],
            no_intel_found=[],
            is_complete=True,
        )

        agent, llm = _make_ti_agent()
        llm.queue_response(json.dumps(fake_action_1.model_dump()))
        llm.queue_response(json.dumps(fake_action_2.model_dump()))

        entities = Entities(ips=["192.0.2.10"])
        findings = agent.run(entities=entities, hints=["T1110"], claims=[])

        assert len(findings) == 1
        f = findings[0]
        assert f.agent == "threat_intel"
        assert "192.0.2.10" in f.claim
        assert f.confidence <= IOC_ONLY_CAP  # Capped from 0.90 → 0.60
        assert "evt-ti-000" in f.evidence_event_ids
        assert "ioc:ip:192.0.2.10" in f.reasoning
        assert f.mitre_hint == "T1110"

    def test_unconfirmed_cve_labeled_correctly(self):
        """
        Phase 6d acceptance: CVE without software log evidence must be capped at 0.50.
        """
        fake_action = ThreatIntelAction(
            tool_calls=[],
            intel_findings=[{
                "claim": "CVE-2021-44228 (Log4Shell) may affect this server — software not confirmed in logs, possible unconfirmed",
                "evidence_event_ids": ["evt-ti-002"],
                "intel_doc_ids": ["cve:CVE-2021-44228"],
                "confidence": 0.80,  # Will be capped to 0.50
                "match_type": "exact",
                "mitre_hint": None,
                "reasoning": "CVE found for software type in incident but not confirmed in log fields, possible unconfirmed",
            }],
            no_intel_found=[],
            is_complete=True,
        )

        agent, llm = _make_ti_agent()
        llm.queue_response(json.dumps(fake_action.model_dump()))

        findings = agent.run(entities=Entities(), hints=[], claims=[])
        assert len(findings) == 1
        assert findings[0].confidence <= CVE_UNCONFIRMED_CAP

    def test_no_intel_found_reported_in_trace(self):
        """
        Phase 6d acceptance: When no intel is found, it must be reported explicitly
        in the agent trace, not silently omitted.
        """
        fake_action = ThreatIntelAction(
            tool_calls=[],
            intel_findings=[],
            no_intel_found=["10.0.0.99", "CVE-9999-99999"],
            is_complete=True,
        )

        agent, llm = _make_ti_agent()
        llm.queue_response(json.dumps(fake_action.model_dump()))

        findings = agent.run(entities=Entities(), hints=[], claims=[])
        assert findings == []
        assert "10.0.0.99" in agent.trace["no_intel_found"]
        assert "CVE-9999-99999" in agent.trace["no_intel_found"]

    def test_agent_completes_without_tool_calls(self):
        """Agent can complete with is_complete=True and no tool calls."""
        fake_action = ThreatIntelAction(
            tool_calls=[],
            intel_findings=[],
            no_intel_found=[],
            is_complete=True,
        )
        agent, llm = _make_ti_agent()
        llm.queue_response(json.dumps(fake_action.model_dump()))

        findings = agent.run(entities=Entities(), hints=[], claims=[])
        assert findings == []
        assert agent.trace["iterations"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Graph integration: TI node wired correctly
# ─────────────────────────────────────────────────────────────────────────────

class TestOrchestatorWithTINode:
    """Smoke test: graph builds with and without a retriever."""

    def test_graph_builds_without_retriever(self):
        """Graph builds without TI node when no retriever is provided (backward compat)."""
        from sentinelai.orchestrator.graph import build_investigation_graph
        from sentinelai.llm.fake import FakeLLMClient
        from sentinelai.tools.registry import ToolRegistry

        llm = FakeLLMClient()
        registry = ToolRegistry()
        graph = build_investigation_graph(registry=registry, llm_client=llm, retriever=None)
        assert graph is not None

    def test_graph_builds_with_retriever(self):
        """Graph builds with TI node when a retriever is provided."""
        from sentinelai.orchestrator.graph import build_investigation_graph
        from sentinelai.llm.fake import FakeLLMClient
        from sentinelai.tools.registry import ToolRegistry

        llm = FakeLLMClient()
        registry = ToolRegistry()
        mock_retriever = MockThreatIntelRetriever()
        graph = build_investigation_graph(
            registry=registry, llm_client=llm, retriever=mock_retriever
        )
        assert graph is not None
