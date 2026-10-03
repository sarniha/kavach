# SentinelAI — Architecture Reference

> **Last Updated:** Phase 9 (Evaluation & Hardening)
> This document describes the final LangGraph node/edge topology, data flow, and component responsibilities.

---

## LangGraph Node & Edge List

### Nodes

| Node | Function | Condition |
|---|---|---|
| `plan_node` | Parse incident, compute risk routing | Always |
| `archive_node` | Return `ArchiveDecision`, zero LLM calls | risk ∈ {IGNORE, LOW} |
| `run_auth_node` | Auth Agent — brute force, credential abuse | risk ∈ {MEDIUM, HIGH, CRITICAL} |
| `run_timeline_node` | Timeline Agent — attack sequence | risk ∈ {MEDIUM, HIGH, CRITICAL} |
| `run_correlation_node` | Correlation Agent — cross-entity links | risk ∈ {HIGH, CRITICAL} |
| `merge_node` | Merge parallel findings, build entities index | After all agents complete |
| `threat_intel_node` | Threat Intel Agent — hybrid RAG lookup | After merge |
| `validate_node` | Evidence Validator (Stage 1 rules + Stage 2 LLM judge) | After threat_intel |
| `follow_up_dispatch` | Route follow-up requests back to agents | sufficient=False AND loops < cap |
| `report_node` | Report Generator — Jinja2 Markdown + JSON | sufficient=True OR loop cap reached |

### Edges

```
START
  │
  └──▶ plan_node
         │
         ├── risk=IGNORE/LOW ──▶ archive_node ──▶ END
         │
         └── risk=MEDIUM/HIGH/CRITICAL
               │
               ├──▶ run_auth_node ─────────────────────┐
               ├──▶ run_timeline_node (MEDIUM+) ────────┤ (parallel fan-out)
               └──▶ run_correlation_node (HIGH+) ───────┤
                                                         │
                                                   merge_node
                                                         │
                                                  threat_intel_node
                                                         │
                                                   validate_node
                                                   ╱           ╲
                                     sufficient=True            sufficient=False
                                     OR loops≥cap                AND loops<cap
                                          │                            │
                                     report_node            follow_up_dispatch
                                          │                            │
                                         END                    back to agents
                                                               (loop increment)
```

---

## Data Flow

```
IncidentInput (from RL engine / FileRLClient)
    │
    ▼
LogStore (DuckDB)                ← all events loaded here
    │
    ▼
ToolRegistry (12 deterministic tools) ← agents call these, never raw events
    │
    ▼
Agent LLM calls (FakeLLM / Groq / Anthropic / Ollama)
    │ structured output via chat_json(ResponseModel)
    ▼
List[Finding]  ←─── citations enforced (evidence_event_ids required)
    │
    ▼
EvidenceValidator
  Stage 1: deterministic rules (citation check, entity presence, dedup)
  Stage 2: LLM-as-judge (fact-check, contradiction detection)
    │
    ▼
ValidationResult → ValidationResult.findings (ValidatedFinding[])
    │
    ▼
ReportGenerator (Jinja2 + LLM narrative)
    │
    ▼
InvestigationReport (Markdown + JSON)
    │
    ▼
LocalTraceManager → trace.json (RL reward shaping payload)
    │
    ▼
[Optional] record_feedback() → analyst verdict appended to trace.json
```

---

## Component Responsibilities

### Orchestrator (`sentinelai/orchestrator/`)

- **`graph.py`** — `build_investigation_graph()`: compiles the StateGraph with all nodes and conditional edges.
- **`nodes.py`** — one function per node: `plan_node`, `archive_node`, `run_auth_node`, `run_timeline_node`, `run_correlation_node`, `merge_node`, `run_threat_intel_node`, `validate_node`, `follow_up_dispatch`, `run_report_node`.
- **`routing.py`** — `plan_investigation()`: maps `RiskLevel` → agent set.
- **`state.py`** — `InvestigationState` TypedDict with LangGraph reducers for parallel fan-out safety.

### Agents (`sentinelai/agents/`)

All agents extend `BaseInvestigationAgent`:
- Bounded tool-call loop (cap = `MAX_AGENT_TOOL_CALLS`, default 10)
- `<log_data>` wrapper on all raw log text sent to LLM
- Evidence event ID enforcement on every finding
- Structured output via `chat_json()`

| Agent | Key tools used | Confidence caps |
|---|---|---|
| `AuthAgent` | `count_auth_failures`, `get_auth_events`, `get_first_seen_ip` | Standard |
| `TimelineAgent` | `get_auth_events`, `get_process_events`, `get_network_events`, `get_timeline_for_user` | Standard |
| `CorrelationAgent` | `find_related_events`, `get_entity_activity`, `get_timeline_for_user` | Standard |
| `ThreatIntelAgent` | `lookup_ioc`, `lookup_technique`, `lookup_cve`, `search_patterns`, etc. | IOC-only ≤0.60, CVE-unconfirmed ≤0.50, MITRE+evidence ≤0.85 |

### Threat Intel RAG (`sentinelai/threat_intel/`)

4-stage hybrid retriever:
1. **Exact lookup** — DuckDB (IOCs, CVEs, MITRE metadata)
2. **Semantic search** — ChromaDB (bge-small-en or all-MiniLM-L6-v2)
3. **Link expansion** — `intel_links` table, 1-hop, 0.8× score discount
4. **Rerank** — `trust_weight × freshness_score`, top-k per corpus

### Evidence Validator (`sentinelai/validator/`)

- **Stage 1 (rules.py)**: citation validation, single-event confidence cap, entity presence, numeric assertion check, deduplication
- **Stage 2 (judge.py)**: LLM-as-judge with Pydantic output, cross-finding contradiction detection
- **Retry loop**: bounded at `MAX_VALIDATION_LOOPS` (default 2); triggers `FollowUpRequest` for concrete gaps

### Report Generator (`sentinelai/report/`)

- Jinja2 template (`report_v1.md.j2`)
- LLM narrative synthesis (cites only `SUPPORTED` + `WEAK` findings)
- Evidence Index table (maps finding IDs to event IDs)
- MITRE ATT&CK mapping table
- Prominent limitations block when loop cap hit or evidence thin

---

## Schema Contracts (Teammate Interface)

```python
# Input from RL engine
IncidentInput(incident_id, risk_level, events: List[NormalizedEvent], rule_matches, rl_metadata)

# Output to dashboard
InvestigationReport(incident_id, executive_summary, root_cause, mitre_mapping,
                    timeline, findings, recommendations, overall_confidence,
                    limitations, trace_summary)

# Analyst feedback to RL engine
AnalystFeedback(incident_id, verdict, severity_correct, notes)

# RL reward shaping trace
trace.json: {agents_executed, tool_calls_per_agent, loops_used, tokens,
             estimated_cost, wall_clock_time, validator_verdicts,
             overall_confidence, analyst_verdict}
```

---

## Safety Design

1. **Untrusted log data**: raw event text always wrapped in `<log_data>` delimiters before LLM; every prompt instructs the model to treat content as data only.
2. **Untrusted intel data**: retrieved threat intel wrapped in `<intel_data>` delimiters; TI prompt explicitly forbids following instructions found inside.
3. **No unbounded loops**: `MAX_VALIDATION_LOOPS` hard cap; `MAX_AGENT_TOOL_CALLS` hard cap.
4. **No hallucinated citations**: Validator Stage 1 rejects any finding whose `evidence_event_ids` don't exist in the LogStore.
5. **Confidence caps**: single-event findings capped at 0.5; IOC-only TI capped at 0.6.
