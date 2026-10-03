# SentinelAI

> **Multi-agent autonomous SOC investigation tier** — a self-improving, explainable,
> cost-aware investigation engine built on LangGraph, Pydantic v2, DuckDB, and ChromaDB.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)](https://python.org)
[![LangGraph](https://img.shields.io/badge/orchestrator-LangGraph-green)](https://python.langchain.com/docs/langgraph)
[![Offline-first](https://img.shields.io/badge/offline--first-✓-brightgreen)](docs/DECISIONS.md)

---

## Overview

SentinelAI separates **detection** from **investigation**. The detection/RL tier
triages incidents (Ignore → Low → Medium → High → Critical). For Medium-and-above
incidents, the investigation tier takes over:

1. **Auth Agent** — authentication anomaly specialist
2. **Timeline Agent** — attack sequence reconstruction
3. **Correlation Agent** (high/critical only) — cross-entity correlation
4. **Threat Intel Agent** — hybrid RAG over MITRE ATT&CK, IOCs, CVEs, malware
5. **Evidence Validator** — fact-checks every finding, loops for follow-up
6. **Report Generator** — Jinja2 Markdown report with full evidence index

All conclusions are **cited** (every claim references log event IDs). No infinite
loops. Every investigation emits a trace usable for RL reward shaping.

---

## Architecture

```
IncidentInput
    │
    ▼
[plan_node]  ──low/ignore──▶  [archive_node]  ──▶  ArchiveDecision
    │
    ├──medium──▶  [auth_node] ──┐
    │                            ├──▶ [merge_node]
    └──high/critical──▶  [auth_node]  [timeline_node]  [correlation_node] ──┘
                                                                              │
                                                                     [threat_intel_node]
                                                                              │
                                                                     [validate_node]
                                                                    ╱         ╲
                                              sufficient=True  [report_node]  ╲ loops<cap
                                                    │                          [follow_up_dispatch]
                                                    ▼                               │
                                           InvestigationReport              back to agents
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full LangGraph node/edge list.

---

## Quick Start

### Requirements

- Python 3.11 (required; 3.12 not yet supported by some dependencies)
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Install (offline / development)

```bash
git clone <repo>
cd kavach-agents

# With uv (recommended):
uv sync --dev

# Or with pip:
pip install -e ".[dev]"
```

### Configure environment

Copy `.env.example` to `.env` and set your preferred LLM provider:

```bash
cp .env.example .env
# Edit .env — minimum required for offline/fake mode: nothing (defaults work)
```

### Run with FakeLLM (no network, no API key needed)

```bash
# Offline demo with fake LLM — runs full graph end-to-end
LLM_PROVIDER=fake uv run python -m sentinelai.cli investigate data/synthetic/sample_incident.json

# Or investigate any incident JSON:
uv run python -m sentinelai.cli investigate path/to/incident.json --out reports/
```

### Run with a real LLM

```bash
# Anthropic Claude (default)
LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... uv run python -m sentinelai.cli investigate path/to/incident.json

# Groq Cloud
LLM_PROVIDER=groq GROQ_API_KEY=gsk_... uv run python -m sentinelai.cli investigate path/to/incident.json

# Ollama (local, offline)
LLM_PROVIDER=ollama OLLAMA_MODEL=llama3.1:8b uv run python -m sentinelai.cli investigate path/to/incident.json
```

### Provide analyst feedback

```bash
uv run python -m sentinelai.cli feedback \
    --incident-id scenario-brute-force-001 \
    --verdict true_positive \
    --notes "Confirmed brute force from 192.0.2.10" \
    --traces-dir reports/
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `fake` | `fake` \| `anthropic` \| `groq` \| `ollama` |
| `ANTHROPIC_API_KEY` | — | Required when `LLM_PROVIDER=anthropic` |
| `GROQ_API_KEY` | — | Required when `LLM_PROVIDER=groq` |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | Groq model name |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.1:8b` | Ollama model name |
| `MAX_VALIDATION_LOOPS` | `2` | Cap on validator retry loops |
| `MAX_AGENT_TOOL_CALLS` | `10` | Per-agent tool call cap |
| `CHROMA_PATH` | `rag/chroma_store` | ChromaDB persistence path |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Sentence-transformer model |
| `LANGFUSE_PUBLIC_KEY` | — | Optional Langfuse tracing |
| `LANGFUSE_SECRET_KEY` | — | Optional Langfuse tracing |
| `LANGFUSE_HOST` | `https://cloud.langfuse.com` | Langfuse endpoint |

---

## Running Tests

```bash
# Full test suite (offline, FakeLLM — should pass with no network)
uv run pytest tests/ -v

# Single phase
uv run pytest tests/test_phase1.py -v         # Foundations
uv run pytest tests/test_tools.py -v          # Tool layer
uv run pytest tests/test_validator.py -v      # Evidence Validator
uv run pytest tests/test_threat_intel_agent.py -v  # RAG + TI Agent
uv run pytest tests/test_interfaces.py -v     # Phase 8: CLI + tracing
uv run pytest tests/test_eval.py -v           # Phase 9: Eval harness
```

---

## Phase 9: End-to-End Evaluation

Run the full scenario scorecard:

```bash
# Offline scorecard (FakeLLM, all 6 scenarios)
uv run python eval.py

# Verbose — per-finding details
uv run python eval.py --verbose

# Export results to JSON
uv run python eval.py --json-out eval_results.json
```

Scenarios evaluated:
1. **Brute force then success** — must classify as `true_positive`
2. **Password spraying** — must classify as `true_positive`
3. **Lateral movement** — must classify as `true_positive`
4. **Benign false positive** — must NOT escalate (`false_positive`)
5. **Thin evidence** — must loop, produce low-confidence report
6. **Prompt injection in logs** — injection must have no effect on verdict

Acceptance criteria enforced by `eval.py` (exit 0 = pass):
- Citation validity = 100% (no hallucinated event IDs)
- Runtime: `investigate()` must not raise for any scenario
- FP scenario must not be escalated as TP
- Injection scenario must remain a `true_positive`

---

## RAG Retrieval Evaluation

```bash
# Runs 40+ labeled queries across MITRE, IOCs, CVEs, malware, and patterns
uv run python rag/eval_retrieval.py
```

Reports recall@5, MRR, no-hallucination rate, and negative-query pass rate.

---

## Integrating the Real RL Engine (Teammate Interface)

Replace `FileRLClient` with your own implementation of the `RLClient` protocol:

```python
from sentinelai.interfaces.rl_client import RLClient
from sentinelai.schemas import IncidentInput, AnalystFeedback

class MyRLClient:
    def get_incident(self) -> IncidentInput:
        # Pull next incident from your RL engine's queue
        ...
    def submit_feedback(self, fb: AnalystFeedback, trace: dict) -> None:
        # Push analyst verdict + trace back as a reward signal
        ...
```

The trace dict contains all fields needed for reward shaping: `agents_executed`,
`tool_calls_per_agent`, `loops_used`, `tokens`, `estimated_cost`,
`wall_clock_time`, `validator_verdicts`, `overall_confidence`, `analyst_verdict`.

---

## Project Structure

```
sentinelai/
  config.py          # env-driven settings
  schemas.py         # Pydantic v2 contracts (teammate interface)
  investigation.py   # main public entrypoint: investigate(incident)
  cli.py             # CLI: investigate / feedback commands
  llm/               # LLMClient protocol, anthropic.py, groq.py, ollama.py, fake.py
  store/             # DuckDB LogStore
  tools/             # 12 deterministic tools + ToolRegistry
  agents/            # base.py, auth.py, timeline.py, correlation.py, threat_intel.py
  orchestrator/      # LangGraph graph.py, nodes.py, routing.py, state.py
  validator/         # rules.py (Stage 1), judge.py (Stage 2), validator.py
  report/            # generator.py, templates/report_v1.md.j2
  threat_intel/      # retriever.py (hybrid RAG), mock_retriever.py
  tracing/           # local_trace.py (per-incident trace.json)
  interfaces/        # rl_client.py (RLClient protocol + FileRLClient), feedback.py
  prompts/           # versioned prompt files (*.md)
data/synthetic/      # scenario generators + ground truth
rag/                 # ingest CLI, ChromaDB collections, DuckDB tables, eval_retrieval.py
tests/               # pytest suite (offline, FakeLLM)
docs/                # MASTERPROMPT.md, DECISIONS.md, ARCHITECTURE.md
eval.py              # end-to-end scorecard runner
pyproject.toml
.env.example
README.md
```

---

## Design Principles

- **Explainable**: every conclusion cites log event IDs — no black-box claims
- **Cost-aware**: deterministic tools do heavy lifting; LLMs see only small, relevant slices
- **Self-improving**: every investigation emits a trace for RL reward shaping
- **Offline-first**: full test suite passes with `LLM_PROVIDER=fake` and no network
- **Bounded**: every loop has a cap; token budgets enforced per agent

---

## License

MIT — see `LICENSE`.
