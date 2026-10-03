# docs/DECISIONS.md
# SentinelAI — Architecture Decision Log

This file records every significant design choice made during the build.
Each entry documents the decision, its rationale, and the alternatives
considered.  Agents that reach an ambiguous situation should add an entry
here and continue (per Rule 6 of MASTERPROMPT.md §0).

---

## D-001 — LLM provider: Groq instead of Anthropic

**Date:** 2026-10-02
**Status:** Accepted

### Decision

The LLM backend is **Groq Cloud** (not Anthropic Claude), accessed via the
official `groq` Python SDK.  `LLM_PROVIDER` now accepts `groq | ollama | fake`.

### Rationale

* Groq's inference API is substantially faster (LPU-based) and lower-cost,
  which matters when the fan-out can invoke 3 agents simultaneously.
* The free tier is sufficient for development and CI integration testing.
* All Groq models support JSON mode and tool calling, so structured output
  works without provider-specific workarounds.

### Models

Model names are **never hardcoded**.  They are set via env vars:

| Var | Purpose | Recommended free-tier value |
|---|---|---|
| `GROQ_MODEL` | Main reasoning — agents + Evidence Validator judge | `llama-3.3-70b-versatile` |
| `GROQ_FAST_MODEL` | Cheap steps — Orchestrator routing, follow-up wording | `llama-3.1-8b-instant` |

See `.env.example` for the full list of current Groq model options.

### Rate-limit mitigations (free tier)

Groq free tier limits are approximately 30 RPM and 6k–14k TPM per model.
Three strategies are in place:

1. **Shared sliding-window rate limiter** (`_SlidingWindowRateLimiter` in
   `sentinelai/llm/groq.py`) — counts requests and tokens over a 60-second
   window and blocks until budget is available, rather than crashing.
2. **Concurrency semaphore** — `MAX_CONCURRENT_LLM_CALLS` (default 2) caps
   how many of the parallel fan-out agents can call the API simultaneously.
3. **Retry with backoff** — 429 and 5xx responses are retried up to 5 times
   with `wait_exponential(min=2s, max=60s)`, honouring the `Retry-After`
   header when present.
4. **Strict token budget** — `MAX_TOKENS_PER_INCIDENT` (default 80k) is
   tracked per-agent and globally; investigations abort gracefully and record
   a `limitations` note when the budget would be exceeded.

### Structured output strategy

Not all Groq models guarantee strict JSON schema adherence.  The client uses:

1. `response_format={"type": "json_object"}` to request JSON mode.
2. Pydantic `model_validate` to check the schema.
3. On failure, one retry with the validation error appended to the prompt.
4. On second failure, raise `StructuredOutputError` — the agent drops the
   finding and records a limitation.  Never silently swallows bad output.

`StructuredOutputError` is defined in `sentinelai/llm/protocol.py` so it can
be imported without the Groq SDK.

### Offline / test behaviour

* `LLM_PROVIDER=fake` (the default) uses `FakeLLMClient` — no network, no
  API key needed.  All CI tests run this way.
* `LLM_PROVIDER=ollama` uses Llama 3.1 8B locally for fully offline real-LLM
  testing.
* Both `FakeLLMClient.enqueue_malformed()` and `enqueue_json()` allow tests
  to precisely script the structured-output retry path.

### Alternatives rejected

| Alternative | Reason rejected |
|---|---|
| Anthropic Claude | Higher cost per token; slower for high-volume fan-out |
| OpenAI GPT-4o | Cost; not needed — Groq is sufficient |
| Keep Anthropic as fallback | Adds SDK weight and config complexity; Ollama covers the offline fallback |

---

## D-002 — Synchronous execution (no async)

**Date:** 2026-10-02
**Status:** Accepted

All code is synchronous.  LangGraph's async support is not used.
The concurrency semaphore in the Groq client handles the parallel fan-out
safely without event loops.  Async can be layered on post-MVP without
changing the graph topology.

---

## D-003 — DuckDB as the only persistent log store

**Date:** 2026-10-02
**Status:** Accepted

DuckDB is used for both the in-memory (tests) and on-disk (deployment) log
store.  No SQLite or Postgres.  DuckDB's column store is well-suited to the
analytical queries the tool layer performs (window functions, group-by-IP,
time-range scans).

---

## D-004 — Intel-only confidence cap = 0.65

**Date:** 2026-10-02
**Status:** Accepted

A finding that relies solely on a threat-intel match (no corroborating log
evidence) is capped at 0.65 confidence.  Rationale: intel feeds have false
positives; without log-level corroboration, a high-confidence finding would
be misleading.  The cap is configurable via `INTEL_ONLY_CONFIDENCE_CAP`.

---

## D-005 — ChromaDB per-corpus collections (not one shared collection)

**Date:** 2026-10-02
**Status:** Accepted

One Chroma collection per RAG corpus (mitre, iocs, cves, malware, patterns).
This allows branch-specific queries without metadata filters on every call,
avoids cross-corpus semantic pollution, and makes per-corpus updates
(refreshing only MITRE, for example) atomic.

---

## D-006 — Flat LangGraph with Send, not sub-graphs

**Date:** 2026-10-02
**Status:** Accepted

The parallel fan-out uses LangGraph `Send` objects from the plan node to
individual agent nodes, which join at `merge_node`.  Sub-graphs were
rejected because they add indirection that makes the graph harder to trace
and debug, and the topology is simple enough not to need them.
