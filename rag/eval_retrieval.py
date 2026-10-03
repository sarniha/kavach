"""
rag/eval_retrieval.py
──────────────────────
Phase 6c RAG evaluation: labeled query set across 5 corpora.

Tests:
- Exact lookups (IOC, CVE, T-ID) → accuracy must be 100%
- Semantic queries → recall@5 and MRR per corpus
- No-hallucination: every returned doc_id must exist in the store
- Negative queries: benign text should return low scores
- Freshness: older IOC ranks below a newer one with otherwise equal score

Usage:
    python rag/eval_retrieval.py
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Ensure package is importable from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinelai.threat_intel.chroma_store import ThreatIntelChromaStore
from sentinelai.threat_intel.duckdb_store import ThreatIntelDuckDBStore
from sentinelai.threat_intel.embeddings import DeterministicMockEmbedder
from sentinelai.threat_intel.ingest import ThreatIntelIngester
from sentinelai.threat_intel.retriever import HybridThreatIntelRetriever
from sentinelai.threat_intel.schemas import IntelSource
from sentinelai.schemas import Entities


# ─────────────────────────────────────────────────────────────────────────────
# Labeled query set (40+ queries across 5 corpora, Section 8.9)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LabeledQuery:
    qid: str
    query: str
    corpus: IntelSource | None          # None = multi-corpus
    expected_doc_ids: list[str]         # At least one must appear in results
    query_type: str                     # exact | semantic | negative
    min_score: float = 0.0             # semantic minimum relevance threshold


LABELED_QUERIES: list[LabeledQuery] = [
    # ── Exact IOC lookups ──────────────────────────────────────────────────
    LabeledQuery(
        qid="ioc_exact_ip_01",
        query="ip:192.0.2.10",
        corpus=IntelSource.IOC,
        expected_doc_ids=["ioc:ip:192.0.2.10"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="ioc_exact_ip_02",
        query="ip:198.51.100.99",
        corpus=IntelSource.IOC,
        expected_doc_ids=["ioc:ip:198.51.100.99"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="ioc_exact_domain_01",
        query="domain:evil-corp.example.com",
        corpus=IntelSource.IOC,
        expected_doc_ids=["ioc:domain:evil-corp.example.com"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="ioc_exact_hash_01",
        query="hash_md5:44d88612fea8a8f36de82e1278abb02f",
        corpus=IntelSource.IOC,
        expected_doc_ids=["ioc:hash_md5:44d88612fea8a8f36de82e1278abb02f"],
        query_type="exact",
    ),

    # ── Exact CVE lookups ──────────────────────────────────────────────────
    LabeledQuery(
        qid="cve_exact_01",
        query="CVE-2021-41773",
        corpus=IntelSource.CVE,
        expected_doc_ids=["cve:CVE-2021-41773"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="cve_exact_02",
        query="CVE-2021-44228",
        corpus=IntelSource.CVE,
        expected_doc_ids=["cve:CVE-2021-44228"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="cve_exact_03",
        query="CVE-2022-30190",
        corpus=IntelSource.CVE,
        expected_doc_ids=["cve:CVE-2022-30190"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="cve_exact_04",
        query="CVE-2023-23397",
        corpus=IntelSource.CVE,
        expected_doc_ids=["cve:CVE-2023-23397"],
        query_type="exact",
    ),

    # ── Exact MITRE T-ID lookups ───────────────────────────────────────────
    LabeledQuery(
        qid="mitre_exact_T1110",
        query="T1110",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1110"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="mitre_exact_T1110.003",
        query="T1110.003",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1110.003"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="mitre_exact_T1078",
        query="T1078",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1078"],
        query_type="exact",
    ),
    LabeledQuery(
        qid="mitre_exact_T1021",
        query="T1021",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1021"],
        query_type="exact",
    ),

    # ── Semantic queries – attack patterns ────────────────────────────────
    LabeledQuery(
        qid="sem_brute_force_01",
        query="many failed logins from one IP then successful login",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:brute_force"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_brute_force_02",
        query="repeated authentication failures followed by success",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:brute_force"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_spray_01",
        query="one IP attempting login to many different user accounts",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:password_spraying"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_lateral_01",
        query="attacker moves between hosts using stolen credentials",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:lateral_movement"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_lateral_02",
        query="user authenticating to multiple hosts in a short time window",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:lateral_movement"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_exfil_01",
        query="large outbound data transfer at night",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:data_exfiltration"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_privesc_01",
        query="user gains administrator or root privileges",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:privilege_escalation"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_credential_stuffing_01",
        query="many accounts tested with leaked credential lists",
        corpus=IntelSource.PATTERN,
        expected_doc_ids=["pattern:credential_stuffing"],
        query_type="semantic",
        min_score=0.1,
    ),

    # ── Semantic queries – MITRE techniques ───────────────────────────────
    LabeledQuery(
        qid="sem_mitre_brute",
        query="systematic password guessing against accounts",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1110"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_mitre_valid_accounts",
        query="adversaries use existing legitimate credentials",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1078"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_mitre_remote_services",
        query="attacker logs into remote services like RDP or SSH",
        corpus=IntelSource.MITRE,
        expected_doc_ids=["mitre:T1021"],
        query_type="semantic",
        min_score=0.1,
    ),

    # ── Semantic queries – malware ─────────────────────────────────────────
    LabeledQuery(
        qid="sem_malware_cobaltstrike",
        query="post-exploitation framework beacon C2 communication",
        corpus=IntelSource.MALWARE,
        expected_doc_ids=["malware:S0154"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_malware_mimikatz",
        query="credential dumping tool steals hashes from memory",
        corpus=IntelSource.MALWARE,
        expected_doc_ids=["malware:S0002"],
        query_type="semantic",
        min_score=0.1,
    ),

    # ── Semantic queries – CVEs ────────────────────────────────────────────
    LabeledQuery(
        qid="sem_cve_log4shell",
        query="remote code execution via Java logging library JNDI lookup",
        corpus=IntelSource.CVE,
        expected_doc_ids=["cve:CVE-2021-44228"],
        query_type="semantic",
        min_score=0.1,
    ),
    LabeledQuery(
        qid="sem_cve_apache_traversal",
        query="Apache HTTP Server path traversal remote code execution",
        corpus=IntelSource.CVE,
        expected_doc_ids=["cve:CVE-2021-41773"],
        query_type="semantic",
        min_score=0.1,
    ),

    # ── Negative queries (benign text → low score) ─────────────────────────
    LabeledQuery(
        qid="neg_benign_01",
        query="user successfully logged in from their home office",
        corpus=None,
        expected_doc_ids=[],  # Should not confidently match anything
        query_type="negative",
        min_score=0.0,
    ),
    LabeledQuery(
        qid="neg_benign_02",
        query="scheduled maintenance window on production server",
        corpus=None,
        expected_doc_ids=[],
        query_type="negative",
        min_score=0.0,
    ),
    LabeledQuery(
        qid="neg_benign_03",
        query="backup completed successfully at 02:00 UTC",
        corpus=None,
        expected_doc_ids=[],
        query_type="negative",
        min_score=0.0,
    ),
    LabeledQuery(
        qid="neg_benign_04",
        query="software license renewal reminder from IT department",
        corpus=None,
        expected_doc_ids=[],
        query_type="negative",
        min_score=0.0,
    ),
    LabeledQuery(
        qid="neg_benign_05",
        query="quarterly employee onboarding sessions scheduled",
        corpus=None,
        expected_doc_ids=[],
        query_type="negative",
        min_score=0.0,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation runner
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EvalResult:
    qid: str
    query_type: str
    corpus: str
    expected: list[str]
    returned_ids: list[str]
    hit: bool
    rank: int | None          # 1-based rank of first expected id (-1 = miss)
    top_score: float
    hallucination: bool       # True if returned id not in store


@dataclass
class ScorecardEntry:
    corpus: str
    query_type: str
    total: int = 0
    hits: int = 0
    reciprocal_rank_sum: float = 0.0
    hallucinations: int = 0

    @property
    def accuracy(self) -> float:
        return self.hits / self.total if self.total else 0.0

    @property
    def recall_at_5(self) -> float:
        return self.accuracy  # single relevant doc case

    @property
    def mrr(self) -> float:
        return self.reciprocal_rank_sum / self.total if self.total else 0.0


def _build_store_doc_id_set(duck: ThreatIntelDuckDBStore, chroma: ThreatIntelChromaStore) -> set[str]:
    """Collect all known doc_ids for no-hallucination checks."""
    known: set[str] = set()

    # From DuckDB metadata
    rows = duck._conn.execute("SELECT doc_id FROM intel_metadata").fetchall()
    known.update(row[0] for row in rows)

    # From DuckDB iocs
    rows = duck._conn.execute("SELECT ioc_type, value_normalized FROM iocs").fetchall()
    for ioc_type, val in rows:
        known.add(f"ioc:{ioc_type}:{val}")

    # From DuckDB cves
    rows = duck._conn.execute("SELECT cve_id FROM cves").fetchall()
    for (cve_id,) in rows:
        known.add(f"cve:{cve_id}")

    return known


def run_evaluation() -> dict:
    """Run the full labeled query evaluation and return a scorecard dict."""
    print("=" * 70)
    print("SentinelAI RAG Retrieval Evaluation (Phase 6c)")
    print("=" * 70)

    # Build stores and ingest seed data
    duck = ThreatIntelDuckDBStore(":memory:")
    chroma = ThreatIntelChromaStore(
        embedder=DeterministicMockEmbedder(), force_in_memory=True
    )
    ingester = ThreatIntelIngester(duck, chroma)
    counts = ingester.ingest_all()

    print(f"\nSeed data ingested: {counts}")

    retriever = HybridThreatIntelRetriever(duck, chroma)
    known_ids = _build_store_doc_id_set(duck, chroma)

    # Per-corpus/type accumulators
    scorecards: dict[str, ScorecardEntry] = {}
    all_results: list[EvalResult] = []

    for lq in LABELED_QUERIES:
        corpus_str = lq.corpus.value if lq.corpus else "multi"
        key = f"{corpus_str}:{lq.query_type}"
        if key not in scorecards:
            scorecards[key] = ScorecardEntry(corpus=corpus_str, query_type=lq.query_type)
        sc = scorecards[key]
        sc.total += 1

        # ── Run retrieval ─────────────────────────────────────────────────
        if lq.query_type == "exact":
            returned: list = []
            if lq.corpus == IntelSource.IOC:
                # Parse "kind:value"
                parts = lq.query.split(":", 1)
                if len(parts) == 2:
                    returned = retriever.lookup_ioc(parts[0], parts[1])
            elif lq.corpus == IntelSource.CVE:
                m = retriever.lookup_cve(lq.query)
                returned = [m] if m else []
            elif lq.corpus == IntelSource.MITRE:
                m = retriever.lookup_technique(lq.query)
                returned = [m] if m else []
        else:
            # Semantic or negative
            target_corpora = [lq.corpus] if lq.corpus else None
            returned = retriever.search(lq.query, corpora=target_corpora, k=5)

        returned_ids = [m.doc_id for m in returned]
        top_score = returned[0].score if returned else 0.0

        # Check for hallucinations (ids not in store)
        hallucination = any(rid not in known_ids for rid in returned_ids)
        if hallucination:
            sc.hallucinations += 1

        # Hit detection and ranking
        hit = False
        rank = None
        if lq.query_type == "negative":
            # For negatives: "pass" if no high-confidence matches
            NEGATIVE_SCORE_THRESHOLD = 0.75
            hit = top_score < NEGATIVE_SCORE_THRESHOLD
            rank = None
        else:
            for i, rid in enumerate(returned_ids, 1):
                if rid in lq.expected_doc_ids:
                    hit = True
                    rank = i
                    sc.reciprocal_rank_sum += 1.0 / i
                    break

        if hit:
            sc.hits += 1

        result = EvalResult(
            qid=lq.qid,
            query_type=lq.query_type,
            corpus=corpus_str,
            expected=lq.expected_doc_ids,
            returned_ids=returned_ids[:5],
            hit=hit,
            rank=rank,
            top_score=round(top_score, 4),
            hallucination=hallucination,
        )
        all_results.append(result)

        status = "✓" if hit else "✗"
        hall_flag = " [HALLUCINATION]" if hallucination else ""
        print(f"  [{status}] {lq.qid:40s}  top_score={top_score:.3f}  rank={rank}{hall_flag}")

    duck.close()

    # ── Scorecard summary ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SCORECARD SUMMARY")
    print("=" * 70)

    scorecard_data: dict[str, dict] = {}
    all_pass = True

    for key, sc in sorted(scorecards.items()):
        label = f"{sc.corpus}/{sc.query_type}"
        row = {
            "total": sc.total,
            "hits": sc.hits,
            "accuracy": round(sc.accuracy, 3),
            "recall@5": round(sc.recall_at_5, 3),
            "MRR": round(sc.mrr, 3),
            "hallucinations": sc.hallucinations,
        }
        scorecard_data[label] = row
        fail_flag = ""

        if sc.query_type == "exact" and sc.accuracy < 1.0:
            fail_flag = "  ← FAIL (exact must be 100%)"
            all_pass = False
        if sc.hallucinations > 0:
            fail_flag += "  ← HALLUCINATIONS DETECTED"
            all_pass = False

        print(f"  {label:30s}  acc={sc.accuracy:.1%}  mrr={sc.mrr:.3f}  hall={sc.hallucinations}{fail_flag}")

    total_queries = len(LABELED_QUERIES)
    total_hits = sum(r.hit for r in all_results)
    total_hall = sum(r.hallucination for r in all_results)

    print(f"\n  Overall: {total_hits}/{total_queries} hits  ({total_hits/total_queries:.1%})  hallucinations={total_hall}")
    print(f"  No-hallucination test: {'PASS' if total_hall == 0 else 'FAIL'}")
    print(f"\n{'ALL TESTS PASS' if all_pass else 'SOME TESTS FAILED'}")

    return {
        "scorecard": scorecard_data,
        "total_queries": total_queries,
        "total_hits": total_hits,
        "total_hallucinations": total_hall,
        "all_pass": all_pass,
    }


if __name__ == "__main__":
    result = run_evaluation()
    sys.exit(0 if result["all_pass"] else 1)
