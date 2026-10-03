"""
sentinelai/threat_intel/retriever.py
─────────────────────────────────────
Phase 6c: HybridThreatIntelRetriever – exact + semantic + link expansion + rerank.

Implements the full 4-stage retrieval pipeline described in Section 8.4:
  1. Exact stage   – DuckDB iocs, cves, mitre technique IDs
  2. Semantic stage – ChromaDB (patterns, mitre, malware, cves)
  3. Link expansion – intel_links graph (1 hop)
  4. Merge + rerank – deduplicate, trust_weight, freshness penalty, top-k per corpus

Also ships ``MockThreatIntelRetriever`` for deterministic test fixtures.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from sentinelai.schemas import Entities
from sentinelai.threat_intel.chroma_store import ThreatIntelChromaStore
from sentinelai.threat_intel.duckdb_store import ThreatIntelDuckDBStore
from sentinelai.threat_intel.normalization import normalize_ioc
from sentinelai.threat_intel.schemas import (
    IntelMatch,
    IntelSource,
    MatchType,
    ThreatIntelRetriever,
)

# ─────────────────────────────────────────────────────────────────────────────
# Trust weights by source (Section 8.4 rerank rules)
# ─────────────────────────────────────────────────────────────────────────────

_SOURCE_TRUST: dict[str, float] = {
    "mitre": 1.0,
    "cve": 1.0,
    "malware": 0.95,
    "pattern": 0.95,
    "ioc": 0.85,
}

_LINKED_SCORE_DISCOUNT = 0.8  # 20 % penalty for LINKED matches


def _freshness_weight(match: IntelMatch) -> float:
    """Apply a staleness penalty if ``freshness_days`` is set (Section 8.2 B)."""
    if match.freshness_days is None:
        return 1.0
    # Decay: half-life 180 days – very old IOCs still carry some weight
    return math.exp(-0.693 * match.freshness_days / 180)


def _deduplicate(matches: list[IntelMatch]) -> list[IntelMatch]:
    """Keep the highest-scoring IntelMatch per doc_id."""
    seen: dict[str, IntelMatch] = {}
    for m in matches:
        if m.doc_id not in seen or m.score > seen[m.doc_id].score:
            seen[m.doc_id] = m
    return list(seen.values())


def _rerank(matches: list[IntelMatch]) -> list[IntelMatch]:
    """
    Apply trust_weight × freshness_weight to scores, clamp to [0, 1],
    and sort descending.
    """
    reranked: list[IntelMatch] = []
    for m in matches:
        fw = _freshness_weight(m)
        new_score = min(1.0, m.score * m.trust_weight * fw)
        reranked.append(m.model_copy(update={"score": round(new_score, 4)}))
    return sorted(reranked, key=lambda x: x.score, reverse=True)


def _top_k_per_corpus(matches: list[IntelMatch], k: int) -> list[IntelMatch]:
    """Return the top ``k`` matches per corpus branch."""
    buckets: dict[str, list[IntelMatch]] = {}
    for m in matches:
        buckets.setdefault(m.corpus.value, []).append(m)

    result: list[IntelMatch] = []
    for corpus_matches in buckets.values():
        result.extend(sorted(corpus_matches, key=lambda x: x.score, reverse=True)[:k])
    return sorted(result, key=lambda x: x.score, reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# HybridThreatIntelRetriever
# ─────────────────────────────────────────────────────────────────────────────


class HybridThreatIntelRetriever:
    """
    Full hybrid retriever implementing Section 8.4 and the ``ThreatIntelRetriever``
    Protocol from Section 8.5.

    Pipeline: exact → semantic → link expansion → deduplicate → rerank → top-k/corpus.
    """

    def __init__(
        self,
        duck_store: ThreatIntelDuckDBStore,
        chroma_store: ThreatIntelChromaStore,
    ) -> None:
        self.duck = duck_store
        self.chroma = chroma_store

    # ── Exact lookups ─────────────────────────────────────────────────────────

    def lookup_ioc(self, kind: str, value: str) -> list[IntelMatch]:
        """
        Exact lookup on normalized IOC value (Section 8.2 B).
        Normalizes defanged values before querying.
        """
        try:
            ioc_kind, norm_val = normalize_ioc(kind, value)
            return self.duck.lookup_ioc(ioc_kind.value, norm_val)
        except Exception:
            return []

    def lookup_cve(self, cve_id: str) -> IntelMatch | None:
        """Exact lookup by CVE identifier (Section 8.2 C)."""
        return self.duck.lookup_cve(cve_id)

    def lookup_cve_by_software(self, product: str, version: str | None = None) -> list[IntelMatch]:
        """Software-based CVE lookup (Section 8.2 C)."""
        return self.duck.lookup_cve_by_software(product, version)

    def lookup_technique(self, technique_id: str) -> IntelMatch | None:
        """
        Exact lookup by MITRE technique T-ID (e.g. T1110.003).
        Falls back to semantic search on the technique ID string if not in metadata.
        """
        t_id = technique_id.strip().upper()
        doc_id = f"mitre:{t_id}"

        # Try exact metadata record
        meta = self.duck.get_metadata(doc_id)
        if meta:
            return IntelMatch(
                doc_id=doc_id,
                corpus=IntelSource.MITRE,
                title=meta["title"],
                snippet=f"MITRE ATT&CK technique {t_id}: {meta['title']}",
                score=1.0,
                match_type=MatchType.EXACT,
                matched_on=t_id,
                source_url=meta.get("source_url"),
                retrieved_at=datetime.now(timezone.utc),
                trust_weight=_SOURCE_TRUST["mitre"],
            )

        # Semantic fallback: search by T-ID string
        sem = self.chroma.query("mitre", t_id, k=1)
        if sem:
            best = sem[0]
            # Only return if doc_id contains the technique we searched for
            if t_id.lower() in best.doc_id.lower():
                return best.model_copy(update={"match_type": MatchType.EXACT, "matched_on": t_id})
        return None

    # ── Semantic search ───────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        corpora: list[IntelSource] | None = None,
        k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[IntelMatch]:
        """
        Semantic search across one or more corpora (Section 8.4 Stage 2).
        Defaults to searching all vector-indexed corpora if ``corpora`` is None.
        """
        target_corpora = corpora or [
            IntelSource.MITRE,
            IntelSource.CVE,
            IntelSource.MALWARE,
            IntelSource.PATTERN,
        ]

        all_matches: list[IntelMatch] = []
        for corpus in target_corpora:
            if corpus == IntelSource.IOC:
                continue  # IOCs are exact-match only
            try:
                col_name = corpus.value
                if col_name == "cve":
                    col_name = "cves"
                elif col_name == "pattern":
                    col_name = "patterns"

                matches = self.chroma.query(col_name, query, k=k, filters=filters)
                # Set trust weights by source
                tw = _SOURCE_TRUST.get(corpus.value, 0.8)
                all_matches.extend(
                    m.model_copy(update={"trust_weight": tw}) for m in matches
                )
            except Exception:
                continue

        return _rerank(_deduplicate(all_matches))[:k]

    # ── Link expansion ────────────────────────────────────────────────────────

    def expand(self, doc_id: str, hops: int = 1) -> list[IntelMatch]:
        """
        1-hop (or N-hop) link traversal from a document (Section 8.3).
        Fetches neighbor docs from intel_metadata, marks as LINKED, discounts score.
        """
        links = self.duck.get_links(doc_id, hops=hops)
        if not links:
            return []

        neighbor_ids: set[str] = set()
        for src, dst, _ in links:
            if src != doc_id:
                neighbor_ids.add(src)
            if dst != doc_id:
                neighbor_ids.add(dst)

        results: list[IntelMatch] = []
        for nid in neighbor_ids:
            meta = self.duck.get_metadata(nid)
            if not meta:
                continue

            corpus_str = meta.get("corpus", "mitre")
            try:
                corpus = IntelSource(corpus_str)
            except ValueError:
                corpus = IntelSource.MITRE

            tw = _SOURCE_TRUST.get(corpus_str, 0.8)
            results.append(
                IntelMatch(
                    doc_id=nid,
                    corpus=corpus,
                    title=meta["title"],
                    snippet=f"[Linked from {doc_id}] {meta['title']}",
                    score=round(_LINKED_SCORE_DISCOUNT * tw, 4),
                    match_type=MatchType.LINKED,
                    matched_on=doc_id,
                    linked_from=doc_id,
                    source_url=meta.get("source_url"),
                    retrieved_at=datetime.now(timezone.utc),
                    trust_weight=tw,
                )
            )
        return sorted(results, key=lambda x: x.score, reverse=True)

    # ── Full hybrid retrieve ──────────────────────────────────────────────────

    def retrieve(
        self,
        entities: Entities,
        hints: list[str],
        claims: list[str] | None = None,
        k: int = 5,
    ) -> list[IntelMatch]:
        """
        Section 8.4 full pipeline:
        Stage 1: Exact lookups for entities + hints
        Stage 2: Semantic search over claims
        Stage 3: 1-hop link expansion from top exact/semantic hits
        Stage 4: Merge, rerank, top-k per corpus
        """
        all_matches: list[IntelMatch] = []

        # ── Stage 1: Exact ───────────────────────────────────────────────────
        # IPs
        for ip in entities.ips:
            all_matches.extend(self.lookup_ioc("ip", ip))

        # Domains
        for domain in entities.domains:
            all_matches.extend(self.lookup_ioc("domain", domain))

        # Hashes
        for h in entities.hashes:
            # Detect type by length
            htype = "hash_md5" if len(h) == 32 else "hash_sha1" if len(h) == 40 else "hash_sha256"
            all_matches.extend(self.lookup_ioc(htype, h))

        # CVE IDs
        for cve_id in entities.cves:
            m = self.lookup_cve(cve_id)
            if m:
                all_matches.append(m)

        # MITRE T-IDs in hints
        for hint in hints:
            tid_clean = hint.strip().upper()
            if tid_clean.startswith("T") and len(tid_clean) >= 4:
                m = self.lookup_technique(tid_clean)
                if m:
                    all_matches.append(m)

        # ── Stage 2: Semantic ────────────────────────────────────────────────
        for claim in (claims or []):
            if not claim.strip():
                continue
            sem_results = self.search(
                query=claim,
                corpora=[IntelSource.MITRE, IntelSource.PATTERN, IntelSource.MALWARE, IntelSource.CVE],
                k=k,
            )
            all_matches.extend(sem_results)

        # ── Stage 3: Link expansion ───────────────────────────────────────────
        # Expand top 3 exact + semantic hits
        top_for_expansion = _rerank(_deduplicate(all_matches))[:3]
        for match in top_for_expansion:
            all_matches.extend(self.expand(match.doc_id, hops=1))

        # ── Stage 4: Merge + rerank + top-k per corpus ───────────────────────
        deduped = _deduplicate(all_matches)
        reranked = _rerank(deduped)
        return _top_k_per_corpus(reranked, k)


# ─────────────────────────────────────────────────────────────────────────────
# MockThreatIntelRetriever – deterministic fixtures for tests (Section 8.5)
# ─────────────────────────────────────────────────────────────────────────────


class MockThreatIntelRetriever:
    """
    Deterministic mock for offline tests. Returns pre-set fixture matches.

    Usage:
        retriever = MockThreatIntelRetriever()
        retriever.add_fixture(IntelMatch(...))
        matches = retriever.retrieve(entities, hints, claims)
    """

    def __init__(self) -> None:
        self._fixtures: list[IntelMatch] = []
        self._ioc_table: dict[str, list[IntelMatch]] = {}
        self._cve_table: dict[str, IntelMatch] = {}
        self._technique_table: dict[str, IntelMatch] = {}

    def add_fixture(self, match: IntelMatch) -> None:
        """Register a fixture match for retrieval."""
        self._fixtures.append(match)

        if match.corpus == IntelSource.IOC:
            key = match.matched_on.lower()
            self._ioc_table.setdefault(key, []).append(match)

        elif match.corpus == IntelSource.CVE:
            self._cve_table[match.doc_id.replace("cve:", "").upper()] = match

        elif match.corpus == IntelSource.MITRE:
            tid = match.doc_id.replace("mitre:", "").upper()
            self._technique_table[tid] = match

    def lookup_ioc(self, kind: str, value: str) -> list[IntelMatch]:
        key = f"{kind}:{value}".lower()
        return self._ioc_table.get(key, [])

    def lookup_cve(self, cve_id: str) -> IntelMatch | None:
        return self._cve_table.get(cve_id.strip().upper())

    def lookup_cve_by_software(self, product: str, version: str | None = None) -> list[IntelMatch]:
        return [m for m in self._fixtures if m.corpus == IntelSource.CVE]

    def lookup_technique(self, technique_id: str) -> IntelMatch | None:
        return self._technique_table.get(technique_id.strip().upper())

    def search(
        self,
        query: str,
        corpora: list[IntelSource] | None = None,
        k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[IntelMatch]:
        results = [
            m for m in self._fixtures
            if not corpora or m.corpus in corpora
        ]
        return sorted(results, key=lambda x: x.score, reverse=True)[:k]

    def expand(self, doc_id: str, hops: int = 1) -> list[IntelMatch]:
        return [m for m in self._fixtures if m.linked_from == doc_id]

    def retrieve(
        self,
        entities: Entities,
        hints: list[str],
        claims: list[str] | None = None,
        k: int = 5,
    ) -> list[IntelMatch]:
        """Return all registered fixtures sorted by score, top-k per corpus."""
        return _top_k_per_corpus(_rerank(list(self._fixtures)), k)
