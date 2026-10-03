"""
sentinelai/threat_intel/chroma_store.py
───────────────────────────────────────
ChromaDB vector store manager for the 4 text corpora: MITRE, CVEs, Malware, Patterns (Section 8.1).
Maintains one dedicated collection per corpus branch, with metadata filtering and cosine similarity ranking.
Includes a lightweight in-memory fallback vector engine for zero-dependency offline test execution.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from sentinelai.threat_intel.embeddings import DeterministicMockEmbedder, Embedder
from sentinelai.threat_intel.schemas import (
    IntelDocument,
    IntelMatch,
    IntelSource,
    MatchType,
)

# Active vector collections (IOCs are stored only in DuckDB exact tables)
COLLECTIONS = ["mitre", "cves", "malware", "patterns"]

COLLECTION_MAP = {
    "mitre": "mitre",
    "cve": "cves",
    "cves": "cves",
    "malware": "malware",
    "pattern": "patterns",
    "patterns": "patterns",
}

COLLECTION_TO_SOURCE = {
    "mitre": IntelSource.MITRE,
    "cves": IntelSource.CVE,
    "cve": IntelSource.CVE,
    "malware": IntelSource.MALWARE,
    "patterns": IntelSource.PATTERN,
    "pattern": IntelSource.PATTERN,
}


def _resolve_collection(corpus: IntelSource | str) -> str:
    raw = corpus.value if isinstance(corpus, IntelSource) else str(corpus).lower()
    return COLLECTION_MAP.get(raw, raw)


class ThreatIntelChromaStore:
    """
    Vector store interface managing 4 independent ChromaDB collections:
    - mitre
    - cves
    - malware
    - patterns
    """

    def __init__(
        self,
        persist_directory: str | None = None,
        embedder: Embedder | None = None,
        force_in_memory: bool = False,
    ) -> None:
        self.persist_directory = persist_directory
        self.embedder = embedder or DeterministicMockEmbedder()
        self._collections: dict[str, Any] = {}
        self._use_chroma = False

        # Attempt to initialize ChromaDB if available and not forced to simple memory
        if not force_in_memory:
            try:
                import chromadb
                if persist_directory:
                    self._client = chromadb.PersistentClient(path=persist_directory)
                else:
                    self._client = chromadb.Client()
                self._use_chroma = True
                self._init_chroma_collections()
            except Exception:
                self._use_chroma = False

        # In-memory dictionary store (used when ChromaDB is not installed or for lightweight tests)
        if not self._use_chroma:
            self._mem_store: dict[str, dict[str, dict[str, Any]]] = {
                c: {} for c in COLLECTIONS
            }

    def _init_chroma_collections(self) -> None:
        """Create or get Chroma collections for each corpus branch with cosine distance."""
        for c in COLLECTIONS:
            self._collections[c] = self._client.get_or_create_collection(
                name=c,
                metadata={"hnsw:space": "cosine"},
            )

    def _clean_metadata(self, meta: dict[str, Any]) -> dict[str, Any]:
        """Chroma metadata allows only str, int, float, bool."""
        clean: dict[str, Any] = {}
        for k, v in meta.items():
            if isinstance(v, (str, int, float, bool)):
                clean[k] = v
            elif isinstance(v, list):
                clean[k] = ", ".join(str(x) for x in v)
            elif v is None:
                continue
            else:
                clean[k] = str(v)
        return clean

    def add_documents(
        self,
        corpus: IntelSource | str,
        documents: list[IntelDocument],
    ) -> int:
        """
        Embed and store documents in the specified corpus collection.
        Idempotent: updates existing document IDs.
        """
        c_name = _resolve_collection(corpus)
        if c_name not in COLLECTIONS:
            raise ValueError(f"Unknown vector corpus '{c_name}'. Valid: {COLLECTIONS}")

        if not documents:
            return 0

        texts = [d.text for d in documents]
        embeddings = self.embedder.embed_documents(texts)
        ids = [d.doc_id for d in documents]

        if self._use_chroma:
            coll = self._collections[c_name]
            metadatas = [
                self._clean_metadata(
                    {
                        "doc_id": d.doc_id,
                        "title": d.title,
                        "source_url": d.source_url or "",
                        "corpus": c_name,
                        "corpus_version": d.corpus_version,
                        **d.metadata,
                    }
                )
                for d in documents
            ]
            coll.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=texts,
                metadatas=metadatas,
            )
            return len(documents)

        # In-memory vector store implementation
        for doc, emb, d_id in zip(documents, embeddings, ids):
            self._mem_store[c_name][d_id] = {
                "doc": doc,
                "embedding": emb,
                "text": doc.text,
            }
        return len(documents)

    def query(
        self,
        corpus: IntelSource | str,
        query_text: str,
        k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[IntelMatch]:
        """
        Semantic similarity search in the specified corpus collection.
        Returns top k IntelMatch objects ranked by cosine similarity (0 to 1).
        """
        c_name = corpus.value if isinstance(corpus, IntelSource) else str(corpus).lower()
        if c_name not in COLLECTIONS:
            return []

        query_vec = self.embedder.embed_query(query_text)

        if self._use_chroma:
            coll = self._collections[c_name]
            chroma_filter = filters if filters else None
            # Count elements first
            if coll.count() == 0:
                return []
            res = coll.query(
                query_embeddings=[query_vec],
                n_results=min(k, coll.count()),
                where=chroma_filter,
            )

            matches: list[IntelMatch] = []
            if not res or not res["ids"] or not res["ids"][0]:
                return matches

            for doc_id, dist, meta, doc_str in zip(
                res["ids"][0],
                res["distances"][0] if res["distances"] else [0.0] * len(res["ids"][0]),
                res["metadatas"][0] if res["metadatas"] else [{}] * len(res["ids"][0]),
                res["documents"][0] if res["documents"] else [""] * len(res["ids"][0]),
            ):
                # Cosine distance to similarity: 1.0 - (dist / 2.0)
                sim = max(0.0, min(1.0, 1.0 - float(dist or 0.0)))
                title = meta.get("title", doc_id) if meta else doc_id
                url = meta.get("source_url") if meta else None
                snippet = doc_str[:250].strip() + ("..." if len(doc_str) > 250 else "")

                matches.append(
                    IntelMatch(
                        doc_id=doc_id,
                        corpus=COLLECTION_TO_SOURCE.get(c_name, IntelSource.MITRE),
                        title=title,
                        snippet=snippet,
                        score=round(sim, 3),
                        match_type=MatchType.SEMANTIC,
                        matched_on=query_text[:100],
                        source_url=url if url else None,
                        retrieved_at=datetime.now(timezone.utc),
                        trust_weight=1.0 if c_name == "mitre" else 0.85,
                    )
                )
            return matches

        # Fallback in-memory cosine similarity
        coll_dict = self._mem_store.get(c_name, {})
        if not coll_dict:
            return []

        scored_items: list[tuple[float, IntelDocument]] = []
        for d_id, record in coll_dict.items():
            doc: IntelDocument = record["doc"]
            # Apply metadata filter if given
            if filters:
                match_filter = all(
                    doc.metadata.get(fk) == fv for fk, fv in filters.items()
                )
                if not match_filter:
                    continue

            emb = record["embedding"]
            # Dot product for normalized vectors = cosine similarity
            sim = sum(a * b for a, b in zip(query_vec, emb))
            sim_norm = max(0.0, min(1.0, (sim + 1.0) / 2.0))
            scored_items.append((sim_norm, doc))

        scored_items.sort(key=lambda x: x[0], reverse=True)
        top_items = scored_items[:k]

        results: list[IntelMatch] = []
        for sim, doc in top_items:
            snippet = doc.text[:250].strip() + ("..." if len(doc.text) > 250 else "")
            results.append(
                IntelMatch(
                    doc_id=doc.doc_id,
                    corpus=COLLECTION_TO_SOURCE.get(c_name, IntelSource.MITRE),
                    title=doc.title,
                    snippet=snippet,
                    score=round(sim, 3),
                    match_type=MatchType.SEMANTIC,
                    matched_on=query_text[:100],
                    source_url=doc.source_url,
                    retrieved_at=datetime.now(timezone.utc),
                    trust_weight=1.0 if c_name == "mitre" else 0.85,
                )
            )
        return results

    def count(self, corpus: IntelSource | str) -> int:
        """Count items in a single collection."""
        c_name = corpus.value if isinstance(corpus, IntelSource) else str(corpus).lower()
        if self._use_chroma and c_name in self._collections:
            return int(self._collections[c_name].count())
        return len(self._mem_store.get(c_name, {}))

    def counts(self) -> dict[str, int]:
        """Count items across all collections."""
        return {c: self.count(c) for c in COLLECTIONS}

    def clear(self) -> None:
        """Clear all collections."""
        if self._use_chroma:
            for c in COLLECTIONS:
                self._client.delete_collection(name=c)
            self._init_chroma_collections()
        else:
            for c in COLLECTIONS:
                self._mem_store[c].clear()
