"""
sentinelai/threat_intel/duckdb_store.py
───────────────────────────────────────
DuckDB exact-match store and relation link graph for Threat Intelligence (Section 8.1 - 8.3).
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

import duckdb

from sentinelai.threat_intel.schemas import (
    IntelDocument,
    IntelMatch,
    IntelSource,
    IOCType,
    MatchType,
)


class ThreatIntelDuckDBStore:
    """
    DuckDB-backed exact lookup tables and relation graph for Threat Intelligence.

    Tables:
    - iocs: Exact-match IP, domain, URL, and file hashes
    - cves: Structured vulnerability data and affected software
    - intel_links: Relation links (parent_of, used_by, maps_to, associated_with, exploited_via)
    - intel_metadata: Common metadata cache for all corpora
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = duckdb.connect(db_path)
        self._setup_schema()

    def _setup_schema(self) -> None:
        """Create exact-match and relation tables with indexes."""
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_type VARCHAR NOT NULL,
                    value_normalized VARCHAR NOT NULL,
                    source VARCHAR NOT NULL,
                    first_seen VARCHAR,
                    last_seen VARCHAR,
                    confidence DOUBLE DEFAULT 0.8,
                    tags_json VARCHAR DEFAULT '[]',
                    malware_family VARCHAR,
                    reference_url VARCHAR,
                    PRIMARY KEY (ioc_type, value_normalized)
                );

                CREATE TABLE IF NOT EXISTS cves (
                    cve_id VARCHAR PRIMARY KEY,
                    description TEXT NOT NULL,
                    cvss_score DOUBLE,
                    cvss_vector VARCHAR,
                    cwe VARCHAR,
                    published_date VARCHAR,
                    modified_date VARCHAR,
                    kev_flag BOOLEAN DEFAULT FALSE,
                    affected_products_json VARCHAR DEFAULT '[]',
                    references_json VARCHAR DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS intel_links (
                    src_id VARCHAR NOT NULL,
                    dst_id VARCHAR NOT NULL,
                    relation VARCHAR NOT NULL,
                    PRIMARY KEY (src_id, dst_id, relation)
                );

                CREATE TABLE IF NOT EXISTS intel_metadata (
                    doc_id VARCHAR PRIMARY KEY,
                    corpus VARCHAR NOT NULL,
                    title VARCHAR NOT NULL,
                    metadata_json VARCHAR DEFAULT '{}',
                    source_url VARCHAR,
                    ingested_at VARCHAR NOT NULL,
                    corpus_version VARCHAR DEFAULT 'v1'
                );
                """
            )

    # ── IOC operations ────────────────────────────────────────────────────────

    def insert_ioc(
        self,
        ioc_type: IOCType | str,
        value_normalized: str,
        source: str = "seed",
        first_seen: str | None = None,
        last_seen: str | None = None,
        confidence: float = 0.8,
        tags: list[str] | None = None,
        malware_family: str | None = None,
        reference_url: str | None = None,
    ) -> None:
        """Insert or replace an IOC record."""
        t_str = ioc_type.value if isinstance(ioc_type, IOCType) else str(ioc_type)
        tags_json = json.dumps(tags or [])
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO iocs (
                    ioc_type, value_normalized, source, first_seen, last_seen,
                    confidence, tags_json, malware_family, reference_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    t_str,
                    value_normalized.strip().lower() if t_str in ("ip", "domain", "hash_md5", "hash_sha1", "hash_sha256") else value_normalized.strip(),
                    source,
                    first_seen or datetime.now(timezone.utc).isoformat(),
                    last_seen or datetime.now(timezone.utc).isoformat(),
                    confidence,
                    tags_json,
                    malware_family,
                    reference_url,
                ],
            )

    def lookup_ioc(self, ioc_type: str, value_normalized: str) -> list[IntelMatch]:
        """Exact lookup of an IOC record."""
        t_clean = ioc_type.lower().strip()
        v_clean = value_normalized.strip().lower() if t_clean in ("ip", "domain", "hash_md5", "hash_sha1", "hash_sha256") else value_normalized.strip()

        with self._lock:
            rel = self._conn.execute(
                """
                SELECT ioc_type, value_normalized, source, first_seen, last_seen,
                       confidence, tags_json, malware_family, reference_url
                FROM iocs
                WHERE ioc_type = ? AND value_normalized = ?
                """,
                [t_clean, v_clean],
            )
            rows = rel.fetchall()

        results: list[IntelMatch] = []
        for row in rows:
            doc_id = f"ioc:{row[0]}:{row[1]}"
            malware_str = f" [Malware: {row[7]}]" if row[7] else ""
            snippet = f"Known malicious {row[0].upper()} indicator from {row[2]}{malware_str}. Last seen: {row[4]}."
            results.append(
                IntelMatch(
                    doc_id=doc_id,
                    corpus=IntelSource.IOC,
                    title=f"IOC: {row[0]} {row[1]}",
                    snippet=snippet,
                    score=float(row[5] or 0.8),
                    match_type=MatchType.EXACT,
                    matched_on=f"{row[0]}:{row[1]}",
                    source_url=row[8],
                    retrieved_at=datetime.now(timezone.utc),
                    trust_weight=0.9,
                )
            )
        return results

    # ── CVE operations ────────────────────────────────────────────────────────

    def insert_cve(
        self,
        cve_id: str,
        description: str,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        cwe: str | None = None,
        published_date: str | None = None,
        modified_date: str | None = None,
        kev_flag: bool = False,
        affected_products: list[dict[str, Any]] | None = None,
        references: list[str] | None = None,
    ) -> None:
        """Insert or update a CVE record."""
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO cves (
                    cve_id, description, cvss_score, cvss_vector, cwe,
                    published_date, modified_date, kev_flag,
                    affected_products_json, references_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    cve_id.strip().upper(),
                    description,
                    cvss_score,
                    cvss_vector,
                    cwe,
                    published_date,
                    modified_date,
                    kev_flag,
                    json.dumps(affected_products or []),
                    json.dumps(references or []),
                ],
            )

    def lookup_cve(self, cve_id: str) -> IntelMatch | None:
        """Exact lookup by CVE identifier."""
        clean_id = cve_id.strip().upper()
        with self._lock:
            rel = self._conn.execute(
                """
                SELECT cve_id, description, cvss_score, cvss_vector, cwe,
                       published_date, modified_date, kev_flag, references_json
                FROM cves
                WHERE cve_id = ?
                """,
                [clean_id],
            )
            row = rel.fetchone()

        if not row:
            return None

        c_id, desc, score, _, cwe, pub, _, kev, refs_json = row
        score_val = (score / 10.0) if score is not None else 0.7
        kev_notice = " [CISA KEV Listed]" if kev else ""
        snippet = f"{c_id} (CVSS: {score or 'N/A'}{kev_notice}): {desc[:200]}"
        refs = json.loads(refs_json) if refs_json else []
        src_url = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{c_id}"

        return IntelMatch(
            doc_id=f"cve:{c_id}",
            corpus=IntelSource.CVE,
            title=f"CVE: {c_id}",
            snippet=snippet,
            score=min(1.0, max(0.1, score_val)),
            match_type=MatchType.EXACT,
            matched_on=clean_id,
            source_url=src_url,
            retrieved_at=datetime.now(timezone.utc),
            trust_weight=1.0,
        )

    def lookup_cve_by_software(self, product: str, version: str | None = None) -> list[IntelMatch]:
        """
        Lookup CVEs affecting specified software product and optional version.
        Scans affected_products_json.
        """
        p_clean = product.lower().strip()
        v_clean = version.strip() if version else None

        with self._lock:
            rel = self._conn.execute(
                """
                SELECT cve_id, description, cvss_score, kev_flag, affected_products_json, references_json
                FROM cves
                """
            )
            rows = rel.fetchall()

        matches: list[IntelMatch] = []
        for row in rows:
            cve_id, desc, score, kev, aff_json, refs_json = row
            try:
                aff_list = json.loads(aff_json or "[]")
            except Exception:
                aff_list = []

            matched = False
            for item in aff_list:
                item_prod = str(item.get("product", "")).lower()
                if p_clean in item_prod or item_prod in p_clean:
                    if v_clean:
                        # Version check (basic substring or range)
                        item_v = str(item.get("version", ""))
                        if v_clean == item_v or v_clean in item_v or item.get("version_range"):
                            matched = True
                            break
                    else:
                        matched = True
                        break

            if matched:
                score_val = (score / 10.0) if score is not None else 0.7
                refs = json.loads(refs_json) if refs_json else []
                src_url = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                matches.append(
                    IntelMatch(
                        doc_id=f"cve:{cve_id}",
                        corpus=IntelSource.CVE,
                        title=f"CVE: {cve_id} affecting {product}",
                        snippet=f"{cve_id}: {desc[:180]}...",
                        score=round(score_val, 2),
                        match_type=MatchType.EXACT,
                        matched_on=f"software:{product}" + (f":{version}" if version else ""),
                        source_url=src_url,
                        retrieved_at=datetime.now(timezone.utc),
                        trust_weight=0.9,
                    )
                )

        return matches

    # ── Relation Link operations ──────────────────────────────────────────────

    def insert_link(self, src_id: str, dst_id: str, relation: str) -> None:
        """Insert a bidirectional or directional relation link (Section 8.3)."""
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO intel_links (src_id, dst_id, relation)
                VALUES (?, ?, ?)
                """,
                [src_id.strip(), dst_id.strip(), relation.strip()],
            )

    def get_links(self, doc_id: str, hops: int = 1) -> list[tuple[str, str, str]]:
        """
        Follow relation links from doc_id up to specified hops.
        Returns list of (src_id, dst_id, relation) tuples.
        """
        clean_id = doc_id.strip()
        visited: set[str] = {clean_id}
        current_frontier: set[str] = {clean_id}
        all_links: list[tuple[str, str, str]] = []

        for _ in range(hops):
            if not current_frontier:
                break
            next_frontier: set[str] = set()
            placeholders = ",".join(["?"] * len(current_frontier))

            with self._lock:
                rel = self._conn.execute(
                    f"""
                    SELECT src_id, dst_id, relation
                    FROM intel_links
                    WHERE src_id IN ({placeholders}) OR dst_id IN ({placeholders})
                    """,
                    list(current_frontier) + list(current_frontier),
                )
                rows = rel.fetchall()

            for src, dst, r_type in rows:
                all_links.append((src, dst, r_type))
                neighbor = dst if src in current_frontier else src
                if neighbor not in visited:
                    visited.add(neighbor)
                    next_frontier.add(neighbor)

            current_frontier = next_frontier

        return all_links

    # ── Metadata cache ────────────────────────────────────────────────────────

    def insert_metadata(self, doc: IntelDocument) -> None:
        """Store document metadata."""
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO intel_metadata (
                    doc_id, corpus, title, metadata_json, source_url, ingested_at, corpus_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    doc.doc_id,
                    doc.corpus.value,
                    doc.title,
                    json.dumps(doc.metadata),
                    doc.source_url,
                    doc.ingested_at.isoformat(),
                    doc.corpus_version,
                ],
            )

    def get_metadata(self, doc_id: str) -> dict[str, Any] | None:
        """Retrieve stored metadata for a document ID."""
        with self._lock:
            rel = self._conn.execute(
                """
                SELECT doc_id, corpus, title, metadata_json, source_url, ingested_at, corpus_version
                FROM intel_metadata
                WHERE doc_id = ?
                """,
                [doc_id.strip()],
            )
            row = rel.fetchone()

        if not row:
            return None
        return {
            "doc_id": row[0],
            "corpus": row[1],
            "title": row[2],
            "metadata": json.loads(row[3]),
            "source_url": row[4],
            "ingested_at": row[5],
            "corpus_version": row[6],
        }

    # ── Store metrics ─────────────────────────────────────────────────────────

    def counts(self) -> dict[str, int]:
        """Return counts of all tables."""
        with self._lock:
            ioc_cnt = self._conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            cve_cnt = self._conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            link_cnt = self._conn.execute("SELECT COUNT(*) FROM intel_links").fetchone()[0]
            meta_cnt = self._conn.execute("SELECT COUNT(*) FROM intel_metadata").fetchone()[0]

        return {
            "iocs": ioc_cnt,
            "cves": cve_cnt,
            "intel_links": link_cnt,
            "intel_metadata": meta_cnt,
        }

    def close(self) -> None:
        """Close connection."""
        with self._lock:
            self._conn.close()
