"""
tests/test_threat_intel_foundations.py
──────────────────────────────────────
Phase 6a acceptance tests: Threat Intelligence RAG Foundations.

Acceptance criteria:
* IntelDocument and IntelMatch schemas validate.
* DuckDB tables (iocs, cves, intel_links, intel_metadata) ingest and query without errors.
* Chroma collections initialise and store mock records.
* Embedder runs in offline mode using deterministic mock vectors.
* IOC normalization correctly refangs and validates IPs, domains, URLs, and hashes.
* Offline seed data ingests into all 5 corpora branches.
* Ingestion is 100% idempotent: running twice yields identical counts.
* CLI skeleton 'ingest --corpus all --offline-seed' executes cleanly.
"""
from __future__ import annotations

import json
from pathlib import Path
from click.testing import CliRunner
import pytest

from sentinelai.cli import main
from sentinelai.threat_intel.chroma_store import ThreatIntelChromaStore
from sentinelai.threat_intel.duckdb_store import ThreatIntelDuckDBStore
from sentinelai.threat_intel.embeddings import DeterministicMockEmbedder, SentenceTransformerEmbedder
from sentinelai.threat_intel.ingest import ThreatIntelIngester
from sentinelai.threat_intel.normalization import (
    detect_hash_type,
    normalize_domain,
    normalize_ioc,
    normalize_ip,
    normalize_url,
    refang,
)
from sentinelai.threat_intel.schemas import (
    IntelDocument,
    IntelMatch,
    IntelSource,
    IOCType,
    MatchType,
)


# ─────────────────────────────────────────────────────────────────────────────
# Schema Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatIntelSchemas:
    def test_intel_document_schema(self):
        doc = IntelDocument(
            doc_id="mitre:T1110",
            corpus=IntelSource.MITRE,
            title="Brute Force",
            text="Adversaries systematically guess passwords.",
            metadata={"tactic": "Credential Access"},
            source_url="https://attack.mitre.org/techniques/T1110",
        )
        assert doc.doc_id == "mitre:T1110"
        assert doc.corpus == IntelSource.MITRE
        assert doc.metadata["tactic"] == "Credential Access"

    def test_intel_match_schema(self):
        match = IntelMatch(
            doc_id="ioc:ip:192.0.2.10",
            corpus=IntelSource.IOC,
            title="Known scanner IP",
            snippet="192.0.2.10 scanner observed in brute force.",
            score=0.95,
            match_type=MatchType.EXACT,
            matched_on="192.0.2.10",
            trust_weight=1.0,
        )
        assert match.doc_id == "ioc:ip:192.0.2.10"
        assert match.score == 0.95
        assert match.match_type == MatchType.EXACT


# ─────────────────────────────────────────────────────────────────────────────
# Normalization Tests (Section 8.2 B)
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCNormalization:
    def test_refang_protocols_and_dots(self):
        assert refang("hxxp://evil[.]com/path") == "http://evil.com/path"
        assert refang("hxxps://malware[.]site[.]org") == "https://malware.site.org"
        assert refang("192[.]0[.]2[.]10") == "192.0.2.10"
        assert refang("bad(.)domain(.)net") == "bad.domain.net"
        assert refang("10[.]0[.]0[.]1[:]8080") == "10.0.0.1:8080"

    def test_normalize_ip_valid(self):
        assert normalize_ip("192.0.2.1") == "192.0.2.1"
        assert normalize_ip("192[.]0[.]2[.]50") == "192.0.2.50"
        assert normalize_ip("2001:db8::1") == "2001:db8::1"

    def test_normalize_ip_invalid_raises(self):
        with pytest.raises(ValueError):
            normalize_ip("999.999.999.999")
        with pytest.raises(ValueError):
            normalize_ip("not-an-ip")

    def test_normalize_domain(self):
        assert normalize_domain("EVIL[.]COM.") == "evil.com"
        assert normalize_domain("https://Phish[.]net/login?x=1") == "phish.net"

    def test_normalize_url(self):
        url = normalize_url("hxxps://target[.]org/auth/login")
        assert url == "https://target.org/auth/login"

    def test_detect_hash_types(self):
        # 32 chars -> MD5
        md5_val = "44d88612fea8a8f36de82e1278abb02f"
        assert detect_hash_type(md5_val) == IOCType.HASH_MD5

        # 40 chars -> SHA1
        sha1_val = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert detect_hash_type(sha1_val) == IOCType.HASH_SHA1

        # 64 chars -> SHA256
        sha256_val = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert detect_hash_type(sha256_val) == IOCType.HASH_SHA256

    def test_normalize_ioc_dispatcher(self):
        kind, val = normalize_ioc("ip", "192[.]0[.]2[.]10")
        assert kind == IOCType.IP
        assert val == "192.0.2.10"

        kind, val = normalize_ioc("hash", "44d88612fea8a8f36de82e1278abb02f")
        assert kind == IOCType.HASH_MD5
        assert val == "44d88612fea8a8f36de82e1278abb02f"


# ─────────────────────────────────────────────────────────────────────────────
# Embedders Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEmbedders:
    def test_deterministic_mock_embedder(self):
        embedder = DeterministicMockEmbedder(dimension=384)
        assert embedder.dimension == 384

        v1 = embedder.embed_query("brute force attack")
        v2 = embedder.embed_query("brute force attack")
        v3 = embedder.embed_query("completely different concept")

        assert len(v1) == 384
        # Same input yields identical vector
        assert v1 == v2
        # Different input yields different vector
        assert v1 != v3

    def test_sentence_transformer_offline_fallback(self):
        # When model name is fake or offline, falls back gracefully without raising
        embedder = SentenceTransformerEmbedder("non-existent-model", offline_fallback=True)
        vec = embedder.embed_query("test query")
        assert len(vec) == 384


# ─────────────────────────────────────────────────────────────────────────────
# DuckDB Exact Store Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDuckDBStore:
    def setup_method(self):
        self.store = ThreatIntelDuckDBStore(":memory:")

    def teardown_method(self):
        self.store.close()

    def test_ioc_insert_and_lookup(self):
        self.store.insert_ioc(
            ioc_type=IOCType.IP,
            value_normalized="192.0.2.10",
            source="threatfox",
            confidence=0.95,
            tags=["scanner"],
            malware_family="Cobalt Strike",
        )
        hits = self.store.lookup_ioc("ip", "192.0.2.10")
        assert len(hits) == 1
        assert hits[0].doc_id == "ioc:ip:192.0.2.10"
        assert hits[0].score == 0.95
        assert "Cobalt Strike" in hits[0].snippet

    def test_cve_insert_and_lookup(self):
        self.store.insert_cve(
            cve_id="CVE-2021-41773",
            description="Apache HTTP Server path traversal vulnerability.",
            cvss_score=7.5,
            kev_flag=True,
            affected_products=[{"vendor": "apache", "product": "http_server", "version": "2.4.49"}],
        )
        # Exact lookup by ID
        hit = self.store.lookup_cve("CVE-2021-41773")
        assert hit is not None
        assert hit.doc_id == "cve:CVE-2021-41773"
        assert hit.score == 0.75

        # Software lookup
        prod_hits = self.store.lookup_cve_by_software("http_server", "2.4.49")
        assert len(prod_hits) == 1
        assert prod_hits[0].doc_id == "cve:CVE-2021-41773"

    def test_relation_links_and_traversal(self):
        # Technique -> Sub-technique
        self.store.insert_link("mitre:T1110", "mitre:T1110.003", "parent_of")
        # Sub-technique -> Malware
        self.store.insert_link("mitre:T1110.003", "malware:S0154", "used_by")

        # 1-hop traversal from T1110
        links_1 = self.store.get_links("mitre:T1110", hops=1)
        assert any(dst == "mitre:T1110.003" for _, dst, _ in links_1)

        # 2-hop traversal reaches S0154
        links_2 = self.store.get_links("mitre:T1110", hops=2)
        all_nodes = [src for src, _, _ in links_2] + [dst for _, dst, _ in links_2]
        assert "malware:S0154" in all_nodes


# ─────────────────────────────────────────────────────────────────────────────
# Chroma Store Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestChromaStore:
    def setup_method(self):
        self.embedder = DeterministicMockEmbedder()
        self.store = ThreatIntelChromaStore(embedder=self.embedder, force_in_memory=True)

    def test_add_and_query_documents(self):
        doc1 = IntelDocument(
            doc_id="mitre:T1110",
            corpus=IntelSource.MITRE,
            title="Brute Force",
            text="Systematic password guessing against accounts.",
            metadata={"tactics": "Credential Access"},
        )
        doc2 = IntelDocument(
            doc_id="mitre:T1078",
            corpus=IntelSource.MITRE,
            title="Valid Accounts",
            text="Adversaries obtain and abuse existing credentials.",
            metadata={"tactics": "Defense Evasion"},
        )
        self.store.add_documents(IntelSource.MITRE, [doc1, doc2])
        assert self.store.count("mitre") == 2

        matches = self.store.query("mitre", "Systematic password guessing", k=2)
        assert len(matches) >= 1
        assert matches[0].doc_id == "mitre:T1110"


# ─────────────────────────────────────────────────────────────────────────────
# Ingestion Pipeline & Idempotency Acceptance Gate (Phase 6a)
# ─────────────────────────────────────────────────────────────────────────────

class TestIngestionAcceptanceGate:
    def setup_method(self):
        self.duck = ThreatIntelDuckDBStore(":memory:")
        self.chroma = ThreatIntelChromaStore(embedder=DeterministicMockEmbedder(), force_in_memory=True)
        self.ingester = ThreatIntelIngester(self.duck, self.chroma)

    def teardown_method(self):
        self.duck.close()

    def test_offline_seed_ingest_all_populates_stores(self):
        counts = self.ingester.ingest_all()

        # All 5 corpora populated
        assert counts["patterns"] == 7
        assert counts["iocs"] == 7
        assert counts["cves"] == 4
        assert counts["mitre"] == 11
        assert counts["malware"] == 4

        # DuckDB tables populated
        db_counts = self.duck.counts()
        assert db_counts["iocs"] == 7
        assert db_counts["cves"] == 4
        assert db_counts["intel_links"] > 0
        assert db_counts["intel_metadata"] > 0

    def test_ingestion_is_strictly_idempotent(self):
        """Acceptance Gate: Running ingestion twice produces identical record counts."""
        pass1 = self.ingester.ingest_all()
        db_pass1 = self.duck.counts()
        chroma_pass1 = self.chroma.counts()

        # Second pass over identical data
        pass2 = self.ingester.ingest_all()
        db_pass2 = self.duck.counts()
        chroma_pass2 = self.chroma.counts()

        assert pass1 == pass2
        assert db_pass1 == db_pass2
        assert chroma_pass1 == chroma_pass2

    def test_cli_ingest_command_executes_cleanly(self):
        """CLI skeleton 'ingest --corpus all --offline-seed' executes with exit code 0."""
        runner = CliRunner()
        result = runner.invoke(main, ["ingest", "--corpus", "all", "--offline-seed"])
        assert result.exit_code == 0
        assert "Ingestion completed successfully" in result.output
        assert "patterns: 7" in result.output
        assert "iocs: 7" in result.output
