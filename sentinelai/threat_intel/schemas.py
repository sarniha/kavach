"""
sentinelai/threat_intel/schemas.py
──────────────────────────────────
Data models and Protocol interfaces for the Threat Intelligence RAG tier (Section 8.5).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from sentinelai.schemas import Entities


class IntelSource(str, Enum):
    """The 5 distinct threat intelligence corpus branches (Section 8.1)."""

    MITRE = "mitre"
    IOC = "ioc"
    CVE = "cve"
    MALWARE = "malware"
    PATTERN = "pattern"


class MatchType(str, Enum):
    """How the intelligence match was identified (Section 8.5)."""

    EXACT = "exact"
    SEMANTIC = "semantic"
    LINKED = "linked"


class IOCType(str, Enum):
    """Supported IOC indicator types (Section 8.2 B)."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class IntelDocument(BaseModel):
    """
    Standardized document schema across all 5 corpora branches.

    Document ID convention:
    - mitre: {technique_id} (e.g. mitre:T1110.003)
    - cve: {cve_id} (e.g. cve:CVE-2021-41773)
    - ioc: {ioc_type}:{value_normalized} (e.g. ioc:ip:192.0.2.1)
    - malware: {malware_id} (e.g. malware:S0154)
    - pattern: {slug} (e.g. pattern:brute_force)
    """

    doc_id: str = Field(description="Unique document ID with corpus prefix")
    corpus: IntelSource = Field(description="Target corpus branch")
    title: str = Field(description="Human readable title or name")
    text: str = Field(description="Primary descriptive text for semantic search")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Structured attributes")
    source_url: str | None = Field(default=None, description="External reference URL")
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of ingestion",
    )
    corpus_version: str = Field(default="v1", description="Corpus version tag")


class IntelMatch(BaseModel):
    """
    Search / retrieval result item returned to agents or pipeline.
    """

    doc_id: str = Field(description="Referenced document ID")
    corpus: IntelSource = Field(description="Originating corpus branch")
    title: str = Field(description="Title of matching document")
    snippet: str = Field(description="Short, relevant excerpt only")
    score: float = Field(ge=0.0, le=1.0, description="Normalized similarity or confidence score")
    match_type: MatchType = Field(description="EXACT, SEMANTIC, or LINKED")
    matched_on: str = Field(description="The indicator or query that produced the hit")
    linked_from: str | None = Field(default=None, description="Parent doc_id if expanded via link")
    source_url: str | None = Field(default=None, description="Provenance link")
    retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Lookup timestamp",
    )
    freshness_days: int | None = Field(default=None, description="Age in days since last seen")
    trust_weight: float = Field(default=1.0, ge=0.0, le=1.0, description="Source trust factor")


@runtime_checkable
class ThreatIntelRetriever(Protocol):
    """
    Protocol definition for Threat Intelligence RAG retrieval (Section 8.5).
    Decouples Threat Intel Agent from storage implementations.
    """

    def lookup_ioc(self, kind: str, value: str) -> list[IntelMatch]:
        """Exact lookup on normalized IOC value."""
        ...

    def lookup_cve(self, cve_id: str) -> IntelMatch | None:
        """Exact lookup by CVE ID."""
        ...

    def lookup_cve_by_software(self, product: str, version: str | None) -> list[IntelMatch]:
        """Lookup CVEs matching software name and optional version."""
        ...

    def lookup_technique(self, technique_id: str) -> IntelMatch | None:
        """Exact lookup by MITRE technique ID (e.g. T1110.003)."""
        ...

    def search(
        self,
        query: str,
        corpora: list[IntelSource] | None = None,
        k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[IntelMatch]:
        """Semantic search across one or more corpora."""
        ...

    def expand(self, doc_id: str, hops: int = 1) -> list[IntelMatch]:
        """Traverse relation links from a document ID."""
        ...

    def retrieve(
        self,
        entities: Entities,
        hints: list[str],
        claims: list[str] | None = None,
        k: int = 5,
    ) -> list[IntelMatch]:
        """
        Hybrid multi-stage retrieval:
        1. Exact lookup for entities (IPs, hashes, CVEs) and hints
        2. Semantic search over claims
        3. 1-hop link expansion
        4. Rerank and return top k per corpus
        """
        ...
