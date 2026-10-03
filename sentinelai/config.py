"""
sentinelai/config.py
────────────────────
Env-driven settings for the entire SentinelAI investigation tier.

All values come from environment variables (with safe defaults).
No secrets or model names are hardcoded here.

Usage::

    from sentinelai.config import settings
    print(settings.llm_provider)
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    GROQ = "groq"
    OLLAMA = "ollama"
    FAKE = "fake"


class TraceBackend(str, Enum):
    NONE = "none"
    LANGFUSE = "langfuse"
    LANGSMITH = "langsmith"


class Settings(BaseSettings):
    """
    Central configuration object.  Read from environment variables (and an
    optional .env file).  All fields have safe offline defaults so the system
    works without any configuration for development and testing.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── LLM provider ─────────────────────────────────────────────────────────
    # Default is "fake" so the full test suite runs offline with no secrets.
    # Set LLM_PROVIDER=groq + GROQ_API_KEY for real investigations.
    llm_provider: LLMProvider = LLMProvider.FAKE

    # ── Groq (used when LLM_PROVIDER=groq) ───────────────────────────────────
    groq_api_key: str = ""
    # Main reasoning model — agent analysis + Evidence Validator judge.
    # Do NOT hardcode; set via GROQ_MODEL env var.
    groq_model: str = ""
    # Fast / cheap model — Orchestrator optional steps.
    # Do NOT hardcode; set via GROQ_FAST_MODEL env var.
    groq_fast_model: str = ""

    # ── Groq rate-limit knobs ─────────────────────────────────────────────────
    # Tune these to your Groq account tier (free tier: 30 RPM, ~6k TPM).
    groq_rpm_limit: int = Field(default=30, ge=1)
    groq_tpm_limit: int = Field(default=6_000, ge=100)
    # Max parallel LLM calls from the fan-out (Auth/Timeline/Correlation).
    max_concurrent_llm_calls: int = Field(default=2, ge=1, le=20)

    # ── Ollama (used when LLM_PROVIDER=ollama) ────────────────────────────────
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    # ── Data stores ───────────────────────────────────────────────────────────
    log_store_path: str = ":memory:"
    rag_db_path: str = ":memory:"
    chroma_persist_dir: str = "data/chroma"

    # ── MITRE ─────────────────────────────────────────────────────────────────
    mitre_stix_path: str = "data/mitre/enterprise-attack.json"

    # ── Investigation limits ──────────────────────────────────────────────────
    max_validation_loops: int = Field(default=2, ge=1, le=10)
    max_tool_calls_per_agent: int = Field(default=8, ge=1, le=50)
    max_tokens_per_incident: int = Field(default=80_000, ge=1_000)

    # ── Confidence caps ───────────────────────────────────────────────────────
    single_event_confidence_cap: float = Field(default=0.6, ge=0.0, le=1.0)
    intel_only_confidence_cap: float = Field(default=0.65, ge=0.0, le=1.0)

    # ── Tracing ───────────────────────────────────────────────────────────────
    trace_backend: TraceBackend = TraceBackend.NONE
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"
    langchain_api_key: str = ""
    langchain_tracing_v2: bool = False

    # ── Live enrichment feature flags (all off by default) ────────────────────
    enable_abuseipdb: bool = False
    abuseipdb_api_key: str = ""
    enable_otx: bool = False
    otx_api_key: str = ""
    enable_nvd_live: bool = False
    nvd_api_key: str = ""

    # ── Report ────────────────────────────────────────────────────────────────
    enable_pdf: bool = False
    report_output_dir: str = "reports/"

    # ── RAG / embeddings ──────────────────────────────────────────────────────
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_fallback_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    sentence_transformers_home: Optional[str] = None

    # CVE ingestion scope
    cve_years_back: int = Field(default=3, ge=1, le=10)
    cve_min_cvss: float = Field(default=7.0, ge=0.0, le=10.0)

    # ── Helpers ───────────────────────────────────────────────────────────────
    @property
    def is_offline_mode(self) -> bool:
        """True when no live enrichment is enabled."""
        return not any([
            self.enable_abuseipdb,
            self.enable_otx,
            self.enable_nvd_live,
        ])


# Module-level singleton — import and use `settings` everywhere.
settings = Settings()
