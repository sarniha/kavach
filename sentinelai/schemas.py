"""
sentinelai/schemas.py
─────────────────────
Stable Pydantic v2 contracts shared across every component of the
SentinelAI investigation tier.

These schemas are the integration boundary with teammates (RL engine,
dashboard, log-ingestion pipeline).  Treat them as stable: add fields
with defaults, never remove or rename without a migration plan.
"""
from __future__ import annotations

import operator
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    IGNORE = "ignore"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ClaimVerdict(str, Enum):
    SUPPORTED = "supported"
    WEAK = "weak"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"


# Alias for concise references
Verdict = ClaimVerdict


# ─────────────────────────────────────────────────────────────────────────────
# Core log + incident schemas (teammate interface)
# ─────────────────────────────────────────────────────────────────────────────

class NormalizedEvent(BaseModel):
    """
    A single normalized log event.  The ``event_id`` is the stable citation
    key: every finding, tool result, and timeline entry must reference it.

    The ``raw`` field contains the untrusted original log line and must
    never be forwarded to an LLM without a ``<log_data>`` wrapper.
    """

    event_id: str = Field(description="Unique, stable log line identifier")
    timestamp: datetime
    source: str = Field(
        description="Log source: syslog | wazuh | cloudwatch | splunk | json"
    )
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_type: str = Field(
        description=(
            "Normalised event category: auth_failure | auth_success | "
            "privilege_change | process_start | network_conn | ..."
        )
    )
    outcome: str | None = Field(
        default=None, description="success | failure | unknown"
    )
    raw: str = Field(description="Original log line — UNTRUSTED, do not pass to LLM raw")
    fields: dict[str, str] = Field(
        default_factory=dict,
        description="Additional parsed key-value pairs from the log",
    )


class RuleMatch(BaseModel):
    """Represents a pre-computed Sigma rule match from the detection tier."""

    rule_id: str
    title: str
    level: str = Field(description="Sigma severity: informational | low | medium | high | critical")
    matched_event_ids: list[str]


class IncidentInput(BaseModel):
    """
    Entry-point schema pushed from the RL engine into the investigation tier.
    ``selected_strategy`` is an optional RL override for which agents to run.
    """

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_level: RiskLevel
    created_at: datetime = Field(default_factory=datetime.utcnow)
    events: list[NormalizedEvent] = Field(min_length=1)
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    selected_strategy: dict[str, Any] | None = Field(
        default=None,
        description=(
            'RL-chosen strategy override, e.g. {"agents": ["auth", "correlation"]}. '
            "Honored when present and valid."
        ),
    )
    rl_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="RL engine metadata: policy version, anomaly scores, etc.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Investigation findings
# ─────────────────────────────────────────────────────────────────────────────

class Entities(BaseModel):
    """Named entities extracted from events and findings."""

    ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)

    def merge(self, other: "Entities") -> "Entities":
        """Return a new Entities that is the union of self and other."""
        return Entities(
            ips=list(dict.fromkeys(self.ips + other.ips)),
            users=list(dict.fromkeys(self.users + other.users)),
            hosts=list(dict.fromkeys(self.hosts + other.hosts)),
            domains=list(dict.fromkeys(self.domains + other.domains)),
            hashes=list(dict.fromkeys(self.hashes + other.hashes)),
            cves=list(dict.fromkeys(self.cves + other.cves)),
        )


class Finding(BaseModel):
    """
    A single, falsifiable claim produced by an investigation agent.

    Rules enforced here and in the Validator:
    - ``evidence_event_ids`` MUST be non-empty (min_length=1).
    - ``confidence`` is in [0, 1].
    - The ``agent`` field identifies who produced this finding.
    """

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent: str = Field(description="auth | timeline | correlation | threat_intel")
    claim: str = Field(description="One specific, falsifiable statement")
    evidence_event_ids: list[str] = Field(
        min_length=1,
        description="REQUIRED: at least one event ID that supports this claim",
    )
    entities: Entities = Field(default_factory=Entities)
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_hint: str | None = Field(
        default=None, description="e.g. T1110, T1078, T1110.003"
    )
    reasoning: str = Field(
        description="Short explanation of how the evidence supports the claim"
    )

    @field_validator("evidence_event_ids")
    @classmethod
    def no_empty_ids(cls, v: list[str]) -> list[str]:
        """Reject findings where any event ID is an empty string."""
        for eid in v:
            if not eid.strip():
                raise ValueError("evidence_event_ids must not contain blank strings")
        return v


class ValidatedFinding(BaseModel):
    """A finding that has been through the Evidence Validator."""

    model_config = ConfigDict(populate_by_name=True)

    finding: Finding
    verdict: ClaimVerdict
    adjusted_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="May be lower than the agent's claimed confidence",
    )
    issues: list[str] = Field(
        default_factory=list,
        description="Validation issues: missing evidence, contradictions, overclaiming",
    )

    @property
    def validated_confidence(self) -> float:
        """Alias for adjusted_confidence for API compatibility."""
        return self.adjusted_confidence

    @property
    def finding_id(self) -> str:
        return self.finding.finding_id

    @property
    def claim(self) -> str:
        return self.finding.claim

    @property
    def evidence_event_ids(self) -> list[str]:
        return self.finding.evidence_event_ids

    @property
    def agent(self) -> str:
        return self.finding.agent

    @property
    def confidence(self) -> float:
        return self.adjusted_confidence

    @property
    def reasoning(self) -> str:
        return self.finding.reasoning



class FollowUpRequest(BaseModel):
    """
    A concrete, tool-answerable question the Validator sends back to the
    Orchestrator when evidence is insufficient.

    Vague requests ("investigate more") are not allowed — the ``question``
    must be specific enough to be answered by a single tool call.
    """

    target_agent: str = Field(description="auth | timeline | correlation | threat_intel")
    question: str = Field(description="Specific, tool-answerable question")
    reason: str = Field(default="", description="Why this gap matters for the investigation")
    suggested_tools: list[str] = Field(
        default_factory=list,
        description="Optional tool names that could answer the question",
    )


class ValidationResult(BaseModel):
    """Output of the Evidence Validator node."""

    model_config = ConfigDict(populate_by_name=True)

    # Primary field name used internally; 'findings' accepted as alias for legacy compat
    validated: list[ValidatedFinding] = Field(
        default_factory=list,
        validation_alias=AliasChoices("validated", "findings"),
    )
    sufficient: bool = Field(
        description=(
            "False only when there is a concrete, tool-answerable gap. "
            "If True, or if the loop cap has been reached, proceed to Report."
        )
    )
    follow_ups: list[FollowUpRequest] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)

    @property
    def findings(self) -> list[ValidatedFinding]:
        return self.validated

    @findings.setter
    def findings(self, val: list[ValidatedFinding]) -> None:
        self.validated = val


# ─────────────────────────────────────────────────────────────────────────────
# Timeline
# ─────────────────────────────────────────────────────────────────────────────

class TimelineEntry(BaseModel):
    """One step in the reconstructed attack timeline."""

    timestamp: datetime
    description: str
    event_ids: list[str] = Field(min_length=1)
    mitre_tactic: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Final report
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationReport(BaseModel):
    """
    The final output of the investigation tier.  Contains only validated
    findings (SUPPORTED or WEAK); UNSUPPORTED/CONTRADICTED appear only in
    ``limitations``.
    """

    incident_id: str
    executive_summary: str
    root_cause: str
    mitre_mapping: list[dict[str, Any]] = Field(
        description="[{technique_id, name, supporting_finding_ids}, ...]"
    )
    timeline: list[TimelineEntry]
    findings: list[ValidatedFinding]
    recommendations: list[str]
    overall_confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(
        default_factory=list,
        description="Loop cap hit, thin evidence, token budget, unsupported findings, etc.",
    )
    trace_summary: dict[str, Any] = Field(
        description=(
            "agents_run, tool_calls_per_agent, loops_used, total_tokens, "
            "estimated_cost_usd, wall_clock_seconds, validator_verdicts, "
            "overall_confidence, analyst_verdict (added later)"
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# Analyst feedback + RL interface
# ─────────────────────────────────────────────────────────────────────────────

class AnalystFeedback(BaseModel):
    """Analyst verdict fed back to the RL engine as a reward signal."""

    incident_id: str
    verdict: str = Field(
        description="true_positive | false_positive | needs_more_work"
    )
    severity_correct: bool | None = None
    notes: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Archive decision (for IGNORE/LOW incidents — no LLM involved)
# ─────────────────────────────────────────────────────────────────────────────

class ArchiveDecision(BaseModel):
    """Returned immediately for IGNORE or LOW risk incidents."""

    incident_id: str
    risk_level: RiskLevel
    reason: str = "Risk level below investigation threshold — no LLM calls made."
    archived_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# LangGraph shared state helpers
# ─────────────────────────────────────────────────────────────────────────────

def _merge_findings(
    left: list[Finding], right: list[Finding]
) -> list[Finding]:
    """Reducer: merge parallel agent outputs without duplicate identical claims and evidence."""
    seen = {(f.claim.strip().lower(), ",".join(sorted(f.evidence_event_ids))) for f in left}
    result = list(left)
    for f in right:
        key = (f.claim.strip().lower(), ",".join(sorted(f.evidence_event_ids)))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _merge_limitations(left: list[str], right: list[str]) -> list[str]:
    """Reducer: append limitation notes from all nodes."""
    return left + right


def _merge_token_usage(
    left: dict[str, int], right: dict[str, int]
) -> dict[str, int]:
    """Reducer: sum token counts per agent key."""
    merged = dict(left)
    for k, v in right.items():
        merged[k] = merged.get(k, 0) + v
    return merged


def _merge_trace(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    """Reducer: merge trace dicts recursively for nested dicts and appending list values."""
    merged: dict[str, Any] = dict(left)
    for k, v in right.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _merge_trace(merged[k], v)
        elif k in merged and isinstance(merged[k], list) and isinstance(v, list):
            merged[k] = merged[k] + v
        else:
            merged[k] = v
    return merged


# Type aliases for annotated LangGraph state fields
FindingsList = Annotated[list[Finding], operator.add]
LimitationsList = Annotated[list[str], operator.add]

