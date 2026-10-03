"""
sentinelai/validator/judge.py
─────────────────────────────
Stage 2: LLM-as-judge with Pydantic-enforced evaluation (Section 7.6).

Evaluates findings that passed Stage 1 against strictly cited events,
and conducts a second pass for cross-finding contradictions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from sentinelai.llm.protocol import LLMClient, LLMMessage, StructuredOutputError
from sentinelai.schemas import ClaimVerdict, ValidatedFinding
from sentinelai.store.log_store import LogStore
from sentinelai.tools.registry import wrap_log_data_safely


class JudgeVerdictOutput(BaseModel):
    """Pydantic structured response returned by the LLM Judge for a single finding."""
    verdict: ClaimVerdict
    issues: list[str] = Field(default_factory=list)
    adjusted_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    reasoning: str = ""


class ContradictionCheckOutput(BaseModel):
    """Pydantic structured response for cross-finding contradiction analysis."""
    has_contradictions: bool = False
    conflicting_finding_indices: list[int] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def load_judge_prompt() -> str:
    """Load judge prompt template from sentinelai/prompts/judge_v1.md."""
    path = Path(__file__).parent.parent / "prompts" / "judge_v1.md"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "You are the Evidence Validator Judge. Evaluate claim against cited evidence."


def validate_stage2(
    stage1_results: list[ValidatedFinding],
    store: LogStore,
    llm_client: LLMClient,
) -> list[ValidatedFinding]:
    """
    Execute Stage 2 LLM-as-judge evaluation.

    - Only findings that passed Stage 1 (SUPPORTED or WEAK) are sent to the judge.
    - The judge sees ONLY the cited events (never raw full log dumps).
    - Checks for cross-finding contradictions and overconfident narratives.
    """
    judge_prompt = load_judge_prompt()
    validated_results: list[ValidatedFinding] = []

    # Optional: set agent context on FakeLLMClient if supported
    if hasattr(llm_client, "set_agent_context"):
        llm_client.set_agent_context("validator")

    for item in stage1_results:
        # If Stage 1 determined it was completely unsupported (e.g. fabricated IDs), do not call LLM
        if item.verdict == ClaimVerdict.UNSUPPORTED and item.adjusted_confidence == 0.0:
            validated_results.append(item)
            continue

        # Fetch ONLY the cited events from LogStore
        cited_events: list[dict[str, Any]] = []
        for eid in item.finding.evidence_event_ids:
            evt = store.get_event(eid)
            if evt is not None:
                cited_events.append(evt)

        # Wrap evidence in prompt injection safety tags
        safe_evidence = wrap_log_data_safely(cited_events)

        eval_query = (
            f"### Claim to Audit\n"
            f"Statement: {item.finding.claim}\n"
            f"Claimed Confidence: {item.adjusted_confidence:.2f}\n"
            f"Stated Reasoning: {item.finding.reasoning}\n"
            f"Named Entities: {item.finding.entities.model_dump()}\n\n"
            f"### Cited Evidence Events ({len(cited_events)} events)\n"
            f"{safe_evidence}\n\n"
            f"Return JSON adhering to the JudgeVerdictOutput schema."
        )

        messages = [
            LLMMessage(role="system", content=judge_prompt),
            LLMMessage(role="user", content=eval_query),
        ]

        try:
            decision: JudgeVerdictOutput = llm_client.chat_json(
                messages=messages,
                schema=JudgeVerdictOutput,
                temperature=0.0,
            )

            # Combine issues from Stage 1 and Stage 2
            combined_issues = list(item.issues) + [iss for iss in decision.issues if iss not in item.issues]

            validated_results.append(
                ValidatedFinding(
                    finding=item.finding,
                    verdict=decision.verdict,
                    issues=combined_issues,
                    adjusted_confidence=decision.adjusted_confidence,
                )
            )
        except Exception as err:
            # Fall back to Stage 1 result with a limitation note
            item.issues.append(f"Stage 2 LLM judge error: {err}")
            validated_results.append(item)

    # Second pass: Contradiction check
    if len(validated_results) >= 2:
        validated_results = _check_cross_finding_contradictions(validated_results)

    if hasattr(llm_client, "clear_agent_context"):
        llm_client.clear_agent_context()

    return validated_results


def _check_cross_finding_contradictions(
    findings: list[ValidatedFinding],
) -> list[ValidatedFinding]:
    """
    Check the set of validated findings for mutual contradictions.
    e.g. One finding claiming auth success while another claims complete failure for same user/ip.
    """
    claims_lower = [vf.finding.claim.lower() for vf in findings]

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            # Check for direct contradictions e.g. success vs failure on same entities
            c1, c2 = claims_lower[i], claims_lower[j]
            e1, e2 = findings[i].finding.entities, findings[j].finding.entities

            shared_users = set(e1.users) & set(e2.users)
            shared_ips = set(e1.ips) & set(e2.ips)

            if (shared_users or shared_ips):
                if ("successful login" in c1 and "no successful login" in c2) or \
                   ("benign" in c1 and "critical attack" in c2):
                    contradiction_note = (
                        f"Contradiction detected between finding {i} ('{findings[i].finding.claim[:40]}...') "
                        f"and finding {j} ('{findings[j].finding.claim[:40]}...')."
                    )
                    findings[i].issues.append(contradiction_note)
                    findings[j].issues.append(contradiction_note)
                    findings[i].verdict = ClaimVerdict.CONTRADICTED
                    findings[j].verdict = ClaimVerdict.CONTRADICTED
                    findings[i].adjusted_confidence = min(findings[i].adjusted_confidence, 0.40)
                    findings[j].adjusted_confidence = min(findings[j].adjusted_confidence, 0.40)

    return findings
