"""
sentinelai/validator/validator.py
─────────────────────────────────
EvidenceValidator orchestrating Stage 1 and Stage 2 checks (Section 7.6).

Emits ValidationResult with concrete FollowUpRequests when tool-answerable
evidence gaps remain.
"""
from __future__ import annotations

from sentinelai.config import Settings, settings as global_settings
from sentinelai.llm.protocol import LLMClient
from sentinelai.schemas import (
    ClaimVerdict,
    Finding,
    FollowUpRequest,
    IncidentInput,
    ValidatedFinding,
    ValidationResult,
)
from sentinelai.store.log_store import LogStore
from sentinelai.validator.judge import validate_stage2
from sentinelai.validator.rules import validate_stage1


class EvidenceValidator:
    """
    Two-stage Evidence Validator fact-checking tier.

    Stage 1: Deterministic rule verification (citations, store existence, entity presence, math).
    Stage 2: LLM-as-judge audit of claims against cited log evidence.
    """

    def __init__(
        self,
        store: LogStore,
        llm_client: LLMClient,
        config: Settings | None = None,
    ) -> None:
        self.store = store
        self.llm_client = llm_client
        self.config = config or global_settings

    def validate(
        self,
        findings: list[Finding],
        incident: IncidentInput,
    ) -> ValidationResult:
        """
        Execute two-stage validation pipeline on findings.

        Returns ValidationResult with findings verdicts, sufficiency determination,
        and concrete follow-up requests if gaps exist.
        """
        if not findings:
            # Thin or empty evidence scenario
            follow_ups: list[FollowUpRequest] = []
            if len(incident.events) == 1:
                # Thin evidence case: trigger targeted follow-up to search for wider events
                single_evt = incident.events[0]
                target_user = single_evt.user or "the target account"
                target_ip = single_evt.src_ip or "the source IP"
                follow_ups.append(
                    FollowUpRequest(
                        target_agent="auth",
                        question=(
                            f"Check for additional authentication events, failures, or unusual timing "
                            f"for user '{target_user}' or source IP '{target_ip}' across an expanded window."
                        ),
                        suggested_tools=["count_failed_logins", "query_events", "ip_activity_summary"],
                    )
                )

            return ValidationResult(
                validated=[],
                sufficient=len(follow_ups) == 0,
                follow_ups=follow_ups,
                overall_confidence=0.30 if follow_ups else 0.50,
                limitations=["No findings were produced by investigation agents."],
            )

        # 1. Stage 1: Deterministic rules
        stage1_findings = validate_stage1(findings, self.store, self.config)

        # 2. Stage 2: LLM-as-judge
        validated_findings = validate_stage2(stage1_findings, self.store, self.llm_client)

        # 3. Check sufficiency & generate concrete follow-up requests
        follow_ups: list[FollowUpRequest] = []
        limitations: list[str] = []

        supported_findings = [
            vf for vf in validated_findings if vf.verdict == ClaimVerdict.SUPPORTED
        ]
        weak_findings = [
            vf for vf in validated_findings if vf.verdict == ClaimVerdict.WEAK
        ]
        unsupported_findings = [
            vf for vf in validated_findings
            if vf.verdict in (ClaimVerdict.UNSUPPORTED, ClaimVerdict.CONTRADICTED)
        ]

        for uf in unsupported_findings:
            limitations.append(
                f"Finding rejected ({uf.verdict.value}): {uf.finding.claim} - Issues: {'; '.join(uf.issues)}"
            )

        # If all findings are rejected (unsupported or contradicted), request follow-up
        if not supported_findings and not weak_findings:
            target_user = "target account"
            target_ip = "source IP"
            for f in findings:
                if f.entities and f.entities.users:
                    target_user = f.entities.users[0]
                    break
            for f in findings:
                if f.entities and f.entities.ips:
                    target_ip = f.entities.ips[0]
                    break
            follow_ups.append(
                FollowUpRequest(
                    target_agent="auth",
                    question=(
                        f"All initial findings were unsupported or lacked valid citations. "
                        f"Perform targeted queries for genuine authentication events, failures, or unusual activity "
                        f"concerning user '{target_user}' or source IP '{target_ip}'."
                    ),
                    suggested_tools=["count_failed_logins", "query_events", "ip_activity_summary"],
                )
            )
        # If thin evidence scenario (e.g. only 1 event in total incident and finding is weak/single-event)
        elif len(self.store.all_event_ids()) <= 2 and (not supported_findings or any(vf.adjusted_confidence <= 0.60 for vf in validated_findings)):
            # Target auth or timeline agent with concrete queries
            first_f = validated_findings[0].finding
            user_target = first_f.entities.users[0] if first_f.entities.users else "target account"
            ip_target = first_f.entities.ips[0] if first_f.entities.ips else "source IP"

            follow_ups.append(
                FollowUpRequest(
                    target_agent="auth",
                    question=(
                        f"Search for additional failed or successful logins, unusual login times, or related IPs "
                        f"touching user '{user_target}' or IP '{ip_target}'."
                    ),
                    suggested_tools=["query_events", "ip_activity_summary", "count_failed_logins"],
                )
            )

        # Compute overall confidence
        if supported_findings:
            conf_scores = [vf.adjusted_confidence for vf in supported_findings]
            overall_confidence = sum(conf_scores) / len(conf_scores)
        elif weak_findings:
            conf_scores = [vf.adjusted_confidence for vf in weak_findings]
            overall_confidence = sum(conf_scores) / len(conf_scores)
        else:
            overall_confidence = 0.20

        is_sufficient = len(follow_ups) == 0 and bool(supported_findings or weak_findings)

        return ValidationResult(
            validated=validated_findings,
            sufficient=is_sufficient,
            follow_ups=follow_ups,
            overall_confidence=round(overall_confidence, 2),
            limitations=limitations,
        )
