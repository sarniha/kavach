"""
sentinelai/agents/threat_intel.py
──────────────────────────────────
Phase 6d: Threat Intelligence Agent (Section 7.5 + Section 8.6).

Receives indicators and technique hints from the merged orchestrator findings,
calls the ThreatIntelRetriever via bounded tool wrappers, and produces
evidence-cited threat findings with correct confidence capping.

Key rules (Section 8.6):
- Only queries indicators that came from merged findings.
- Every finding must cite evidence_event_ids (log events with the indicator).
- Intel is context, not proof – confidence caps are strictly enforced.
- Reports "no intel found" explicitly when nothing matches.
- Intel text wrapped in <intel_data> delimiters before LLM sees it.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sentinelai.agents.schemas import FindingDraft
from sentinelai.config import Settings, settings as global_settings
from sentinelai.llm.protocol import LLMClient, LLMMessage, StructuredOutputError
from sentinelai.schemas import Entities, Finding, IncidentInput
from sentinelai.threat_intel.retriever import HybridThreatIntelRetriever, MockThreatIntelRetriever
from sentinelai.threat_intel.schemas import IntelMatch, IntelSource, ThreatIntelRetriever

# ─────────────────────────────────────────────────────────────────────────────
# Confidence caps (Section 8.6 + prompt rules)
# ─────────────────────────────────────────────────────────────────────────────

IOC_ONLY_CAP: float = 0.60          # IOC reputation hit alone
CVE_UNCONFIRMED_CAP: float = 0.50   # CVE without software evidence in logs
MITRE_WITH_EVIDENCE_CAP: float = 0.85
COMBINED_MATCH_CAP: float = 0.90
INTEL_ONLY_ABSOLUTE_MAX: float = 0.65  # Hard ceiling if no corroborating log evidence


# ─────────────────────────────────────────────────────────────────────────────
# Tool call schema
# ─────────────────────────────────────────────────────────────────────────────


class IntelToolCall(BaseModel):
    tool_name: str = Field(description="Intel tool to call")
    tool_args: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = Field(default="", description="Why this lookup is needed")


class ThreatIntelFindingDraft(BaseModel):
    """Draft finding produced by the Threat Intel Agent."""

    claim: str = Field(description="Specific, falsifiable threat intelligence claim")
    evidence_event_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs from the log that contain the indicator or behavior",
    )
    intel_doc_ids: list[str] = Field(
        default_factory=list,
        description="Intel doc_ids that informed this finding (e.g. ioc:ip:..., mitre:T1110)",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    match_type: str = Field(
        default="exact",
        description="exact | semantic | linked | combined",
    )
    mitre_hint: str | None = Field(default=None)
    reasoning: str = Field(default="", description="Explanation linking evidence to intel")


class ThreatIntelAction(BaseModel):
    """Structured LLM response for a Threat Intel Agent iteration."""

    tool_calls: list[IntelToolCall] = Field(default_factory=list)
    intel_findings: list[ThreatIntelFindingDraft] = Field(default_factory=list)
    no_intel_found: list[str] = Field(
        default_factory=list,
        description="Indicators for which no intel was found (explicit reporting)",
    )
    is_complete: bool = Field(default=False)


# ─────────────────────────────────────────────────────────────────────────────
# ThreatIntelAgent
# ─────────────────────────────────────────────────────────────────────────────


class ThreatIntelAgent:
    """
    Threat Intelligence Agent (Section 7.5).

    Standalone agent – does NOT inherit BaseInvestigationAgent because it:
    - Uses ThreatIntelRetriever (not the standard ToolRegistry)
    - Has different structured output schemas
    - Has its own confidence-cap logic

    Signature is compatible with the orchestrator's expectations:
    ``run()`` returns ``list[Finding]``.
    """

    agent_name: str = "threat_intel"
    prompt_version: str = "threat_intel_v1"

    def __init__(
        self,
        llm_client: LLMClient,
        retriever: ThreatIntelRetriever,
        incident: IncidentInput,
        config: Settings | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.retriever = retriever
        self.incident = incident
        self.config = config or global_settings

        self.max_tool_calls: int = self.config.max_tool_calls_per_agent
        self.trace: dict[str, Any] = {
            "agent": self.agent_name,
            "prompt_version": self.prompt_version,
            "tool_calls": [],
            "iterations": 0,
            "token_usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "latency_ms": 0.0,
            "limitations": [],
            "dropped_findings": [],
            "no_intel_found": [],
        }

    # ── Prompt loading ────────────────────────────────────────────────────────

    def _load_prompt(self) -> str:
        base_dir = Path(__file__).parent.parent / "prompts"
        prompt_file = base_dir / f"{self.prompt_version}.md"
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        raise FileNotFoundError(f"Prompt not found: {prompt_file}")

    # ── Intel tool dispatch ───────────────────────────────────────────────────

    def _execute_tool(self, tc: IntelToolCall) -> str:
        """Execute an intel tool call and return a formatted, safe string result."""
        tool_name = tc.tool_name.strip()
        args = tc.tool_args
        result_matches: list[IntelMatch] = []

        try:
            if tool_name == "lookup_ioc":
                result_matches = self.retriever.lookup_ioc(
                    kind=args.get("kind", ""),
                    value=args.get("value", ""),
                )
            elif tool_name == "lookup_technique":
                m = self.retriever.lookup_technique(args.get("technique_id", ""))
                result_matches = [m] if m else []
            elif tool_name == "lookup_cve":
                m = self.retriever.lookup_cve(args.get("cve_id", ""))
                result_matches = [m] if m else []
            elif tool_name == "lookup_cve_by_software":
                result_matches = self.retriever.lookup_cve_by_software(
                    product=args.get("product", ""),
                    version=args.get("version"),
                )
            elif tool_name == "search_patterns":
                result_matches = self.retriever.search(
                    query=args.get("query", ""),
                    corpora=[IntelSource.PATTERN],
                    k=3,
                )
            elif tool_name == "search_malware":
                result_matches = self.retriever.search(
                    query=args.get("query", ""),
                    corpora=[IntelSource.MALWARE],
                    k=3,
                )
            elif tool_name == "expand_links":
                result_matches = self.retriever.expand(
                    doc_id=args.get("doc_id", ""),
                    hops=args.get("hops", 1),
                )
            else:
                return f"[UNKNOWN TOOL: {tool_name}]"
        except Exception as ex:
            return f"[TOOL ERROR for {tool_name}]: {ex}"

        if not result_matches:
            return f"<intel_data>[No results found for {tool_name}({args})]</intel_data>"

        # Format matches safely inside <intel_data> delimiters (Section 8.8)
        snippets = []
        for m in result_matches[:5]:  # Cap at 5 matches
            # Truncate snippet to 300 chars (Section 8.8 safety)
            safe_snippet = m.snippet[:300] if m.snippet else ""
            snippets.append(
                f"  - doc_id: {m.doc_id}\n"
                f"    title: {m.title}\n"
                f"    score: {m.score:.3f}\n"
                f"    match_type: {m.match_type.value}\n"
                f"    snippet: {safe_snippet}\n"
                f"    trust_weight: {m.trust_weight}"
            )

        return (
            f"<intel_data>\n"
            f"Tool: {tool_name} | Args: {json.dumps(args)}\n"
            f"Results ({len(result_matches)} match(es), showing up to 5):\n"
            + "\n".join(snippets)
            + "\n</intel_data>"
        )

    # ── Confidence enforcement ────────────────────────────────────────────────

    def _enforce_confidence_cap(self, draft: ThreatIntelFindingDraft) -> ThreatIntelFindingDraft:
        """
        Apply strict confidence caps per Section 8.6 rules.
        """
        match_type = draft.match_type.lower()
        intel_doc_ids = [d.lower() for d in draft.intel_doc_ids]

        has_ioc = any(d.startswith("ioc:") for d in intel_doc_ids)
        has_technique = any(d.startswith("mitre:") for d in intel_doc_ids)
        has_malware = any(d.startswith("malware:") for d in intel_doc_ids)
        has_cve = any(d.startswith("cve:") for d in intel_doc_ids)
        has_pattern = any(d.startswith("pattern:") for d in intel_doc_ids)

        is_combined = sum([has_ioc, has_technique, has_malware, has_cve, has_pattern]) >= 2

        # Apply caps in descending order of permissiveness
        if is_combined:
            cap = COMBINED_MATCH_CAP
        elif has_technique and not has_ioc:
            cap = MITRE_WITH_EVIDENCE_CAP
        elif has_cve:
            # CVE without corroborating log evidence
            if "unconfirmed" in draft.reasoning.lower() or "possible" in draft.reasoning.lower():
                cap = CVE_UNCONFIRMED_CAP
            else:
                cap = IOC_ONLY_CAP  # Conservative default
        elif has_ioc:
            cap = IOC_ONLY_CAP
        else:
            cap = INTEL_ONLY_ABSOLUTE_MAX

        original = draft.confidence
        draft.confidence = round(min(draft.confidence, cap), 3)
        if draft.confidence < original:
            note = f" [confidence capped from {original:.2f} to {draft.confidence:.2f} per intel-only policy]"
            draft.reasoning = draft.reasoning + note

        return draft

    # ── Main run loop ─────────────────────────────────────────────────────────

    def run(
        self,
        entities: Entities | None = None,
        hints: list[str] | None = None,
        claims: list[str] | None = None,
        follow_up_question: str | None = None,
    ) -> list[Finding]:
        """
        Execute bounded Threat Intel investigation and return validated findings.

        Parameters
        ----------
        entities: Entities extracted from merged investigation findings
        hints: MITRE T-ID hints from findings' mitre_hint fields
        claims: Agent claims as strings for semantic search context
        follow_up_question: Optional targeted inquiry from the Evidence Validator
        """
        start_time = time.monotonic()
        prompt_instructions = self._load_prompt()

        entities = entities or Entities()
        hints = hints or []
        claims = claims or []

        # Build system prompt
        system_prompt = (
            f"{prompt_instructions}\n\n"
            f"### Indicators to Investigate\n"
            f"IPs: {entities.ips}\n"
            f"Domains: {entities.domains}\n"
            f"Hashes: {entities.hashes}\n"
            f"CVE IDs: {entities.cves}\n"
            f"MITRE Hints: {hints}\n\n"
            f"### Agent Claims (for semantic search)\n"
            + "\n".join(f"- {c}" for c in claims[:10])  # Limit claims
        )

        if follow_up_question:
            system_prompt += f"\n\n### Validator Follow-Up\n{follow_up_question}"

        # Optional: set agent context on FakeLLMClient if supported
        if hasattr(self.llm_client, "set_agent_context"):
            self.llm_client.set_agent_context(self.agent_name)

        observations: list[str] = []
        raw_drafts: list[ThreatIntelFindingDraft] = []
        no_intel_found: list[str] = []
        tool_call_count = 0

        while tool_call_count < self.max_tool_calls:
            self.trace["iterations"] += 1

            obs_text = "\n\n".join(observations) if observations else "No intel lookups performed yet."
            user_content = (
                f"### Intel Observations So Far\n"
                f"{obs_text}\n\n"
                f"Issue tool calls to gather intel, or provide final intel_findings "
                f"if all indicators have been queried. Set is_complete=True when done."
            )

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_content),
            ]

            try:
                action: ThreatIntelAction = self.llm_client.chat_json(
                    messages=messages,
                    schema=ThreatIntelAction,
                    temperature=0.0,
                )
            except StructuredOutputError as err:
                self.trace["limitations"].append(
                    f"LLM structured output error at iteration {self.trace['iterations']}: {err}"
                )
                break
            except Exception as exc:
                self.trace["limitations"].append(
                    f"LLM call failed at iteration {self.trace['iterations']}: {exc}"
                )
                break

            if action.intel_findings:
                raw_drafts.extend(action.intel_findings)

            if action.no_intel_found:
                no_intel_found.extend(action.no_intel_found)

            if action.is_complete:
                break

            if not action.tool_calls:
                break

            # Execute tool calls
            for tc in action.tool_calls:
                if tool_call_count >= self.max_tool_calls:
                    self.trace["limitations"].append(
                        f"Reached MAX_TOOL_CALLS_PER_AGENT ({self.max_tool_calls})."
                    )
                    break

                tool_call_count += 1
                t0 = time.monotonic()
                result_text = self._execute_tool(tc)
                latency = (time.monotonic() - t0) * 1000

                self.trace["tool_calls"].append({
                    "tool_name": tc.tool_name,
                    "arguments": tc.tool_args,
                    "reasoning": tc.reasoning,
                    "latency_ms": round(latency, 2),
                })
                observations.append(f"[INTEL RESULT for {tc.tool_name}]:\n{result_text}")

        if hasattr(self.llm_client, "clear_agent_context"):
            self.llm_client.clear_agent_context()

        self.trace["latency_ms"] = round((time.monotonic() - start_time) * 1000, 2)
        self.trace["no_intel_found"] = no_intel_found

        # Convert drafts to validated Finding objects
        return self._validate_drafts(raw_drafts)

    # ── Finding validation ─────────────────────────────────────────────────────

    def _validate_drafts(self, drafts: list[ThreatIntelFindingDraft]) -> list[Finding]:
        """Validate, cap confidence, and convert to Finding objects."""
        findings: list[Finding] = []

        for i, draft in enumerate(drafts):
            # 1. Must have evidence event IDs
            clean_eids = [eid.strip() for eid in draft.evidence_event_ids if eid.strip()]
            if not clean_eids:
                self.trace["dropped_findings"].append(draft.claim)
                self.trace["limitations"].append(
                    f"Dropped intel finding '{draft.claim[:60]}': no evidence_event_ids"
                )
                continue

            # 2. Apply confidence caps
            draft = self._enforce_confidence_cap(draft)

            # 3. Single-event cap
            if len(clean_eids) == 1:
                draft.confidence = min(
                    draft.confidence,
                    self.config.single_event_confidence_cap,
                )

            # 4. Create Finding
            finding = Finding(
                finding_id=f"ti-{self.incident.incident_id}-{i:03d}",
                agent=self.agent_name,
                claim=draft.claim,
                evidence_event_ids=clean_eids,
                entities=Entities(),  # TI findings don't extract new entities
                confidence=max(0.0, min(1.0, draft.confidence)),
                mitre_hint=draft.mitre_hint,
                reasoning=(
                    f"{draft.reasoning} "
                    f"| Intel docs: {', '.join(draft.intel_doc_ids[:5])}"
                ).strip(),
            )
            findings.append(finding)

        return findings
