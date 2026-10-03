"""
sentinelai/agents/base.py
─────────────────────────
Base investigation agent class (Section 7).

All SOC agents inherit from ``BaseInvestigationAgent``, which provides:
- Bounded tool-calling loop (MAX_TOOL_CALLS_PER_AGENT).
- Trace logging (every tool call, token count, latency).
- Versioned prompt loading from ``sentinelai/prompts/*.md``.
- Early validation and repair (drops findings with empty/invalid event IDs).
- Prompt-injection defense: wraps evidence in ``<log_data>``.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from sentinelai.agents.schemas import AgentAction, FindingDraft
from sentinelai.config import Settings, settings as global_settings
from sentinelai.llm.protocol import LLMClient, LLMMessage, StructuredOutputError
from sentinelai.schemas import Finding, IncidentInput
from sentinelai.tools.registry import ToolRegistry, wrap_log_data_safely


class BaseInvestigationAgent:
    """
    Abstract base class for all SentinelAI investigation agents.

    Subclasses define:
    - ``agent_name``: e.g. "auth", "timeline", "correlation", "threat_intel"
    - ``prompt_version``: e.g. "auth_v1"
    """

    agent_name: str = "base"
    prompt_version: str = "base_v1"

    def __init__(
        self,
        llm_client: LLMClient,
        registry: ToolRegistry,
        incident: IncidentInput,
        config: Settings | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.registry = registry
        self.incident = incident
        self.config = config or global_settings

        self.max_tool_calls: int = self.config.max_tool_calls_per_agent
        self.timeline_entries: list[TimelineEntry] = []

        # Trace metadata
        self.trace: dict[str, Any] = {
            "agent": self.agent_name,
            "prompt_version": self.prompt_version,
            "tool_calls": [],
            "iterations": 0,
            "token_usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "latency_ms": 0.0,
            "limitations": [],
            "dropped_findings": [],
        }

    # ── Prompt Loading ────────────────────────────────────────────────────────

    def load_prompt(self) -> str:
        """Load the versioned prompt from sentinelai/prompts/{prompt_version}.md."""
        base_dir = Path(__file__).parent.parent / "prompts"
        prompt_file = base_dir / f"{self.prompt_version}.md"
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        # Fallback to .j2 or base prompt
        j2_file = base_dir / f"{self.prompt_version}.j2"
        if j2_file.exists():
            return j2_file.read_text(encoding="utf-8")
        raise FileNotFoundError(f"Prompt template {prompt_file} not found.")

    # ── Investigation Loop ────────────────────────────────────────────────────

    def run(self, follow_up_question: str | None = None) -> list[Finding]:
        """
        Execute the bounded investigation loop and return validated findings.

        Parameters
        ----------
        follow_up_question:
            Optional targeted inquiry from the Evidence Validator.
        """
        start_time = time.monotonic()
        prompt_instructions = self.load_prompt()

        # Tools description for system prompt
        tools_summary = "\n".join(
            f"- {t.name}: {t.description}" for t in self.registry.list_tools()
        )

        system_prompt = (
            f"{prompt_instructions}\n\n"
            f"### Available Investigation Tools\n"
            f"{tools_summary}\n\n"
            f"### Response Instructions\n"
            f"Respond with JSON matching the AgentAction schema.\n"
            f"If more information is needed, specify tool_calls.\n"
            f"If investigation is complete or sufficient evidence is gathered, "
            f"set is_complete=True and provide findings."
        )

        incident_overview = {
            "incident_id": self.incident.incident_id,
            "risk_level": self.incident.risk_level.value,
            "created_at": self.incident.created_at.isoformat(),
            "rule_matches": [rm.model_dump() for rm in self.incident.rule_matches],
            "rl_metadata": self.incident.rl_metadata,
        }

        observations: list[str] = []
        if follow_up_question:
            observations.append(
                f"[VALIDATOR FOLLOW-UP INQUIRY]: {follow_up_question}"
            )

        raw_drafts: list[FindingDraft] = []
        tool_call_count = 0

        # Optional: set agent context on FakeLLMClient if supported
        if hasattr(self.llm_client, "set_agent_context"):
            self.llm_client.set_agent_context(self.agent_name)

        while tool_call_count < self.max_tool_calls:
            self.trace["iterations"] += 1

            obs_text = "\n\n".join(observations) if observations else "No tool observations yet."
            user_content = (
                f"### Incident Overview\n"
                f"{json.dumps(incident_overview, indent=2)}\n\n"
                f"### Current Evidence Observations\n"
                f"{obs_text}\n\n"
                f"Decide your next action (tool_calls or complete findings)."
            )

            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=user_content),
            ]

            try:
                action: AgentAction = self.llm_client.chat_json(
                    messages=messages,
                    schema=AgentAction,
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

            if action.findings:
                raw_drafts.extend(action.findings)

            if action.timeline_entries:
                store = self.registry.store
                for te in action.timeline_entries:
                    valid_eids = [eid for eid in te.event_ids if store is None or store.event_exists(eid)]
                    if valid_eids:
                        te.event_ids = valid_eids
                        self.timeline_entries.append(te)

            if action.is_complete:
                break

            if not action.tool_calls:
                # No more tools requested and no findings
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
                try:
                    if not self.registry.has(tc.tool_name):
                        tool_err = f"Tool {tc.tool_name!r} not found in registry."
                        observations.append(f"[TOOL ERROR {tc.tool_name}]: {tool_err}")
                        continue

                    result = self.registry.execute(tc.tool_name, **tc.tool_args)
                    latency = (time.monotonic() - t0) * 1000

                    # Extract cited event IDs from result if available
                    eids = getattr(result, "event_ids", [])

                    self.trace["tool_calls"].append({
                        "tool_name": tc.tool_name,
                        "arguments": tc.tool_args,
                        "reasoning": tc.reasoning,
                        "latency_ms": round(latency, 2),
                        "event_ids": eids,
                        "truncated": getattr(result, "truncated", False),
                    })

                    # Wrap log content safely in <log_data>
                    safe_log = wrap_log_data_safely(result)
                    observations.append(
                        f"[TOOL RESULT for {tc.tool_name}]:\n{safe_log}"
                    )
                except Exception as ex:
                    observations.append(f"[TOOL EXECUTION ERROR {tc.tool_name}]: {ex}")

        if tool_call_count >= self.max_tool_calls:
            reach_msg = f"Reached MAX_TOOL_CALLS_PER_AGENT ({self.max_tool_calls})."
            if reach_msg not in self.trace["limitations"]:
                self.trace["limitations"].append(reach_msg)

        # If loop finished without findings, attempt one synthesis pass if we have observations
        if not raw_drafts and observations:
            synthesis_prompt = (
                f"{system_prompt}\n\n"
                f"You have finished tool execution. Provide your final findings based on "
                f"the observations gathered. Set is_complete=True."
            )
            synth_messages = [
                LLMMessage(role="system", content=synthesis_prompt),
                LLMMessage(role="user", content="\n\n".join(observations)),
            ]
            try:
                final_action: AgentAction = self.llm_client.chat_json(
                    messages=synth_messages,
                    schema=AgentAction,
                    temperature=0.0,
                )
                if final_action.findings:
                    raw_drafts.extend(final_action.findings)
            except Exception as synth_err:
                self.trace["limitations"].append(f"Final synthesis failed: {synth_err}")

        # Clean up agent context if needed
        if hasattr(self.llm_client, "clear_agent_context"):
            self.llm_client.clear_agent_context()

        self.trace["latency_ms"] = round((time.monotonic() - start_time) * 1000, 2)

        # Early validation and repair
        return self._validate_and_repair_findings(raw_drafts)

    # ── Validation & Repair ───────────────────────────────────────────────────

    def _validate_and_repair_findings(self, drafts: list[FindingDraft]) -> list[Finding]:
        """
        Validate, normalize, and filter findings before returning.
        
        Section 7 requirement:
        'drops or repairs any finding with empty or non-existent evidence_event_ids
        before returning (the validator also checks this, but fail early).'
        """
        validated: list[Finding] = []
        store = self.registry.store

        for draft in drafts:
            # 1. Clean event IDs: drop blanks
            candidate_eids = [eid.strip() for eid in draft.evidence_event_ids if eid and eid.strip()]

            # 2. Check store existence if store is available
            verified_eids: list[str] = []
            if store is not None:
                for eid in candidate_eids:
                    if store.event_exists(eid):
                        verified_eids.append(eid)
            else:
                verified_eids = candidate_eids

            # 3. Drop finding if no valid event IDs exist
            if not verified_eids:
                drop_msg = (
                    f"Dropped finding with claim '{draft.claim[:50]}...': "
                    f"No existing evidence event IDs found in LogStore."
                )
                self.trace["dropped_findings"].append(draft.claim)
                self.trace["limitations"].append(drop_msg)
                continue

            # 4. Repair finding with verified event IDs
            draft.evidence_event_ids = verified_eids

            # 5. Enforce single-event confidence cap
            if len(verified_eids) == 1:
                draft.confidence = min(
                    draft.confidence,
                    self.config.single_event_confidence_cap,
                )

            # 6. Ensure confidence is bounded [0.0, 1.0]
            draft.confidence = max(0.0, min(1.0, draft.confidence))

            finding = draft.to_finding(self.agent_name)
            validated.append(finding)

        return validated
