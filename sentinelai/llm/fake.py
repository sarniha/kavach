"""
sentinelai/llm/fake.py
──────────────────────
FakeLLMClient — deterministic, scripted LLM responses for offline tests.

Design
------
The client holds a queue of scripted responses per ``(agent_name, call_index)``
key.  When a call is made it pops the next response for that key, or falls back
to a configurable default.  This gives tests precise control over every LLM
call without any network traffic.

Usage in tests::

    from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse

    client = FakeLLMClient(default_content='{"verdict": "supported"}')
    client.register("auth", 0, ScriptedResponse(content='{"findings": []}'))

    response = client.chat([LLMMessage(role="user", content="analyse this")])
    assert response.content == '{"findings": []}'
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Type, TypeVar

from pydantic import BaseModel

from sentinelai.llm.protocol import LLMMessage, LLMResponse, StructuredOutputError

T = TypeVar("T", bound=BaseModel)

# Sentinel value stored in the flat queue to simulate malformed output
_MALFORMED = "__MALFORMED_JSON__"


@dataclass
class ScriptedResponse:
    """A pre-canned response to be returned by FakeLLMClient."""

    content: str
    input_tokens: int = 10
    output_tokens: int = 20


class FakeLLMClient:
    """
    Deterministic LLM client for tests.

    All calls are recorded in ``call_log`` for assertion in tests.
    """

    def __init__(
        self,
        default_content: str = '{"status": "ok"}',
        default_input_tokens: int = 10,
        default_output_tokens: int = 20,
    ) -> None:
        self._default = ScriptedResponse(
            content=default_content,
            input_tokens=default_input_tokens,
            output_tokens=default_output_tokens,
        )
        # key: (agent_name, call_index) or just a plain string label
        self._queues: dict[str, deque[ScriptedResponse]] = defaultdict(deque)
        # Flat call queue (used when no key is specified)
        self._flat_queue: deque[ScriptedResponse] = deque()
        self.call_log: list[dict[str, Any]] = []
        self._call_count = 0

    # ── Registration helpers ──────────────────────────────────────────────────

    def register(self, key: str, response: ScriptedResponse) -> None:
        """Register a scripted response for a given key."""
        self._queues[key].append(response)

    def enqueue(self, response: ScriptedResponse) -> None:
        """Enqueue a response to the flat (keyless) queue."""
        self._flat_queue.append(response)

    def queue_response(self, content: str) -> None:
        """Enqueue a response string to the flat (keyless) queue."""
        self.enqueue(ScriptedResponse(content=content))

    def enqueue_many(self, responses: list[ScriptedResponse]) -> None:
        """Enqueue multiple responses to the flat queue."""
        for r in responses:
            self._flat_queue.append(r)

    # ── LLMClient interface ───────────────────────────────────────────────────

    def chat(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: dict[str, Any] | None = None,
        use_fast_model: bool = False,
        key: str | None = None,
    ) -> LLMResponse:
        """
        Return the next scripted response.

        Resolution order:
        1. Keyed queue (``key`` argument or the ``_agent_context`` attribute)
        2. Flat queue
        3. Default content
        """
        self._call_count += 1

        scripted: ScriptedResponse | None = None

        # Try keyed queue
        lookup_key = key or getattr(self, "_agent_context", None)
        if lookup_key and self._queues[lookup_key]:
            scripted = self._queues[lookup_key].popleft()

        # Fall back to flat queue
        if scripted is None and self._flat_queue:
            scripted = self._flat_queue.popleft()

        # Fall back to default
        if scripted is None:
            scripted = self._default

        response = LLMResponse(
            content=scripted.content,
            input_tokens=scripted.input_tokens,
            output_tokens=scripted.output_tokens,
            model="fake-llm",
        )

        self.call_log.append(
            {
                "call_index": self._call_count,
                "key": lookup_key,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "response_content": scripted.content,
                "tokens": scripted.input_tokens + scripted.output_tokens,
            }
        )
        return response

    @property
    def model_name(self) -> str:
        return "fake-llm"

    # ── Context manager for agent-scoped calls ────────────────────────────────

    def set_agent_context(self, agent_name: str) -> None:
        """
        Set the active agent context so subsequent calls automatically use
        the keyed queue for ``agent_name``.
        """
        self._agent_context: str = agent_name

    def clear_agent_context(self) -> None:
        """Clear the agent context."""
        if hasattr(self, "_agent_context"):
            del self._agent_context

    # ── Convenience: register JSON responses ─────────────────────────────────

    def register_json(self, key: str, obj: Any) -> None:
        """Register a JSON-serialisable object as a scripted response."""
        self.register(key, ScriptedResponse(content=json.dumps(obj)))

    def enqueue_json(self, obj: Any) -> None:
        """Enqueue a JSON-serialisable object to the flat queue."""
        self.enqueue(ScriptedResponse(content=json.dumps(obj)))

    def enqueue_malformed(self) -> None:
        """Enqueue a deliberately malformed JSON response (for error-path tests)."""
        self.enqueue(ScriptedResponse(content=_MALFORMED))

    # ── chat_json (mirrors GroqClient, but using the scripted queue) ─────────────────

    def chat_json(
        self,
        messages: list[LLMMessage],
        schema: Type[T],
        *,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        use_fast_model: bool = False,
    ) -> T:
        """
        Fake implementation of ``chat_json``.

        * If the next scripted response is valid JSON for ``schema``, return
          the validated model.
        * If it is ``_MALFORMED``, simulate the retry logic:
          - consume a second response from the queue,
          - if that is also malformed, raise ``StructuredOutputError``.
        """
        response = self.chat(messages, temperature=temperature, max_tokens=max_tokens,
                             use_fast_model=use_fast_model)

        try:
            data = json.loads(response.content)
            return schema.model_validate(data)
        except (json.JSONDecodeError, Exception) as first_err:
            # Simulate one retry
            retry_response = self.chat(
                messages + [LLMMessage(role="assistant", content=response.content),
                            LLMMessage(role="user", content=f"Fix: {first_err}")],
                temperature=0.0, max_tokens=max_tokens, use_fast_model=use_fast_model,
            )
            try:
                data = json.loads(retry_response.content)
                return schema.model_validate(data)
            except (json.JSONDecodeError, Exception) as second_err:
                raise StructuredOutputError(
                    f"Could not produce valid {schema.__name__} after 2 attempts: {second_err}",
                    raw_content=retry_response.content,
                ) from second_err

    # ── Inspection ────────────────────────────────────────────────────────────

    @property
    def total_calls(self) -> int:
        """Total number of ``chat`` calls made so far."""
        return self._call_count

    def reset(self) -> None:
        """Reset all queues and call logs (useful between test cases)."""
        self._queues.clear()
        self._flat_queue.clear()
        self.call_log.clear()
        self._call_count = 0
        self.clear_agent_context()
