"""
sentinelai/llm/protocol.py
──────────────────────────
Defines the ``LLMClient`` Protocol that all provider implementations must
satisfy.  This is the *only* interface agents and other modules see — they
never import a concrete provider directly.

Usage::

    from sentinelai.llm.protocol import LLMClient, LLMMessage, LLMResponse
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Type, TypeVar, runtime_checkable

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class StructuredOutputError(Exception):
    """
    Raised when the model returns output that cannot be parsed and validated
    into the requested Pydantic schema even after one retry.

    Agents should catch this, drop the finding, and record a limitation note.
    """

    def __init__(self, message: str, raw_content: str = "") -> None:
        super().__init__(message)
        self.raw_content = raw_content


@dataclass
class LLMMessage:
    """A single message in a chat conversation."""

    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    """
    The response returned by any LLMClient call.

    Attributes
    ----------
    content:
        The text content of the model's reply.
    input_tokens:
        Number of prompt tokens consumed.
    output_tokens:
        Number of completion tokens generated.
    model:
        The model identifier that produced this response.
    raw:
        The full raw response object from the provider, for debugging.
        May be ``None`` for fake/mock clients.
    """

    content: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = "unknown"
    raw: Any = field(default=None, repr=False)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@runtime_checkable
class LLMClient(Protocol):
    """
    The single interface every LLM provider must implement.

    Implementations:
    - ``FakeLLMClient``      — deterministic scripted responses for tests
    - ``AnthropicClient``    — Claude via the Anthropic API (Phase 8)
    - ``OllamaClient``       — Llama 3.1 via Ollama (Phase 8)

    All implementations are selected at runtime via ``settings.llm_provider``.
    """

    def chat(
        self,
        messages: list[LLMMessage],
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: dict[str, Any] | None = None,
        use_fast_model: bool = False,
    ) -> LLMResponse:
        """
        Send a list of messages and return the model's reply.

        Parameters
        ----------
        messages:
            Ordered list of conversation turns.
        temperature:
            Sampling temperature. 0.0 for deterministic outputs preferred.
        max_tokens:
            Maximum tokens in the completion.
        response_format:
            Optional structured-output hint, e.g. ``{"type": "json_object"}``.
        use_fast_model:
            If True, use the cheaper/faster model (Groq: groq_fast_model;
            Ollama: same model; Fake: no difference).

        Returns
        -------
        LLMResponse
        """
        ...

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
        Send messages, request JSON output, and validate against ``schema``.

        Raises ``StructuredOutputError`` if validation fails after retries.
        Agents should catch this, drop the finding, and record a limitation.
        """
        ...

    @property
    def model_name(self) -> str:
        """The identifier of the underlying model."""
        ...
