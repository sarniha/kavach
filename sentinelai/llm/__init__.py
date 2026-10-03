"""sentinelai/llm/__init__.py — LLM provider package."""
from sentinelai.llm.protocol import LLMClient, LLMMessage, LLMResponse
from sentinelai.llm.fake import FakeLLMClient, ScriptedResponse, StructuredOutputError


def create_llm_client(provider: str | None = None) -> LLMClient:
    """
    Factory function to instantiate the configured LLM client.
    Defaults to settings.llm_provider ('groq', 'fake', etc.).
    """
    from sentinelai.config import settings

    prov = (provider or settings.llm_provider).lower()
    if prov == "groq":
        from sentinelai.llm.groq import GroqClient
        return GroqClient()
    # Default to FakeLLMClient for offline reliability
    return FakeLLMClient()


__all__ = [
    "LLMClient",
    "LLMMessage",
    "LLMResponse",
    "FakeLLMClient",
    "ScriptedResponse",
    "StructuredOutputError",
    "create_llm_client",
]
