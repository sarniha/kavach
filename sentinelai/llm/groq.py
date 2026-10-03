"""
sentinelai/llm/groq.py
───────────────────────
Groq Cloud LLM client implementing the ``LLMClient`` protocol.

Features
--------
* **Shared rate limiter** — sliding-window counters for RPM and TPM, derived
  from ``settings.groq_rpm_limit`` / ``settings.groq_tpm_limit``.
* **Concurrency cap** — a ``threading.Semaphore`` limits simultaneous
  in-flight calls to ``settings.max_concurrent_llm_calls`` (default 2),
  preventing fan-out from triggering 429s.
* **Retry with exponential backoff** — on 429 and 5xx, honours the
  ``Retry-After`` header when present, then falls back to Tenacity's
  ``wait_exponential``.
* **Structured output** — ``chat_json`` sends with ``response_format`` /
  tool-call JSON mode, validates with Pydantic, and retries *once* with
  the validation error appended before raising ``StructuredOutputError``.
* **Fast model routing** — pass ``use_fast_model=True`` to use
  ``settings.groq_fast_model`` for cheap orchestrator steps.

All agent code should call the standard ``chat()`` (for free-form text) or
``chat_json()`` (for structured JSON responses).  Neither method is
provider-specific at the call site — they are part of the LLMClient protocol.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from typing import Any, Type, TypeVar

from pydantic import BaseModel, ValidationError
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sentinelai.llm.protocol import LLMMessage, LLMResponse, StructuredOutputError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class GroqRateLimitError(Exception):
    """Raised when the Groq API returns 429 or TPM budget is pre-exhausted."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class GroqServerError(Exception):
    """Raised on 5xx responses from Groq."""



class _SlidingWindowRateLimiter:
    """
    Thread-safe sliding-window rate limiter for RPM and TPM.

    Both counters share one lock so a single ``acquire`` call atomically
    checks and reserves both budgets.

    Parameters
    ----------
    rpm:
        Maximum requests per 60-second window.
    tpm:
        Maximum tokens per 60-second window.
    """

    _WINDOW = 60.0  # seconds

    def __init__(self, rpm: int, tpm: int) -> None:
        self._rpm = rpm
        self._tpm = tpm
        self._lock = threading.Lock()
        # Deques of (timestamp, value) pairs within the sliding window
        self._req_times: deque[float] = deque()
        self._tok_events: deque[tuple[float, int]] = deque()

    def _evict_old(self, now: float) -> None:
        """Remove entries older than the window (caller holds the lock)."""
        cutoff = now - self._WINDOW
        while self._req_times and self._req_times[0] < cutoff:
            self._req_times.popleft()
        while self._tok_events and self._tok_events[0][0] < cutoff:
            self._tok_events.popleft()

    def _current_tpm(self) -> int:
        return sum(t for _, t in self._tok_events)

    def acquire(self, estimated_tokens: int = 0, timeout: float = 120.0) -> None:
        """
        Block until both the RPM and TPM budgets allow a new request.

        Parameters
        ----------
        estimated_tokens:
            Rough estimate of tokens this call will consume.  Used to
            pre-check the TPM budget before sending.
        timeout:
            Maximum seconds to wait before raising ``GroqRateLimitError``.
        """
        deadline = time.monotonic() + timeout
        sleep_step = 0.25

        while True:
            with self._lock:
                now = time.monotonic()
                self._evict_old(now)

                rpm_ok = len(self._req_times) < self._rpm
                tpm_ok = (self._current_tpm() + estimated_tokens) <= self._tpm

                if rpm_ok and tpm_ok:
                    # Reserve the slot
                    self._req_times.append(now)
                    if estimated_tokens:
                        self._tok_events.append((now, estimated_tokens))
                    return

            if time.monotonic() >= deadline:
                raise GroqRateLimitError(
                    f"Rate-limit budget not available within {timeout}s "
                    f"(rpm={len(self._req_times)}/{self._rpm}, "
                    f"tpm={self._current_tpm()}/{self._tpm})"
                )
            time.sleep(sleep_step)

    def record_actual_tokens(self, tokens: int) -> None:
        """
        Update the TPM window with the *actual* token count after a call
        completes (to correct any estimation error).
        """
        with self._lock:
            now = time.monotonic()
            self._tok_events.append((now, tokens))


# ─────────────────────────────────────────────────────────────────────────────
# Module-level shared state (one limiter + semaphore per process)
# ─────────────────────────────────────────────────────────────────────────────

_limiter: _SlidingWindowRateLimiter | None = None
_concurrency_sem: threading.Semaphore | None = None
_shared_lock = threading.Lock()


def _get_shared_resources(
    rpm: int, tpm: int, max_concurrent: int
) -> tuple[_SlidingWindowRateLimiter, threading.Semaphore]:
    """Lazily initialise (or return) the shared rate-limiter and semaphore."""
    global _limiter, _concurrency_sem
    with _shared_lock:
        if _limiter is None:
            _limiter = _SlidingWindowRateLimiter(rpm=rpm, tpm=tpm)
        if _concurrency_sem is None:
            _concurrency_sem = threading.Semaphore(max_concurrent)
    return _limiter, _concurrency_sem


def reset_shared_resources() -> None:
    """
    Reset the shared rate limiter and semaphore.
    Call this between tests to avoid state leakage.
    """
    global _limiter, _concurrency_sem
    with _shared_lock:
        _limiter = None
        _concurrency_sem = None


# ─────────────────────────────────────────────────────────────────────────────
# Retry helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_retryable(exc: BaseException) -> bool:
    return isinstance(exc, (GroqRateLimitError, GroqServerError))


def _before_retry(retry_state: RetryCallState) -> None:
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    wait = getattr(exc, "retry_after", None)
    if wait:
        logger.info("Groq Retry-After header: sleeping %.1fs", wait)
        time.sleep(wait)


# ─────────────────────────────────────────────────────────────────────────────
# GroqClient
# ─────────────────────────────────────────────────────────────────────────────

class GroqClient:
    """
    Groq Cloud LLM client with rate limiting, retry, and structured-output
    support.

    Parameters
    ----------
    api_key:
        Groq API key.  Defaults to ``settings.groq_api_key``.
    model:
        Main reasoning model name.  Defaults to ``settings.groq_model``.
    fast_model:
        Cheap model for simple steps.  Defaults to ``settings.groq_fast_model``.
    rpm_limit, tpm_limit:
        Rate-limit parameters; default to settings values.
    max_concurrent:
        Concurrency cap; default to ``settings.max_concurrent_llm_calls``.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        fast_model: str | None = None,
        rpm_limit: int | None = None,
        tpm_limit: int | None = None,
        max_concurrent: int | None = None,
    ) -> None:
        from groq import Groq  # local import keeps the module importable without groq installed
        from sentinelai.config import settings as _s

        self._api_key = api_key or _s.groq_api_key
        if not self._api_key:
            raise ValueError(
                "GROQ_API_KEY is not set.  "
                "Set LLM_PROVIDER=fake for offline runs, or provide the key."
            )

        self._model = model or _s.groq_model
        self._fast_model = fast_model or _s.groq_fast_model

        if not self._model:
            raise ValueError("GROQ_MODEL must be set (e.g. llama-3.3-70b-versatile)")

        # Fall back to main model if fast model is unset
        self._fast_model = self._fast_model or self._model

        _rpm = rpm_limit if rpm_limit is not None else _s.groq_rpm_limit
        _tpm = tpm_limit if tpm_limit is not None else _s.groq_tpm_limit
        _con = max_concurrent if max_concurrent is not None else _s.max_concurrent_llm_calls

        self._rate_limiter, self._sem = _get_shared_resources(_rpm, _tpm, _con)
        self._client = Groq(api_key=self._api_key)

    # ── Public interface ──────────────────────────────────────────────────────

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
        Send messages and return a text response.

        Acquires the rate-limiter and concurrency semaphore before calling
        the API.  Retries on 429 / 5xx with exponential backoff.
        """
        model = self._fast_model if use_fast_model else self._model
        groq_messages = [{"role": m.role, "content": m.content} for m in messages]

        # Estimate tokens (rough: 1 token ≈ 4 chars)
        estimated_tokens = sum(len(m.content) // 4 for m in messages) + max_tokens
        self._rate_limiter.acquire(estimated_tokens=min(estimated_tokens, self._rate_limiter._tpm))

        with self._sem:
            return self._call_with_retry(
                model=model,
                messages=groq_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format=response_format,
            )

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

        Retry strategy
        --------------
        1. Send with ``response_format={"type": "json_object"}``.
        2. Parse JSON; validate with Pydantic.
        3. On ``ValidationError``: append the error to the last user message
           and retry *once*.
        4. If still invalid: raise ``StructuredOutputError`` (caller drops
           the finding and records a limitation).

        Parameters
        ----------
        schema:
            A Pydantic ``BaseModel`` subclass to validate against.
        """
        rf: dict[str, Any] = {"type": "json_object"}

        response = self.chat(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=rf,
            use_fast_model=use_fast_model,
        )

        try:
            data = json.loads(response.content)
            return schema.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as first_err:
            logger.warning(
                "Structured output validation failed (attempt 1): %s", first_err
            )

        # ── Retry once with the validation error appended ─────────────────
        retry_messages = list(messages) + [
            LLMMessage(role="assistant", content=response.content),
            LLMMessage(
                role="user",
                content=(
                    f"Your response could not be parsed. Error: {first_err}\n"
                    f"Please return ONLY valid JSON matching this schema:\n"
                    f"{json.dumps(schema.model_json_schema(), indent=2)}"
                ),
            ),
        ]
        retry_response = self.chat(
            retry_messages,
            temperature=0.0,
            max_tokens=max_tokens,
            response_format=rf,
            use_fast_model=use_fast_model,
        )

        try:
            data = json.loads(retry_response.content)
            return schema.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as second_err:
            logger.error(
                "Structured output validation failed after retry: %s", second_err
            )
            raise StructuredOutputError(
                f"Could not produce valid {schema.__name__} after 2 attempts: {second_err}",
                raw_content=retry_response.content,
            ) from second_err

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def fast_model_name(self) -> str:
        return self._fast_model

    # ── Internal ──────────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type((GroqRateLimitError, GroqServerError)),
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(5),
        before_sleep=_before_retry,
        reraise=True,
    )
    def _call_with_retry(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        response_format: dict[str, Any] | None,
    ) -> LLMResponse:
        """Execute the Groq API call and translate HTTP errors to our types."""
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if response_format:
                kwargs["response_format"] = response_format

            completion = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            # Translate Groq SDK errors to our error types
            exc_str = str(exc)
            status = getattr(exc, "status_code", None)

            if status == 429 or "rate_limit" in exc_str.lower():
                retry_after: float | None = None
                headers = getattr(exc, "response", None)
                if headers is not None:
                    ra = getattr(headers, "headers", {}).get("retry-after")
                    if ra:
                        try:
                            retry_after = float(ra)
                        except ValueError:
                            pass
                raise GroqRateLimitError(exc_str, retry_after=retry_after) from exc

            if status and status >= 500:
                raise GroqServerError(exc_str) from exc

            raise  # propagate unexpected errors as-is

        content = completion.choices[0].message.content or ""
        usage = completion.usage
        in_tokens = usage.prompt_tokens if usage else 0
        out_tokens = usage.completion_tokens if usage else 0

        # Record actual tokens back to the rate limiter
        self._rate_limiter.record_actual_tokens(in_tokens + out_tokens)

        logger.debug(
            "Groq call complete: model=%s in=%d out=%d",
            model,
            in_tokens,
            out_tokens,
        )
        return LLMResponse(
            content=content,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            model=model,
            raw=completion,
        )
