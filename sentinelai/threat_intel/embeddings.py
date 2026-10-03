"""
sentinelai/threat_intel/embeddings.py
─────────────────────────────────────
Embedding interfaces and implementations for semantic RAG search (Section 8.1 - 8.4).
Supports real SentenceTransformers (bge-small-en / all-MiniLM-L6-v2) and deterministic offline mock.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol, runtime_checkable


@runtime_checkable
class Embedder(Protocol):
    """Protocol for text embedding generators."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Compute dense vector embeddings for a list of document strings."""
        ...

    def embed_query(self, text: str) -> list[float]:
        """Compute dense vector embedding for a single search query string."""
        ...

    @property
    def dimension(self) -> int:
        """Vector dimension size."""
        ...


class DeterministicMockEmbedder:
    """
    Deterministic, zero-network, offline mock embedder for tests.
    Generates unit-normalized 384-dimensional dense vectors based on SHA256 hashes of input texts.
    Semantically identical texts yield cosine similarity = 1.0; differing texts yield stable vectors.
    """

    def __init__(self, dimension: int = 384) -> None:
        self._dim = dimension

    @property
    def dimension(self) -> int:
        return self._dim

    def _word_vector(self, word: str) -> list[float]:
        vec = []
        h = hashlib.sha256(word.encode("utf-8")).digest()
        for i in range(self._dim):
            b1 = h[(i * 2) % len(h)]
            b2 = h[(i * 2 + 1) % len(h)]
            val = ((b1 << 8) | b2) / 65535.0 - 0.5
            vec.append(val)
        return vec

    def _hash_to_vector(self, text: str) -> list[float]:
        clean = text.strip().lower()
        if not clean:
            return [0.0] * self._dim

        words = [w for w in re.split(r"\W+", clean) if w]
        if not words:
            words = [clean]

        combined = [0.0] * self._dim
        # Add whole-string vector with weight
        whole_vec = self._word_vector(clean)
        for i in range(self._dim):
            combined[i] += whole_vec[i] * 2.0

        # Sum token vectors for bag-of-words similarity
        for w in words:
            w_vec = self._word_vector(w)
            for i in range(self._dim):
                combined[i] += w_vec[i]

        # Unit normalize
        norm = math.sqrt(sum(x * x for x in combined))
        if norm > 0:
            combined = [x / norm for x in combined]
        return combined

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._hash_to_vector(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._hash_to_vector(text)


class SentenceTransformerEmbedder:
    """
    Production embedder wrapping sentence-transformers (e.g. bge-small-en or all-MiniLM-L6-v2).
    Falls back to DeterministicMockEmbedder if model weights cannot be loaded offline.
    """

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en",
        offline_fallback: bool = True,
    ) -> None:
        self.model_name = model_name
        self._model = None
        self._fallback = DeterministicMockEmbedder() if offline_fallback else None

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(model_name)
        except Exception:
            if not offline_fallback:
                raise

    @property
    def dimension(self) -> int:
        if self._model is not None:
            return int(self._model.get_sentence_embedding_dimension() or 384)
        return self._fallback.dimension if self._fallback else 384

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if self._model is not None:
            embeddings = self._model.encode(texts, normalize_embeddings=True)
            return embeddings.tolist()
        if self._fallback:
            return self._fallback.embed_documents(texts)
        raise RuntimeError("No sentence-transformer model loaded and fallback disabled.")

    def embed_query(self, text: str) -> list[float]:
        if self._model is not None:
            # Recommended query prefix for bge models
            prefix = "Represent this sentence for searching relevant passages: " if "bge" in self.model_name.lower() else ""
            emb = self._model.encode(prefix + text, normalize_embeddings=True)
            return emb.tolist()
        if self._fallback:
            return self._fallback.embed_query(text)
        raise RuntimeError("No sentence-transformer model loaded and fallback disabled.")
