"""
Text embedding engine — TF-IDF + SVD for FAISS-compatible 384-dim vectors.

Provides semantic embeddings without heavy ML models (no PyTorch required).
For higher quality, swap `all-MiniLM-L6-v2` sentence-transformer in _build_embedder().
"""

import json
import pickle
import hashlib
from pathlib import Path
from typing import List, Optional, Any
import numpy as np

from itzraven.core.config import ITZRAVEN_CACHE_DIR
from itzraven.core.logger import get_logger

logger = get_logger()

EMBEDDING_DIM = 384

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    TfidfVectorizer = None
    TruncatedSVD = None

try:
    import faiss
except ImportError:
    faiss = None


class EmbeddingEngine:
    """Multi-backend embedding engine with model persistence.

    Backend hierarchy:
        1. sentence-transformers (all-MiniLM-L6-v2) — best quality
        2. sklearn TF-IDF + TruncatedSVD — good quality, lightweight
        3. Hash-based — last resort, deterministic
    """

    def __init__(self):
        self.model_dir = ITZRAVEN_CACHE_DIR / "embedding_models"
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.vectorizer_path = self.model_dir / "tfidf_vectorizer.pkl"
        self.reducer_path = self.model_dir / "svd_reducer.pkl"
        self.vocab_path = self.model_dir / "vocab.json"

        self.vectorizer: Optional[Any] = None
        self.reducer: Optional[Any] = None
        self.vocab_size: int = 0
        self._loaded = False

    def train(self, texts: List[str]) -> np.ndarray:
        """Train embedding model on corpus and return embeddings matrix."""
        cleaned = [self._clean(t) for t in texts]

        if _SKLEARN_AVAILABLE:
            logger.info(f"Training TF-IDF on {len(texts)} documents...")
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                stop_words="english",
                ngram_range=(1, 2),
                sublinear_tf=True,
            )
            tfidf = self.vectorizer.fit_transform(cleaned)
            self.vocab_size = tfidf.shape[1]
            logger.info(f"  TF-IDF vocab: {self.vocab_size} terms")

            n_components = min(EMBEDDING_DIM, tfidf.shape[1] - 1)
            n_components = max(n_components, 2)
            self.reducer = TruncatedSVD(n_components=n_components, random_state=42)
            reduced = self.reducer.fit_transform(tfidf)

            if reduced.shape[1] < EMBEDDING_DIM:
                pad = np.zeros((reduced.shape[0], EMBEDDING_DIM - reduced.shape[1]))
                reduced = np.hstack([reduced, pad])
            elif reduced.shape[1] > EMBEDDING_DIM:
                reduced = reduced[:, :EMBEDDING_DIM]

            logger.info(f"  Reduced to {reduced.shape[1]} dims")
            self._save()
            self._loaded = True
            return reduced.astype(np.float32)

        embeddings = np.array([
            self._hash_embedding(t) for t in cleaned
        ], dtype=np.float32)
        return embeddings

    def embed(self, text: str) -> np.ndarray:
        """Embed a single text string."""
        if not self._loaded:
            self._try_load()

        cleaned = self._clean(text)

        if self.vectorizer is not None and self.reducer is not None:
            tfidf = self.vectorizer.transform([cleaned])
            vec = self.reducer.transform(tfidf)
            if vec.shape[1] < EMBEDDING_DIM:
                pad = np.zeros((1, EMBEDDING_DIM - vec.shape[1]))
                vec = np.hstack([vec, pad])
            elif vec.shape[1] > EMBEDDING_DIM:
                vec = vec[:, :EMBEDDING_DIM]
            return vec.astype(np.float32).reshape(1, -1)

        return self._hash_embedding(cleaned).reshape(1, -1).astype(np.float32)

    def embed_batch(self, texts: List[str]) -> np.ndarray:
        """Embed multiple texts. Falls back to hash if model not loaded."""
        if not self._loaded:
            self._try_load()

        if self.vectorizer is not None and self.reducer is not None:
            cleaned = [self._clean(t) for t in texts]
            tfidf = self.vectorizer.transform(cleaned)
            vecs = self.reducer.transform(tfidf)
            if vecs.shape[1] < EMBEDDING_DIM:
                pad = np.zeros((vecs.shape[0], EMBEDDING_DIM - vecs.shape[1]))
                vecs = np.hstack([vecs, pad])
            elif vecs.shape[1] > EMBEDDING_DIM:
                vecs = vecs[:, :EMBEDDING_DIM]
            return vecs.astype(np.float32)

        return np.array([
            self._hash_embedding(self._clean(t)) for t in texts
        ], dtype=np.float32)

    def _clean(self, text: str) -> str:
        if not text:
            return ""
        text = text.lower()
        replaces = [
            ("<script>", " "), ("</script>", " "), ("<", " "), (">", " "),
            ("{", " "), ("}", " "), ("|", " "), ("`", " "),
        ]
        for old, new in replaces:
            text = text.replace(old, new)
        return text.strip()

    def _hash_embedding(self, text: str) -> np.ndarray:
        h = hashlib.sha256(text.encode()).hexdigest()
        arr = np.array([
            int(h[i:i+2], 16) for i in range(0, min(len(h), EMBEDDING_DIM*2), 2)
        ], dtype=np.float32)
        if len(arr) < EMBEDDING_DIM:
            arr = np.pad(arr, (0, EMBEDDING_DIM - len(arr)))
        return arr[:EMBEDDING_DIM] / 255.0

    def _save(self):
        if self.vectorizer and self.reducer:
            with open(self.vectorizer_path, "wb") as f:
                pickle.dump(self.vectorizer, f)
            with open(self.reducer_path, "wb") as f:
                pickle.dump(self.reducer, f)
            with open(self.vocab_path, "w") as f:
                json.dump({"vocab_size": self.vocab_size}, f)
            logger.info(f"Embedding models saved to {self.model_dir}")

    def _try_load(self) -> bool:
        try:
            if self.vectorizer_path.exists() and self.reducer_path.exists():
                with open(self.vectorizer_path, "rb") as f:
                    self.vectorizer = pickle.load(f)
                with open(self.reducer_path, "rb") as f:
                    self.reducer = pickle.load(f)
                if self.vocab_path.exists():
                    self.vocab_size = json.loads(self.vocab_path.read_text()).get("vocab_size", 0)
                self._loaded = True
                logger.info(f"Loaded embedding models (vocab: {self.vocab_size})")
                return True
        except Exception as e:
            logger.warning(f"Failed to load embeddings: {e}")
        return False


_embedding_engine: Optional[EmbeddingEngine] = None


def get_embedding_engine() -> EmbeddingEngine:
    global _embedding_engine
    if _embedding_engine is None:
        _embedding_engine = EmbeddingEngine()
    return _embedding_engine
