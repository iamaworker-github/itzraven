"""
LLMCache — Persistent disk cache for LLM responses.
Hashes prompt+system, caches result. Avoids repeated API calls.
TTL-based expiry, SQLite backend.
Now with Semantic Cache: embedding-based similarity matching for near-identical prompts.
"""
import hashlib
import json
import sqlite3
import threading
import time
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from itzraven.core.logger import get_logger

logger = get_logger()
CACHE_DB = Path("./itzraven_results/llm_cache.db")
CACHE_TTL = 3600  # 1 hour default
SEMANTIC_SIMILARITY_THRESHOLD = 0.88


class SemanticCache:
    """Embedding-based semantic similarity cache for LLM prompts.

    Falls back to exact hash match if embedding model unavailable.
    Stores pre-computed embeddings alongside responses for cosine similarity search.
    """
    _instance = None
    _lock = threading.Lock()
    _embedder = None
    _embedder_lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        self._conn: Optional[sqlite3.Connection] = None
        CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        self._hit_count = 0
        self._semantic_hit_count = 0
        self._miss_count = 0
        self._init_db()

    def _get_embedder(self):
        """Lazy-load sentence transformer for embeddings."""
        if SemanticCache._embedder is None:
            with SemanticCache._embedder_lock:
                if SemanticCache._embedder is None:
                    try:
                        from sentence_transformers import SentenceTransformer
                        SemanticCache._embedder = SentenceTransformer('all-MiniLM-L6-v2')
                        logger.info("SemanticCache: embedding model loaded (all-MiniLM-L6-v2)")
                    except ImportError:
                        logger.warning("SemanticCache: sentence-transformers not installed. Run: pip install sentence-transformers")
                        SemanticCache._embedder = False
        return SemanticCache._embedder if SemanticCache._embedder is not False else None

    def _embed(self, text: str) -> Optional[List[float]]:
        embedder = self._get_embedder()
        if embedder is None:
            return None
        try:
            emb = embedder.encode(text[:2048])
            return emb.tolist()
        except Exception as e:
            logger.debug(f"SemanticCache: embedding failed: {e}")
            return None

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = sum(x * x for x in a) ** 0.5
        nb = sum(y * y for y in b) ** 0.5
        return dot / (na * nb) if na > 0 and nb > 0 else 0.0

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(CACHE_DB))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=OFF")
        return self._conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS semantic_cache (
                cache_key TEXT PRIMARY KEY,
                response TEXT,
                model TEXT,
                embedding TEXT,
                prompt_preview TEXT,
                created_at REAL,
                ttl REAL DEFAULT 3600
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sem_cache_created ON semantic_cache(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sem_cache_model ON semantic_cache(model)")
        conn.commit()
        self._cleanup()

    def _make_exact_key(self, prompt: str, system: Optional[str] = None, model: str = "") -> str:
        raw = f"{model}:{system}:{prompt}"[:2000]
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def get(self, prompt: str, system: Optional[str] = None, model: str = "", max_age: float = CACHE_TTL) -> Optional[str]:
        # 1. Exact hash match (fast path)
        exact_key = self._make_exact_key(prompt, system, model)
        conn = self._get_conn()
        row = conn.execute(
            "SELECT response FROM semantic_cache WHERE cache_key = ? AND (? - created_at) < ttl",
            (exact_key, time.time()),
        ).fetchone()
        if row:
            self._hit_count += 1
            return row[0]

        # 2. Semantic similarity match (slow path)
        prompt_emb = self._embed(prompt)
        if prompt_emb is not None:
            emb_json = json.dumps(prompt_emb)
            candidates = conn.execute(
                "SELECT response, embedding FROM semantic_cache WHERE model = ? AND (? - created_at) < ttl",
                (model, time.time()),
            ).fetchall()
            best_sim = 0.0
            best_response = None
            for resp, emb_str in candidates:
                if not emb_str:
                    continue
                try:
                    cached_emb = json.loads(emb_str)
                    sim = self._cosine_similarity(prompt_emb, cached_emb)
                    if sim > best_sim:
                        best_sim = sim
                        best_response = resp
                except Exception:
                    continue
            if best_sim >= SEMANTIC_SIMILARITY_THRESHOLD:
                self._semantic_hit_count += 1
                conn.execute(
                    "UPDATE semantic_cache SET created_at = ? WHERE cache_key = ?",
                    (time.time(), self._make_exact_key(prompt, system, model)),
                )
                conn.commit()
                return best_response

        self._miss_count += 1
        return None

    def set(self, prompt: str, response: str, system: Optional[str] = None, model: str = "", ttl: float = CACHE_TTL):
        key = self._make_exact_key(prompt, system, model)
        embedding = self._embed(prompt)
        emb_json = json.dumps(embedding) if embedding else ""
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO semantic_cache VALUES (?, ?, ?, ?, ?, ?, ?)",
            (key, response, model, emb_json, prompt[:200], time.time(), ttl),
        )
        conn.commit()

    def _cleanup(self):
        try:
            conn = self._get_conn()
            deleted = conn.execute("DELETE FROM semantic_cache WHERE (? - created_at) > ttl", (time.time(),)).rowcount
            if deleted:
                conn.commit()
                logger.debug(f"Semantic cache cleanup: removed {deleted} expired entries")
        except Exception:
            pass

    def stats(self) -> Dict[str, Any]:
        return {
            "hits": self._hit_count,
            "semantic_hits": self._semantic_hit_count,
            "misses": self._miss_count,
            "ratio": round((self._hit_count + self._semantic_hit_count) / max(self._hit_count + self._semantic_hit_count + self._miss_count, 1), 3),
        }

    def clear(self):
        conn = self._get_conn()
        conn.execute("DELETE FROM semantic_cache")
        conn.commit()
        self._hit_count = 0
        self._semantic_hit_count = 0
        self._miss_count = 0


_cache = SemanticCache()


def cached_llm_call(func):
    """Decorator: cache LLM responses by exact + semantic prompt matching."""
    async def wrapper(prompt: str, system: Optional[str] = None, model: str = "", *args, **kwargs):
        cached = _cache.get(prompt, system, model)
        if cached:
            return cached
        result = await func(prompt, system, model, *args, **kwargs)
        _cache.set(prompt, str(result), system, model)
        return result
    return wrapper
