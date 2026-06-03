"""
RAG-based prior art search — FAISS semantic search over HackerOne reports.

Provides agents with instant access to similar vulnerabilities found
in the wild. Supports hybrid search (semantic + keyword), filtering by
technique/severity, and structured context for LLM prompts.
"""

import json
import sqlite3
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from itzraven.core.config import ITZRAVEN_CACHE_DIR
from itzraven.core.logger import get_logger
from itzraven.core.embeddings import get_embedding_engine, EmbeddingEngine, EMBEDDING_DIM

logger = get_logger()

_FAISS_AVAILABLE = False
try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:
    faiss = None


@dataclass
class PriorArt:
    """Prior art from H1 reports, CVEs, or writeups — production grade."""
    source: str
    id: str
    title: str
    description: str
    technique: str
    severity: str
    program_name: str = ""
    weakness_type: str = ""
    reporter: str = ""
    bounty: int = 0
    url: str = ""
    tags: List[str] = field(default_factory=list)
    similarity: float = 0.0
    disclosed_at: str = ""
    vote_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "id": self.id, "title": self.title,
            "description": self.description, "technique": self.technique,
            "severity": self.severity, "program_name": self.program_name,
            "weakness_type": self.weakness_type, "reporter": self.reporter,
            "bounty": self.bounty, "url": self.url, "tags": self.tags,
            "similarity": round(self.similarity, 3),
            "disclosed_at": self.disclosed_at, "vote_count": self.vote_count,
        }


class RagSearch:
    """FAISS-based semantic search over prior art — production grade.

    Uses TF-IDF + SVD embeddings (or sentence-transformers if available).
    Supports HNSW for fast search over 10,000+ entries.
    """

    EMBEDDING_DIM = EMBEDDING_DIM

    def __init__(self):
        self.index_dir = ITZRAVEN_CACHE_DIR / "rag"
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.index_dir / "prior_art.index"
        self.meta_path = self.index_dir / "prior_art_meta.json"
        self.db_path = self.index_dir / "prior_art.db"

        self.index: Optional[Any] = None
        self.metadata: List[PriorArt] = []
        self._loaded = False
        self._db: Optional[sqlite3.Connection] = None
        self.embedder = get_embedding_engine()

        self._ensure_index()

    def _get_db(self) -> sqlite3.Connection:
        if self._db is None:
            self._db = sqlite3.connect(str(self.db_path))
        return self._db

    def _ensure_index(self):
        if not self.index_path.exists() or not self.meta_path.exists():
            self._build_default_index()
            return
        try:
            if _FAISS_AVAILABLE:
                self.index = faiss.read_index(str(self.index_path))
            with open(self.meta_path) as f:
                raw = json.load(f)
            self.metadata = [PriorArt(**m) for m in raw]
            self._loaded = True
            logger.info(f"RAG loaded: {len(self.metadata)} prior art entries")
        except Exception as e:
            logger.warning(f"RAG index load failed: {e}")
            self._loaded = False

    def _build_default_index(self):
        """Build fallback index with 18 built-in entries (when no HF data)."""
        import numpy as np
        if not _FAISS_AVAILABLE:
            logger.warning("FAISS not available, RAG disabled")
            return

        corpus = self._get_builtin_corpus()
        meta_list = []
        for item in corpus:
            art = PriorArt(
                source=item.get("source", "hackerone"),
                id=item.get("id", ""),
                title=item.get("title", ""),
                description=item.get("description", ""),
                technique=item.get("technique", ""),
                severity=item.get("severity", "medium"),
                program_name=item.get("program_name", ""),
                weakness_type=item.get("weakness_type", ""),
                reporter=item.get("reporter", ""),
                url=item.get("url", ""),
                tags=item.get("tags", []),
            )
            meta_list.append(art)

        texts = [f"{a.title} {a.description} {a.technique}" for a in meta_list]
        embeddings = self.embedder.train(texts)

        dim = embeddings.shape[1]
        index = faiss.IndexHNSWFlat(dim, 32)
        index.add(embeddings)
        faiss.write_index(index, str(self.index_path))

        with open(self.meta_path, "w") as f:
            json.dump([m.to_dict() for m in meta_list], f)

        self.index = index
        self.metadata = meta_list
        self._loaded = True
        logger.info(f"Built default RAG index: {len(corpus)} entries")

    def search(self, query: str, technique: str = "", k: int = 5) -> List[PriorArt]:
        """Search for similar prior art — hybrid semantic + keyword.

        Args:
            query: Search text (finding title + description)
            technique: Filter by technique type
            k: Max number of results

        Returns:
            List of PriorArt entries sorted by similarity (descending)
        """
        if not self._loaded:
            self._ensure_index()
        if not self._loaded or not _FAISS_AVAILABLE or self.index is None:
            return self._keyword_fallback(query, technique, k)

        try:
            emb = self.embedder.embed(query)
            k_search = min(k * 5, len(self.metadata))
            distances, indices = self.index.search(emb, k_search)

            results = []
            for idx, dist in zip(indices[0], distances[0]):
                if idx < 0 or idx >= len(self.metadata):
                    continue
                art = self.metadata[idx]
                if technique:
                    t = technique.lower()
                    if t not in art.technique.lower():
                        if t not in [x.lower() for x in art.tags]:
                            continue
                art.similarity = float(1.0 / (1.0 + dist))
                results.append(art)
                if len(results) >= k:
                    break

            results.sort(key=lambda x: x.similarity, reverse=True)

            if not results:
                return self._keyword_fallback(query, technique, k)
            return results

        except Exception as e:
            logger.debug(f"FAISS search failed ({e}), using keyword fallback")
            return self._keyword_fallback(query, technique, k)

    def search_by_technique(self, technique: str, k: int = 5) -> List[PriorArt]:
        """Filter prior art by technique type using keyword match."""
        results = [
            a for a in self.metadata
            if technique.lower() in a.technique.lower()
            or technique.lower() in [t.lower() for t in a.tags]
        ]
        results.sort(key=lambda x: x.vote_count, reverse=True)
        return results[:k]

    def _keyword_fallback(self, query: str, technique: str = "", k: int = 5) -> List[PriorArt]:
        """BM25-like keyword fallback when FAISS unavailable."""
        import math
        results = []
        query_lower = query.lower()
        query_terms = [w for w in query_lower.split() if len(w) > 2]
        n_docs = len(self.metadata)

        if not query_terms:
            return results

        idf_cache = {}
        for art in self.metadata:
            text = (art.title + " " + art.description + " " + art.technique).lower()
            score = 0.0
            matched_terms = 0
            for word in query_terms:
                if word in text:
                    matched_terms += 1
                    if word not in idf_cache:
                        df = sum(1 for a in self.metadata if word in (
                            a.title + " " + a.description + " " + a.technique
                        ).lower())
                        idf_cache[word] = math.log((n_docs - df + 0.5) / (df + 0.5) + 1.0) if df > 0 else 0.0
                    score += idf_cache[word]
            if technique:
                t = technique.lower()
                if t not in art.technique.lower() and t not in [x.lower() for x in art.tags]:
                    score = 0
            if score > 0:
                art.similarity = score / (len(query_terms) + 1)
                results.append(art)

        results.sort(key=lambda x: x.similarity, reverse=True)
        return results[:k]

    def add_writeup(self, art: PriorArt):
        """Add a custom writeup to the index (rebuilts index incrementally)."""
        db = self._get_db()
        db.execute(
            "INSERT OR REPLACE INTO prior_art VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (art.id, art.source, art.title, art.description,
             art.technique, art.severity, art.program_name,
             art.weakness_type, "", art.reporter, art.bounty,
             art.url, json.dumps(art.tags), art.disclosed_at, art.vote_count),
        )
        db.commit()

        cursor = db.execute("SELECT * FROM prior_art")
        rows = cursor.fetchall()
        cols = [desc[0] for desc in cursor.description]
        self.metadata = []
        for row in rows:
            row_dict = dict(zip(cols, row))
            self.metadata.append(PriorArt(
                source=row_dict["source"], id=row_dict["id"],
                title=row_dict["title"], description=row_dict["description"],
                technique=row_dict["technique"], severity=row_dict["severity"],
                program_name=row_dict.get("program_name", ""),
                weakness_type=row_dict.get("weakness_type", ""),
                reporter=row_dict.get("reporter", ""),
                bounty=row_dict.get("bounty", 0),
                url=row_dict.get("url", ""),
                tags=json.loads(row_dict.get("tags", "[]")),
                disclosed_at=row_dict.get("disclosed_at", ""),
                vote_count=row_dict.get("vote_count", 0),
            ))
        with open(self.meta_path, "w") as f:
            json.dump([m.to_dict() for m in self.metadata], f)

        if _FAISS_AVAILABLE:
            texts = [f"{m.title} {m.description} {m.technique}" for m in self.metadata]
            embeddings = self.embedder.embed_batch(texts)
            dim = embeddings.shape[1]
            new_index = faiss.IndexHNSWFlat(dim, 32)
            new_index.add(embeddings)
            faiss.write_index(new_index, str(self.index_path))
            self.index = new_index

        logger.info(f"Added writeup: {art.title} ({len(self.metadata)} total)")

    def build_context(self, query: str, technique: str = "", k: int = 3, format: str = "compact") -> str:
        """Build LLM context string from prior art search.

        Args:
            query: Search text
            technique: Filter by technique
            k: Number of results
            format: "compact" (short) or "detailed" (full metadata)

        Returns:
            Formatted context string or empty string
        """
        results = self.search(query, technique, k)
        if not results:
            return ""

        if format == "detailed":
            lines = ["[PRIOR ART — Similar findings from H1/CVE database]", ""]
            for i, art in enumerate(results, 1):
                lines.append(f"--- Prior Art #{i} ---")
                lines.append(f"Title: {art.title}")
                lines.append(f"Severity: {art.severity.upper()}")
                lines.append(f"Technique: {art.technique}")
                lines.append(f"Program: {art.program_name or 'N/A'}")
                lines.append(f"Weakness: {art.weakness_type or 'N/A'}")
                lines.append(f"Reporter: {art.reporter or 'N/A'}")
                lines.append(f"Bounty: ${art.bounty}" if art.bounty else "Bounty: N/A")
                lines.append(f"URL: {art.url}" if art.url else "")
                lines.append(f"Description: {art.description[:300]}...")
                lines.append(f"Similarity: {art.similarity:.1%}")
                lines.append("")
        else:
            lines = ["[PRIOR ART — Similar findings from H1/CVE database]", ""]
            for i, art in enumerate(results, 1):
                lines.append(f"{i}. [{art.severity.upper()}] {art.title}")
                lines.append(f"   Technique: {art.technique} | Source: {art.source}")
                if art.program_name:
                    lines.append(f"   Program: {art.program_name}")
                lines.append(f"   Similarity: {art.similarity:.1%}")
                lines.append("")

        return "\n".join(lines)

    def _get_builtin_corpus(self) -> List[Dict[str, Any]]:
        """Fallback corpus of 18 entries when no external data sources available."""
        return [
            {"source": "hackerone", "id": "H1-001", "title": "SQL Injection in login parameter via comment injection",
             "description": "SQL injection in login form. POST /login with parameter username vulnerable to blind SQLi",
             "technique": "sqli", "severity": "critical", "url": "https://hackerone.com/reports/1",
             "tags": ["sqli", "login", "post", "blind"]},
            {"source": "hackerone", "id": "H1-002", "title": "Reflected XSS in search parameter",
             "description": "XSS in search parameter on /search page. Input reflected without sanitization in h1 tag",
             "technique": "xss", "severity": "high", "url": "https://hackerone.com/reports/2",
             "tags": ["xss", "reflected", "search"]},
            {"source": "hackerone", "id": "H1-003", "title": "SSRF via webhook URL parameter",
             "description": "SSRF in /api/webhooks endpoint. URL parameter allows requests to internal IPs",
             "technique": "ssrf", "severity": "critical", "tags": ["ssrf", "webhook", "internal"]},
            {"source": "hackerone", "id": "H1-004", "title": "IDOR in user profile API",
             "description": "IDOR in GET /api/v1/users/{id}. No authorization check allows viewing any user profile",
             "technique": "idor", "severity": "high", "tags": ["idor", "api", "users"]},
            {"source": "hackerone", "id": "H1-005", "title": "Authentication bypass via password reset token leak",
             "description": "Password reset token leaked in Referer header. Chain to account takeover",
             "technique": "auth", "severity": "critical", "tags": ["auth", "password-reset", "leak"]},
            {"source": "hackerone", "id": "H1-006", "title": "RCE via command injection in file export",
             "description": "OS command injection in filename parameter during CSV export. No input sanitization",
             "technique": "rce", "severity": "critical", "tags": ["rce", "cmd-injection", "export"]},
            {"source": "hackerone", "id": "H1-007", "title": "File upload RCE via extension bypass",
             "description": "Webshell upload via .php5 extension. Server configured to execute .php5 files",
             "technique": "file_upload", "severity": "critical", "tags": ["file-upload", "webshell", "rce"]},
            {"source": "hackerone", "id": "H1-008", "title": "JWT alg none bypass",
             "description": "JWT with alg: none accepted by the server. Forge tokens for any user",
             "technique": "jwt", "severity": "critical", "tags": ["jwt", "auth", "token"]},
            {"source": "hackerone", "id": "H1-009", "title": "OAuth redirect URI open redirect",
             "description": "OAuth redirect_uri parameter accepts https://evil.com. Token theft via open redirect",
             "technique": "oauth", "severity": "high", "tags": ["oauth", "redirect", "token-theft"]},
            {"source": "hackerone", "id": "H1-010", "title": "GraphQL introspection enabled exposing schema",
             "description": "GraphQL endpoint has introspection enabled. Full schema leak revealing admin queries",
             "technique": "graphql", "severity": "medium", "tags": ["graphql", "introspection"]},
            {"source": "hackerone", "id": "H1-011", "title": "SSTI in email template",
             "description": "Server-Side Template Injection in email template rendering. {{7*7}} evaluates to 49",
             "technique": "ssti", "severity": "critical", "tags": ["ssti", "email", "rce"]},
            {"source": "hackerone", "id": "H1-012", "title": "LFI via path traversal in download parameter",
             "description": "Local File Inclusion in /download?file= parameter. Reads arbitrary files",
             "technique": "lfi_rfi", "severity": "high", "tags": ["lfi", "file-read", "path-traversal"]},
            {"source": "hackerone", "id": "H1-013", "title": "NoSQL injection in MongoDB query",
             "description": "NoSQL injection in JSON body parameter. $ne operator bypasses auth check",
             "technique": "nosql", "severity": "critical", "tags": ["nosql", "injection", "mongodb"]},
            {"source": "hackerone", "id": "H1-014", "title": "Race condition in coupon redemption",
             "description": "Race condition allows redeeming same coupon 50 times. No locking on coupon_used check",
             "technique": "race_condition", "severity": "high", "tags": ["race", "payment", "coupon"]},
            {"source": "hackerone", "id": "H1-015", "title": "Deserialization RCE in Java via CommonsCollections",
             "description": "Java deserialization in session data. ysoserial CommonsCollections6 chain works",
             "technique": "deserialization", "severity": "critical", "tags": ["deserialization", "java", "rce"]},
            {"source": "cve", "id": "CVE-2021-21972", "title": "VMware vCenter Server RCE",
             "description": "vSphere Client (HTML5) contains a remote code execution vulnerability",
             "technique": "rce", "severity": "critical", "tags": ["vmware", "vcenter", "rce"]},
            {"source": "cve", "id": "CVE-2021-44228", "title": "Apache Log4j2 JNDI injection",
             "description": "Log4j2 JNDI features allow RCE via crafted log messages",
             "technique": "rce", "severity": "critical", "tags": ["log4j", "jndi", "rce"]},
            {"source": "cve", "id": "CVE-2024-37085", "title": "VMware ESXi AD authentication bypass",
             "description": "ESXi authentication bypass via Active Directory group manipulation",
             "technique": "auth", "severity": "critical", "tags": ["vmware", "esxi", "auth-bypass"]},
        ]

    def status(self) -> Dict[str, Any]:
        """Get index status."""
        return {
            "loaded": self._loaded,
            "entries": len(self.metadata),
            "index_path": str(self.index_path),
            "faiss_available": _FAISS_AVAILABLE,
        }


_rag_search: Optional[RagSearch] = None


def get_rag_search() -> RagSearch:
    global _rag_search
    if _rag_search is None:
        _rag_search = RagSearch()
    return _rag_search


def rebuild_rag_index(max_reports: int = 0, force: bool = False) -> int:
    """Convenience: rebuild RAG index from all available sources."""
    from itzraven.core.corpus_populator import populate_from_all_sources
    return populate_from_all_sources(max_reports=max_reports, force=force)
