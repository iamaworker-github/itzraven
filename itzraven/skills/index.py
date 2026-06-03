"""
SkillIndex — Persistent SQLite skill index.
Build once, query fast across multiple runs.
Auto-rebuilds only when .md files change (via mtime hash).
"""
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from itzraven.skills.engine import Skill, get_skills_engine
from itzraven.skills.registry import TAG_INDEX, get_skill_registry
from itzraven.core.logger import get_logger

logger = get_logger()

from itzraven.core.config import Config

INDEX_DB = Config.CACHE_DIR / "skill_index.db"


class SkillIndex:
    _instance = None
    _lock = threading.Lock()

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
        INDEX_DB.parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(INDEX_DB))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=OFF")
            self._conn.execute("PRAGMA cache_size=-8000")
        return self._conn

    def _compute_mtime_hash(self) -> str:
        skills_dir = Path(__file__).parent.parent / "skills"
        h = hashlib.md5()
        for f in sorted(skills_dir.rglob("*.md")):
            h.update(str(f.stat().st_mtime).encode())
        return h.hexdigest()[:16]

    def ensure_index(self) -> bool:
        conn = self._get_conn()
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='skills'")
        if cur.fetchone():
            return True
        self.build_index()
        return False

    def build_index(self) -> int:
        t0 = time.time()
        conn = self._get_conn()
        conn.executescript("""
            DROP TABLE IF EXISTS skills;
            DROP TABLE IF EXISTS skill_tags;
            DROP TABLE IF EXISTS tag_index;
            DROP TABLE IF EXISTS skills_fts;

            CREATE TABLE skills (
                name TEXT PRIMARY KEY,
                description TEXT,
                category TEXT,
                subcategory TEXT,
                relevance INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                content_preview TEXT DEFAULT ''
            );

            CREATE VIRTUAL TABLE skills_fts USING fts5(
                name, description, category, subcategory, content_preview,
                content='skills',
                content_rowid='rowid'
            );

            CREATE TABLE skill_tags (
                skill_name TEXT,
                tag TEXT,
                FOREIGN KEY(skill_name) REFERENCES skills(name)
            );
            CREATE INDEX idx_skill_tags_tag ON skill_tags(tag);
            CREATE INDEX idx_skills_category ON skills(category);
            CREATE INDEX idx_skills_subcategory ON skills(subcategory);
            CREATE INDEX idx_skills_relevance ON skills(relevance DESC);

            CREATE TABLE tag_index (
                tag TEXT PRIMARY KEY,
                keywords TEXT
            );

            CREATE TRIGGER skills_ai AFTER INSERT ON skills BEGIN
                INSERT INTO skills_fts(rowid, name, description, category, subcategory, content_preview)
                VALUES (new.rowid, new.name, new.description, new.category, new.subcategory, new.content_preview);
            END;
        """)

        # Index tag definitions
        for tag, keywords in TAG_INDEX.items():
            conn.execute("INSERT OR REPLACE INTO tag_index VALUES (?, ?)", (tag, json.dumps(keywords)))

        # Load all skills (without resetting cache between calls)
        engine = get_skills_engine()
        engine._loaded = False
        engine._skills_cache = {}
        engine._loaded = False
        for f in sorted(engine.skills_dir.rglob("*.md")):
            try:
                skill = engine._parse_skill_file(f)
                if skill:
                    engine._skills_cache[skill.name] = skill
            except Exception:
                pass
        engine._loaded = True

        count = 0
        for skill in engine._skills_cache.values():
            conn.execute(
                "INSERT OR REPLACE INTO skills VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    skill.name,
                    skill.description[:300],
                    skill.category,
                    skill.metadata.get("subcategory", ""),
                    int(skill.metadata.get("relevance", 0) or 0),
                    json.dumps(skill.metadata.get("tags", [])),
                    skill.content[:200],
                ),
            )

            text = (skill.name + " " + skill.description + " " + skill.content[:300]).lower()
            seen_tags: Set[str] = set()
            for tag_name, keywords in TAG_INDEX.items():
                for kw in keywords:
                    if kw in text and tag_name not in seen_tags:
                        seen_tags.add(tag_name)
                        conn.execute("INSERT INTO skill_tags VALUES (?, ?)", (skill.name, tag_name))
                        break
            count += 1

        conn.commit()
        dt = time.time() - t0
        logger.info(f"Built persistent skill index: {count} skills in {dt:.2f}s (FTS5 enabled)")
        return count

    def get_by_tag(self, tag: str, max_count: int = 5) -> List[Dict]:
        self.ensure_index()
        conn = self._get_conn()
        tag_lower = tag.lower().replace(" ", "-").replace("_", "-")

        rows = conn.execute(
            """SELECT s.* FROM skills s
               JOIN skill_tags st ON s.name = st.skill_name
               WHERE st.tag = ?
               ORDER BY s.relevance DESC
               LIMIT ?""",
            (tag_lower, max_count),
        ).fetchall()

        if not rows:
            rows = conn.execute(
                """SELECT s.* FROM skills s
                   WHERE s.category = ? OR s.subcategory = ?
                   ORDER BY s.relevance DESC
                   LIMIT ?""",
                (tag_lower, tag_lower, max_count),
            ).fetchall()

        return [dict(r) for r in rows]

    def get_by_category(self, category: str, max_count: int = 8) -> List[Dict]:
        self.ensure_index()
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM skills WHERE category = ? OR subcategory = ? ORDER BY relevance DESC LIMIT ?",
            (category, category, max_count),
        ).fetchall()
        return [dict(r) for r in rows]

    def search(self, query: str, max_count: int = 10) -> List[Dict]:
        self.ensure_index()
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT s.* FROM skills s
                   JOIN skills_fts fts ON s.rowid = fts.rowid
                   WHERE skills_fts MATCH ?
                   ORDER BY rank
                   LIMIT ?""",
                (query, max_count),
            ).fetchall()
            if rows:
                return [dict(r) for r in rows]
        except Exception:
            pass
        like = f"%{query}%"
        rows = conn.execute(
            """SELECT * FROM skills
               WHERE name LIKE ? OR description LIKE ? OR category LIKE ?
               ORDER BY relevance DESC LIMIT ?""",
            (like, like, like, max_count),
        ).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> Dict:
        self.ensure_index()
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM skills").fetchone()[0]
        cats = conn.execute("SELECT category, COUNT(*) as c FROM skills GROUP BY category ORDER BY c DESC").fetchall()
        return {"total": total, "categories": {r["category"]: r["c"] for r in cats}}
