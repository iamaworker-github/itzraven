import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from itzraven.core.logger import get_logger

logger = get_logger(__name__)


class WriteupStore:
    """Stores and searches security writeups using SQLite."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path.home() / ".itzraven" / "writeups.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS writeups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        content TEXT NOT NULL,
                        vuln_class TEXT NOT NULL,
                        source TEXT DEFAULT '',
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_writeups_vuln_class ON writeups(vuln_class)"
                )
                conn.commit()
            finally:
                conn.close()

    def add_writeup(
        self, title: str, content: str, vuln_class: str, source: str = ""
    ) -> int:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                now = datetime.utcnow().isoformat()
                cursor = conn.execute(
                    "INSERT INTO writeups (title, content, vuln_class, source, created_at) VALUES (?, ?, ?, ?, ?)",
                    (title, content, vuln_class, source, now),
                )
                conn.commit()
                writeup_id = cursor.lastrowid
                logger.info(f"Added writeup '{title}' (id={writeup_id})")
                return writeup_id
            finally:
                conn.close()

    def search(
        self, keyword: str, vuln_class: Optional[str] = None, limit: int = 5
    ) -> List[Dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.row_factory = sqlite3.Row
                query = "SELECT * FROM writeups WHERE (title LIKE ? OR content LIKE ?)"
                params = [f"%{keyword}%", f"%{keyword}%"]
                if vuln_class:
                    query += " AND vuln_class = ?"
                    params.append(vuln_class)
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                total = conn.execute("SELECT COUNT(*) FROM writeups").fetchone()[0]
                by_class = conn.execute(
                    "SELECT vuln_class, COUNT(*) as cnt FROM writeups GROUP BY vuln_class ORDER BY cnt DESC"
                ).fetchall()
                return {"total_writeups": total, "by_class": dict(by_class)}
            finally:
                conn.close()
