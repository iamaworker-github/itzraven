"""
ItzravenMemory — Cross-session persistent memory for targets, findings, techniques.
Hermes-inspired memory provider with SQLite backend.
Keeps learning across pentest sessions.
"""
import json
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from itzraven.core.logger import get_logger

logger = get_logger()

_local = threading.local()


def _get_conn(db_path: Path) -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(db_path))
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
    return _local.conn


class ItzravenMemory:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            default_dir = Path(__file__).parent.parent.parent.parent / "itzraven_results"
            default_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = default_dir / "itzraven_memory.db"
        else:
            self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = _get_conn(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                target_type TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned TIMESTAMP,
                total_findings INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                category TEXT,
                evidence TEXT,
                proof_of_concept TEXT,
                remediation TEXT,
                confidence REAL,
                agent_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(target) REFERENCES targets(target)
            );
            CREATE TABLE IF NOT EXISTS techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_name TEXT UNIQUE NOT NULL,
                category TEXT,
                description TEXT,
                success_count INTEGER DEFAULT 1,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                payload_example TEXT
            );
            CREATE TABLE IF NOT EXISTS skills_learned (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT UNIQUE NOT NULL,
                source_finding TEXT,
                content TEXT,
                category TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                usage_count INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                target TEXT,
                scan_depth TEXT,
                mode TEXT,
                started TIMESTAMP,
                completed TIMESTAMP,
                findings_count INTEGER DEFAULT 0,
                summary TEXT
            );
        """)
        conn.commit()

    def record_target(self, target: str, target_type: str = "unknown") -> None:
        conn = _get_conn(self.db_path)
        conn.execute(
            """INSERT INTO targets (target, target_type, first_seen, last_scanned)
               VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
               ON CONFLICT(target) DO UPDATE SET last_scanned = CURRENT_TIMESTAMP""",
            (target, target_type),
        )
        conn.commit()

    def record_finding(self, finding) -> None:
        conn = _get_conn(self.db_path)
        conn.execute(
            """INSERT INTO findings (target, title, severity, category, evidence,
               proof_of_concept, remediation, confidence, agent_name)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.get("target", "unknown"),
                finding.get("title", ""),
                finding.get("severity", "info"),
                finding.get("category", ""),
                finding.get("evidence", ""),
                finding.get("proof_of_concept", ""),
                finding.get("remediation", ""),
                finding.get("confidence", 0),
                finding.get("agent_name", ""),
            ),
        )
        conn.execute(
            "UPDATE targets SET total_findings = total_findings + 1 WHERE target = ?",
            (finding.get("target", "unknown"),),
        )
        conn.commit()

    def record_technique(self, technique_name: str, category: str, description: str, payload: str = "") -> None:
        conn = _get_conn(self.db_path)
        conn.execute(
            """INSERT INTO techniques (technique_name, category, description, success_count, last_used, payload_example)
               VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP, ?)
               ON CONFLICT(technique_name) DO UPDATE SET
               success_count = success_count + 1, last_used = CURRENT_TIMESTAMP""",
            (technique_name, category, description, payload),
        )
        conn.commit()

    def record_session(self, session_id: str, target: str, scan_depth: str, mode: str) -> None:
        conn = _get_conn(self.db_path)
        conn.execute(
            "INSERT INTO sessions (session_id, target, scan_depth, mode, started) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (session_id, target, scan_depth, mode),
        )
        conn.commit()

    def complete_session(self, session_id: str, findings_count: int, summary: str) -> None:
        conn = _get_conn(self.db_path)
        conn.execute(
            "UPDATE sessions SET completed = CURRENT_TIMESTAMP, findings_count = ?, summary = ? WHERE session_id = ?",
            (findings_count, summary, session_id),
        )
        conn.commit()

    def get_target_history(self, target: str) -> Dict[str, Any]:
        conn = _get_conn(self.db_path)
        row = conn.execute("SELECT * FROM targets WHERE target = ?", (target,)).fetchone()
        if not row:
            return {"target": target, "first_seen": None, "total_findings": 0}
        return dict(row)

    def get_past_findings(self, target: str, severity: Optional[str] = None) -> List[Dict]:
        conn = _get_conn(self.db_path)
        if severity:
            rows = conn.execute(
                "SELECT * FROM findings WHERE target = ? AND severity = ? ORDER BY timestamp DESC LIMIT 20",
                (target, severity),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE target = ? ORDER BY timestamp DESC LIMIT 50", (target,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_top_techniques(self, limit: int = 10) -> List[Dict]:
        conn = _get_conn(self.db_path)
        rows = conn.execute(
            "SELECT * FROM techniques ORDER BY success_count DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_learned_skills(self) -> List[Dict]:
        conn = _get_conn(self.db_path)
        rows = conn.execute("SELECT * FROM skills_learned ORDER BY usage_count DESC").fetchall()
        return [dict(r) for r in rows]

    def build_memory_context(self, target: str) -> str:
        history = self.get_target_history(target)
        past = self.get_past_findings(target)
        techniques = self.get_top_techniques(5)

        parts = ["<memory-context>"]
        if history.get("first_seen"):
            parts.append(f"Target '{target}' previously scanned. Total findings: {history['total_findings']}.")

        if past:
            parts.append("Past findings:")
            for f in past[:5]:
                parts.append(f"  [{f['severity']}] {f['title']} ({f['category']})")

        if techniques:
            parts.append("Top techniques learned:")
            for t in techniques[:3]:
                parts.append(f"  {t['technique_name']} (used {t['success_count']}x)")

        parts.append("</memory-context>")
        return "\n".join(parts)


_memory_instance: Optional[ItzravenMemory] = None


def get_memory() -> ItzravenMemory:
    global _memory_instance
    if _memory_instance is None:
        _memory_instance = ItzravenMemory()
    return _memory_instance
