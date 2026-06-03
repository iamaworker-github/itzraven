"""
Session Manager for Itzraven - session persistence & resume

Handles saving/loading scan sessions to/from disk as JSON files
in ~/.itzraven/sessions/.
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Dict, List
from dataclasses import dataclass, field, asdict

from itzraven.core.logger import get_logger

logger = get_logger()

SESSIONS_DIR = Path.home() / ".itzraven" / "sessions"


@dataclass
class SessionData:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    agent_states: Dict[str, str] = field(default_factory=dict)
    scan_progress: Dict[str, Any] = field(default_factory=dict)
    chat_history: List[Dict[str, str]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    mode: str = ""
    target: str = ""
    duration: float = 0.0


class SessionManager:
    """Manages session persistence and resume for Itzraven scans."""

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or self._generate_id()
        self.data = SessionData()
        self._dirty = False
        self._closed = False
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _generate_id() -> str:
        return datetime.now().strftime("session_%Y%m%d_%H%M%S")

    def save_session(self, session_data: Optional[Dict[str, Any]] = None) -> str:
        if session_data:
            self.data = SessionData(
                findings=session_data.get("findings", []),
                agent_states=session_data.get("agent_states", {}),
                scan_progress=session_data.get("scan_progress", {}),
                chat_history=session_data.get("chat_history", []),
                timestamp=datetime.now().isoformat(),
                mode=session_data.get("mode", ""),
                target=session_data.get("target", ""),
                duration=session_data.get("duration", 0.0),
            )

        filepath = SESSIONS_DIR / f"{self.session_id}.json"
        payload = asdict(self.data)
        payload["session_id"] = self.session_id
        try:
            with open(filepath, "w") as f:
                json.dump(payload, f, indent=2, default=str)
            self._dirty = False
            logger.info(f"Session saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save session {self.session_id}: {e}")
        return self.session_id

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        filepath = SESSIONS_DIR / f"{session_id}.json"
        if not filepath.exists():
            logger.warning(f"Session file not found: {filepath}")
            return None
        try:
            with open(filepath) as f:
                payload = json.load(f)
            self.session_id = payload.pop("session_id", session_id)
            self.data = SessionData(
                findings=payload.get("findings", []),
                agent_states=payload.get("agent_states", {}),
                scan_progress=payload.get("scan_progress", {}),
                chat_history=payload.get("chat_history", []),
                timestamp=payload.get("timestamp", ""),
                mode=payload.get("mode", ""),
                target=payload.get("target", ""),
                duration=payload.get("duration", 0.0),
            )
            logger.info(f"Session loaded: {filepath}")
            return payload
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None

    @staticmethod
    def list_sessions() -> List[Dict[str, Any]]:
        if not SESSIONS_DIR.exists():
            return []
        sessions = []
        for fpath in sorted(SESSIONS_DIR.glob("*.json"), reverse=True):
            try:
                with open(fpath) as f:
                    data = json.load(f)
                sessions.append({
                    "session_id": data.get("session_id", fpath.stem),
                    "timestamp": data.get("timestamp", ""),
                    "mode": data.get("mode", ""),
                    "target": data.get("target", ""),
                    "duration": data.get("duration", 0.0),
                    "findings_count": len(data.get("findings", [])),
                })
            except Exception:
                continue
        return sessions

    @staticmethod
    def get_latest_session() -> Optional[Dict[str, Any]]:
        sessions = SessionManager.list_sessions()
        return sessions[0] if sessions else None

    def update_progress(self, key: str, value: Any) -> None:
        self.data.scan_progress[key] = value
        self._dirty = True

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.data.findings.append(finding)
        self._dirty = True

    def add_chat_message(self, message: str, msg_type: str = "normal") -> None:
        self.data.chat_history.append({
            "message": message,
            "type": msg_type,
            "timestamp": datetime.now().isoformat(),
        })
        self._dirty = True

    def set_agent_state(self, agent_name: str, state: str) -> None:
        self.data.agent_states[agent_name] = state
        self._dirty = True

    def close(self) -> None:
        if self._dirty and not self._closed:
            self.save_session()
        self._closed = True

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "SessionManager":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
