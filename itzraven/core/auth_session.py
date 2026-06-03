"""
Auth Session Manager — centralized cookie/token/header management for authenticated scanning.

Stores and replays authentication state (cookies, headers, tokens) across
scan requests so agents can test authenticated endpoints without manual replay.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class AuthSession:
    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    base_url: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def header_dict(self) -> Dict[str, str]:
        h = dict(self.headers)
        for key, val in self.tokens.items():
            if key.lower() == "bearer":
                h["Authorization"] = f"Bearer {val}"
            elif key.lower() == "basic":
                h["Authorization"] = f"Basic {val}"
            else:
                h[key] = val
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AuthSession":
        return cls(**data)


class AuthSessionManager:
    """Manages multiple authentication sessions for different targets."""

    SESSIONS_DIR = Path.home() / ".itzraven" / "sessions" / "auth"

    def __init__(self):
        self._sessions: Dict[str, AuthSession] = {}
        self._active_session: Optional[str] = None
        self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self._load_persisted()

    def create_session(self, name: str, base_url: str = "") -> AuthSession:
        session = AuthSession(name=name, base_url=base_url)
        self._sessions[name] = session
        self._active_session = name
        return session

    def get_session(self, name: Optional[str] = None) -> Optional[AuthSession]:
        key = name or self._active_session
        if key is None:
            return None
        session = self._sessions.get(key)
        if session and session.is_expired:
            logger.warning(f"Auth session '{key}' has expired")
            return None
        return session

    def set_active(self, name: str) -> bool:
        if name in self._sessions:
            self._active_session = name
            return True
        return False

    def delete_session(self, name: str) -> bool:
        if name in self._sessions:
            del self._sessions[name]
            self._delete_persisted(name)
            if self._active_session == name:
                self._active_session = None
            return True
        return False

    def list_sessions(self) -> List[dict]:
        return [
            {
                "name": s.name,
                "base_url": s.base_url,
                "cookie_count": len(s.cookies),
                "header_count": len(s.headers),
                "token_count": len(s.tokens),
                "is_expired": s.is_expired,
                "created_at": s.created_at,
            }
            for s in self._sessions.values()
        ]

    def persist(self, name: Optional[str] = None):
        if name:
            session = self._sessions.get(name)
            if session:
                self._write_session(session)
        else:
            for session in self._sessions.values():
                self._write_session(session)

    def _write_session(self, session: AuthSession):
        path = self.SESSIONS_DIR / f"{session.name}.json"
        try:
            path.write_text(json.dumps(session.to_dict(), indent=2, default=str))
        except Exception as e:
            logger.error(f"Failed to persist auth session '{session.name}': {e}")

    def _delete_persisted(self, name: str):
        path = self.SESSIONS_DIR / f"{name}.json"
        path.unlink(missing_ok=True)

    def _load_persisted(self):
        for path in self.SESSIONS_DIR.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                session = AuthSession.from_dict(data)
                self._sessions[session.name] = session
            except Exception as e:
                logger.debug(f"Failed to load auth session {path.stem}: {e}")


_auth_manager: Optional[AuthSessionManager] = None


def get_auth_manager() -> AuthSessionManager:
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthSessionManager()
    return _auth_manager
