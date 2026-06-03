"""Tests for the Auth Session Manager."""

from itzraven.core.auth_session import AuthSessionManager, AuthSession


def test_create_session():
    mgr = AuthSessionManager()
    session = mgr.create_session("test-session", "https://example.com")
    assert session.name == "test-session"
    assert session.base_url == "https://example.com"


def test_add_cookies_and_headers():
    session = AuthSession(name="test")
    session.cookies["sessionid"] = "abc123"
    session.headers["X-Custom"] = "value"
    session.tokens["Bearer"] = "token123"

    headers = session.header_dict
    assert "Cookie" in headers
    assert "sessionid=abc123" in headers["Cookie"]
    assert "Authorization" in headers
    assert "Bearer token123" in headers["Authorization"]


def test_session_expiry():
    import time
    session = AuthSession(name="test", expires_at=time.time() - 10)
    assert session.is_expired

    session2 = AuthSession(name="test2", expires_at=time.time() + 3600)
    assert not session2.is_expired


def test_session_manager_lifecycle():
    mgr = AuthSessionManager()
    mgr.create_session("s1", "https://example.com")
    mgr.create_session("s2", "https://test.com")

    sessions = mgr.list_sessions()
    assert len(sessions) >= 2

    retrieved = mgr.get_session("s1")
    assert retrieved is not None
    assert retrieved.name == "s1"

    assert mgr.delete_session("s1") is True
    assert mgr.get_session("s1") is None


def test_active_session():
    mgr = AuthSessionManager()
    mgr.create_session("primary")
    mgr.create_session("secondary")

    assert mgr.set_active("secondary") is True
    session = mgr.get_session()
    assert session is not None
    assert session.name == "secondary"
