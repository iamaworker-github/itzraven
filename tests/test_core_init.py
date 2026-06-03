"""Tests for core __init__.py lazy loading and __all__ exports."""

import itzraven.core


def test_core_all_exports():
    expected = [
        "RateLimiter", "TokenBucket", "get_rate_limiter",
        "PluginLoader", "get_plugin_loader",
        "AuthSessionManager", "AuthSession",
        "FuzzerEngine", "FuzzResult",
        "VulnDB", "CVELookup", "get_vulndb",
        "Notifier", "get_notifier",
        "WebSocketAPI", "get_ws_api",
        "AnomalyDetector", "get_anomaly_detector",
    ]
    for name in expected:
        assert hasattr(itzraven.core, name), f"Missing export: {name}"


def test_core_original_exports_still_work():
    assert hasattr(itzraven.core, "Config")
    assert hasattr(itzraven.core, "get_config")
    assert hasattr(itzraven.core, "EventBus")
    assert hasattr(itzraven.core, "get_event_bus")
    assert hasattr(itzraven.core, "Blackboard")
    assert hasattr(itzraven.core, "SessionManager")
    assert hasattr(itzraven.core, "SessionTracker")


def test_lazy_loading_no_circular_imports():
    # This should not raise any ImportError or circular import issues
    from itzraven.core.rate_limiter import RateLimiter
    from itzraven.core.plugin_loader import PluginLoader
    from itzraven.core.auth_session import AuthSessionManager
    from itzraven.core.vulndb import VulnDB
    from itzraven.core.notifier import Notifier
    from itzraven.core.ws_api import WebSocketAPI
    from itzraven.core.anomaly_detector import AnomalyDetector
    from itzraven.toolkit.fuzzer import FuzzerEngine
    from itzraven.core.distributed import RedisEventBackend
    assert RateLimiter is not None
    assert PluginLoader is not None
    assert AuthSessionManager is not None
    assert VulnDB is not None
    assert Notifier is not None
    assert WebSocketAPI is not None
    assert AnomalyDetector is not None
    assert FuzzerEngine is not None
    assert RedisEventBackend is not None
