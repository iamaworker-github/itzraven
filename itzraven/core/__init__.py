"""
Core modules for Itzraven

NOTE: Minimal imports here to avoid circular import chains with
itzraven/__init__.py which also imports from config and logger.
The sub-modules are imported lazily where needed.
"""

from itzraven.core.config import Config, get_config, set_config
from itzraven.core.logger import ItzravenLogger, get_logger, setup_logging

# Event Bus - lazy import via helper to avoid circular chains
_event_bus_loaded = False
_event_bus_classes = {}

def _ensure_event_bus():
    global _event_bus_loaded, _event_bus_classes
    if not _event_bus_loaded:
        from itzraven.core.event_bus import EventBus, get_event_bus, set_event_bus
        from itzraven.core.events import (
            BaseEvent, EventPriority,
            AgentStartedEvent, AgentProgressEvent, AgentCompletedEvent, AgentFailedEvent,
            AgentThinkingEvent,
            FindingDiscoveredEvent, FindingValidatedEvent,
            ScanStartedEvent, ScanProgressEvent, ScanCompletedEvent,
            BrowserPageLoadedEvent, ShellCommandExecutedEvent,
            SystemErrorEvent, SystemMetricEvent,
        )
        _event_bus_classes.update({
            "EventBus": EventBus, "get_event_bus": get_event_bus, "set_event_bus": set_event_bus,
            "BaseEvent": BaseEvent, "EventPriority": EventPriority,
            "AgentStartedEvent": AgentStartedEvent, "AgentProgressEvent": AgentProgressEvent,
            "AgentCompletedEvent": AgentCompletedEvent, "AgentFailedEvent": AgentFailedEvent,
            "AgentThinkingEvent": AgentThinkingEvent,
            "FindingDiscoveredEvent": FindingDiscoveredEvent, "FindingValidatedEvent": FindingValidatedEvent,
            "ScanStartedEvent": ScanStartedEvent, "ScanProgressEvent": ScanProgressEvent,
            "ScanCompletedEvent": ScanCompletedEvent,
            "BrowserPageLoadedEvent": BrowserPageLoadedEvent, "ShellCommandExecutedEvent": ShellCommandExecutedEvent,
            "SystemErrorEvent": SystemErrorEvent, "SystemMetricEvent": SystemMetricEvent,
        })
        _event_bus_loaded = True

# Memory System - lazy
_memory_loaded = False
_memory_classes = {}

def _ensure_memory():
    global _memory_loaded, _memory_classes
    if not _memory_loaded:
        try:
            from itzraven.core.memory_manager import MemoryManager, get_memory_manager, set_memory_manager
            from itzraven.core.memory_models import (
                Vulnerability, VulnerabilitySeverity, Target, Exploit,
                ExploitType, AttackPath, AttackComplexity, ScanState,
            )
            _memory_classes.update({
                "MemoryManager": MemoryManager, "get_memory_manager": get_memory_manager,
                "set_memory_manager": set_memory_manager, "Vulnerability": Vulnerability,
                "VulnerabilitySeverity": VulnerabilitySeverity, "Target": Target,
                "Exploit": Exploit, "ExploitType": ExploitType, "AttackPath": AttackPath,
                "AttackComplexity": AttackComplexity, "ScanState": ScanState,
                "MEMORY_SYSTEM_AVAILABLE": True,
            })
        except Exception:
            _memory_classes.update({
                "MemoryManager": None, "get_memory_manager": None, "set_memory_manager": None,
                "Vulnerability": None, "VulnerabilitySeverity": None, "Target": None,
                "Exploit": None, "ExploitType": None, "AttackPath": None,
                "AttackComplexity": None, "ScanState": None, "MEMORY_SYSTEM_AVAILABLE": False,
            })
        _memory_loaded = True

# Blackboard - lazy loaded
_blackboard_loaded = False
_blackboard_classes = {}

def _ensure_blackboard():
    global _blackboard_loaded, _blackboard_classes
    if not _blackboard_loaded:
        from itzraven.core.blackboard import Blackboard, get_blackboard, set_blackboard, FindingCategory, BlackboardEntry
        _blackboard_classes.update({
            "Blackboard": Blackboard, "get_blackboard": get_blackboard, "set_blackboard": set_blackboard,
            "FindingCategory": FindingCategory, "BlackboardEntry": BlackboardEntry,
        })
        _blackboard_loaded = True

# Agent Spawner - lazy
_spawner_loaded = False
_spawner_classes = {}

def _ensure_spawner():
    global _spawner_loaded, _spawner_classes
    if not _spawner_loaded:
        from itzraven.agents.spawner import AgentSpawner, SubAgent
        _spawner_classes.update({
            "AgentSpawner": AgentSpawner, "SubAgent": SubAgent,
        })
        _spawner_loaded = True

# Session Tracker - lazy
_tracker_loaded = False
_tracker_classes = {}

def _ensure_tracker():
    global _tracker_loaded, _tracker_classes
    if not _tracker_loaded:
        from itzraven.core.tracker import SessionTracker, get_session_tracker
        _tracker_classes.update({
            "SessionTracker": SessionTracker,
            "get_session_tracker": get_session_tracker,
        })
        _tracker_loaded = True

# Session Manager - lazy
_session_loaded = False
_session_classes = {}

def _ensure_session():
    global _session_loaded, _session_classes
    if not _session_loaded:
        from itzraven.core.session import SessionManager, SessionData
        _session_classes.update({
            "SessionManager": SessionManager,
            "SessionData": SessionData,
        })
        _session_loaded = True

def __getattr__(name):
    _ensure_event_bus()
    if name in _event_bus_classes:
        return _event_bus_classes[name]
    _ensure_memory()
    if name in _memory_classes:
        return _memory_classes[name]
    _ensure_blackboard()
    if name in _blackboard_classes:
        return _blackboard_classes[name]
    _ensure_spawner()
    if name in _spawner_classes:
        return _spawner_classes[name]
    _ensure_tracker()
    if name in _tracker_classes:
        return _tracker_classes[name]
    _ensure_session()
    if name in _session_classes:
        return _session_classes[name]
    _ensure_rate_limiter()
    if name in _rate_limiter_classes:
        return _rate_limiter_classes[name]
    _ensure_plugin_loader()
    if name in _plugin_loader_classes:
        return _plugin_loader_classes[name]
    _ensure_auth_session()
    if name in _auth_session_classes:
        return _auth_session_classes[name]
    _ensure_fuzzer()
    if name in _fuzzer_classes:
        return _fuzzer_classes[name]
    _ensure_vulndb()
    if name in _vulndb_classes:
        return _vulndb_classes[name]
    _ensure_notifier()
    if name in _notifier_classes:
        return _notifier_classes[name]
    _ensure_ws_api()
    if name in _ws_api_classes:
        return _ws_api_classes[name]
    _ensure_anomaly()
    if name in _anomaly_classes:
        return _anomaly_classes[name]
    _ensure_graph_memory()
    if name in _graph_memory_classes:
        return _graph_memory_classes[name]
    _ensure_corpus()
    if name in _corpus_classes:
        return _corpus_classes[name]
    _ensure_embedding()
    if name in _embedding_classes:
        return _embedding_classes[name]
    _ensure_reaction()
    if name in _reaction_classes:
        return _reaction_classes[name]
    raise AttributeError(f"module 'itzraven.core' has no attribute '{name}'")

# ---------------------------------------------------------------------------
# New modules: Rate Limiter, Plugin Loader, Auth Session, Fuzzer, VulnDB,
#              Notifier, WebSocket API, Anomaly Detector
# ---------------------------------------------------------------------------

_rate_limiter_loaded = False
_rate_limiter_classes = {}

def _ensure_rate_limiter():
    global _rate_limiter_loaded, _rate_limiter_classes
    if not _rate_limiter_loaded:
        try:
            from itzraven.core.rate_limiter import RateLimiter, TokenBucket, get_rate_limiter
            _rate_limiter_classes.update({
                "RateLimiter": RateLimiter, "TokenBucket": TokenBucket,
                "get_rate_limiter": get_rate_limiter,
            })
        except Exception:
            pass
        _rate_limiter_loaded = True

_plugin_loader_loaded = False
_plugin_loader_classes = {}

def _ensure_plugin_loader():
    global _plugin_loader_loaded, _plugin_loader_classes
    if not _plugin_loader_loaded:
        try:
            from itzraven.core.plugin_loader import PluginLoader, get_plugin_loader
            _plugin_loader_classes.update({
                "PluginLoader": PluginLoader, "get_plugin_loader": get_plugin_loader,
            })
        except Exception:
            pass
        _plugin_loader_loaded = True

_auth_session_loaded = False
_auth_session_classes = {}

def _ensure_auth_session():
    global _auth_session_loaded, _auth_session_classes
    if not _auth_session_loaded:
        try:
            from itzraven.core.auth_session import AuthSessionManager, AuthSession
            _auth_session_classes.update({
                "AuthSessionManager": AuthSessionManager,
                "AuthSession": AuthSession,
            })
        except Exception:
            pass
        _auth_session_loaded = True

_fuzzer_loaded = False
_fuzzer_classes = {}

def _ensure_fuzzer():
    global _fuzzer_loaded, _fuzzer_classes
    if not _fuzzer_loaded:
        try:
            from itzraven.toolkit.fuzzer import FuzzerEngine, FuzzResult
            _fuzzer_classes.update({
                "FuzzerEngine": FuzzerEngine, "FuzzResult": FuzzResult,
            })
        except Exception:
            pass
        _fuzzer_loaded = True

_vulndb_loaded = False
_vulndb_classes = {}

def _ensure_vulndb():
    global _vulndb_loaded, _vulndb_classes
    if not _vulndb_loaded:
        try:
            from itzraven.core.vulndb import VulnDB, CVELookup, get_vulndb
            _vulndb_classes.update({
                "VulnDB": VulnDB, "CVELookup": CVELookup, "get_vulndb": get_vulndb,
            })
        except Exception:
            pass
        _vulndb_loaded = True

_notifier_loaded = False
_notifier_classes = {}

def _ensure_notifier():
    global _notifier_loaded, _notifier_classes
    if not _notifier_loaded:
        try:
            from itzraven.core.notifier import Notifier, get_notifier
            _notifier_classes.update({
                "Notifier": Notifier, "get_notifier": get_notifier,
            })
        except Exception:
            pass
        _notifier_loaded = True

_ws_api_loaded = False
_ws_api_classes = {}

def _ensure_ws_api():
    global _ws_api_loaded, _ws_api_classes
    if not _ws_api_loaded:
        try:
            from itzraven.core.ws_api import WebSocketAPI, get_ws_api
            _ws_api_classes.update({
                "WebSocketAPI": WebSocketAPI, "get_ws_api": get_ws_api,
            })
        except Exception:
            pass
        _ws_api_loaded = True

_anomaly_loaded = False
_anomaly_classes = {}

def _ensure_anomaly():
    global _anomaly_loaded, _anomaly_classes
    if not _anomaly_loaded:
        try:
            from itzraven.core.anomaly_detector import AnomalyDetector, get_anomaly_detector
            _anomaly_classes.update({
                "AnomalyDetector": AnomalyDetector,
                "get_anomaly_detector": get_anomaly_detector,
            })
        except Exception:
            pass
        _anomaly_loaded = True

_graph_memory_loaded = False
_graph_memory_classes = {}

def _ensure_graph_memory():
    global _graph_memory_loaded, _graph_memory_classes
    if not _graph_memory_loaded:
        try:
            from itzraven.core.graph_memory import (
                GraphMemory, Entity, Relationship,
                EntityType, RelationType,
                get_graph_memory, set_graph_memory,
            )
            _graph_memory_classes.update({
                "GraphMemory": GraphMemory,
                "Entity": Entity,
                "Relationship": Relationship,
                "EntityType": EntityType,
                "RelationType": RelationType,
                "get_graph_memory": get_graph_memory,
                "set_graph_memory": set_graph_memory,
            })
        except Exception:
            pass
        _graph_memory_loaded = True

# ========================================================================
# RAG Search (Phase 3 — prior art semantic search)
# ========================================================================

_rag_loaded = False
_rag_classes = {}

def _ensure_rag():
    global _rag_loaded, _rag_classes
    if not _rag_loaded:
        try:
            from itzraven.core.rag_search import RagSearch, PriorArt, get_rag_search
            _rag_classes.update({
                "RagSearch": RagSearch, "PriorArt": PriorArt,
                "get_rag_search": get_rag_search,
            })
        except Exception:
            pass
        _rag_loaded = True

# ========================================================================
# Autopilot (Phase 3 — autonomous hunt loop)
# ========================================================================

_autopilot_loaded = False
_autopilot_classes = {}

def _ensure_autopilot():
    global _autopilot_loaded, _autopilot_classes
    if not _autopilot_loaded:
        try:
            from itzraven.core.autopilot import Autopilot, HuntSession, EndpointState, get_autopilot
            _autopilot_classes.update({
                "Autopilot": Autopilot, "HuntSession": HuntSession,
                "EndpointState": EndpointState, "get_autopilot": get_autopilot,
            })
        except Exception:
            pass
        _autopilot_loaded = True

# ========================================================================
# Corpus Populator (Phase 4 — production RAG data pipeline)
# ========================================================================

_corpus_loaded = False
_corpus_classes = {}

def _ensure_corpus():
    global _corpus_loaded, _corpus_classes
    if not _corpus_loaded:
        try:
            from itzraven.core.corpus_populator import CorpusPopulator, populate_from_all_sources, get_corpus_stats, refresh_corpus
            _corpus_classes.update({
                "CorpusPopulator": CorpusPopulator,
                "populate_from_all_sources": populate_from_all_sources,
                "get_corpus_stats": get_corpus_stats,
                "refresh_corpus": refresh_corpus,
            })
        except Exception:
            pass
        _corpus_loaded = True

# ========================================================================
# Reaction Engine (Phase 4 — cross-agent collaboration)
# ========================================================================

_reaction_loaded = False
_reaction_classes = {}

def _ensure_reaction():
    global _reaction_loaded, _reaction_classes
    if not _reaction_loaded:
        try:
            from itzraven.core.reaction_engine import ReactionEngine, ReactionRule, get_reaction_engine
            _reaction_classes.update({
                "ReactionEngine": ReactionEngine,
                "ReactionRule": ReactionRule,
                "get_reaction_engine": get_reaction_engine,
            })
        except Exception:
            pass
        _reaction_loaded = True

# ========================================================================
# Embeddings (Phase 4 — production embedding engine)
# ========================================================================

_embedding_loaded = False
_embedding_classes = {}

def _ensure_embedding():
    global _embedding_loaded, _embedding_classes
    if not _embedding_loaded:
        try:
            from itzraven.core.embeddings import EmbeddingEngine, get_embedding_engine, EMBEDDING_DIM
            _embedding_classes.update({
                "EmbeddingEngine": EmbeddingEngine,
                "get_embedding_engine": get_embedding_engine,
                "EMBEDDING_DIM": EMBEDDING_DIM,
            })
        except Exception:
            pass
        _embedding_loaded = True

# ========================================================================
# Safety Rules (Phase 3 — src-hunter style red lines)
# ========================================================================

_safety_loaded = False
_safety_classes = {}

def _ensure_safety():
    global _safety_loaded, _safety_classes
    if not _safety_loaded:
        try:
            from itzraven.core.safety_rules import SafetyRules, SafetyViolation
            _safety_classes.update({
                "SafetyRules": SafetyRules, "SafetyViolation": SafetyViolation,
            })
        except Exception:
            pass
        _safety_loaded = True

# ========================================================================
# New modules (Phase 2 improvements)
# ========================================================================

_http_client_loaded = False
_http_client_classes = {}

def _ensure_http_client():
    global _http_client_loaded, _http_client_classes
    if not _http_client_loaded:
        try:
            from itzraven.core.http_client import SharedHttpClient, get_http_client, HttpClientStats
            _http_client_classes.update({
                "SharedHttpClient": SharedHttpClient, "get_http_client": get_http_client,
                "HttpClientStats": HttpClientStats,
            })
        except Exception:
            pass
        _http_client_loaded = True

_bloom_filter_loaded = False
_bloom_filter_classes = {}

def _ensure_bloom_filter():
    global _bloom_filter_loaded, _bloom_filter_classes
    if not _bloom_filter_loaded:
        try:
            from itzraven.core.bloom_filter import BloomFilter, FindingDeduplicator, get_finding_dedup
            _bloom_filter_classes.update({
                "BloomFilter": BloomFilter, "FindingDeduplicator": FindingDeduplicator,
                "get_finding_dedup": get_finding_dedup,
            })
        except Exception:
            pass
        _bloom_filter_loaded = True

_adaptive_concurrency_loaded = False
_adaptive_concurrency_classes = {}

def _ensure_adaptive_concurrency():
    global _adaptive_concurrency_loaded, _adaptive_concurrency_classes
    if not _adaptive_concurrency_loaded:
        try:
            from itzraven.core.adaptive_concurrency import (
                AdaptiveConcurrencyController, TargetMetrics, get_adaptive_concurrency,
            )
            _adaptive_concurrency_classes.update({
                "AdaptiveConcurrencyController": AdaptiveConcurrencyController,
                "TargetMetrics": TargetMetrics,
                "get_adaptive_concurrency": get_adaptive_concurrency,
            })
        except Exception:
            pass
        _adaptive_concurrency_loaded = True

_circuit_breaker_loaded = False
_circuit_breaker_classes = {}

def _ensure_circuit_breaker():
    global _circuit_breaker_loaded, _circuit_breaker_classes
    if not _circuit_breaker_loaded:
        try:
            from itzraven.core.circuit_breaker import (
                CircuitBreaker, CircuitBreakerConfig, CircuitBreakerRegistry,
                CircuitBreakerOpenError, get_circuit_breaker_registry,
            )
            _circuit_breaker_classes.update({
                "CircuitBreaker": CircuitBreaker, "CircuitBreakerConfig": CircuitBreakerConfig,
                "CircuitBreakerRegistry": CircuitBreakerRegistry,
                "CircuitBreakerOpenError": CircuitBreakerOpenError,
                "get_circuit_breaker_registry": get_circuit_breaker_registry,
            })
        except Exception:
            pass
        _circuit_breaker_loaded = True

_di_container_loaded = False
_di_container_classes = {}

def _ensure_di_container():
    global _di_container_loaded, _di_container_classes
    if not _di_container_loaded:
        try:
            from itzraven.core.di_container import (
                DIContainer, ServiceLifecycle, ServiceNotFoundError,
                ServiceAlreadyRegisteredError, get_container,
            )
            _di_container_classes.update({
                "DIContainer": DIContainer, "ServiceLifecycle": ServiceLifecycle,
                "ServiceNotFoundError": ServiceNotFoundError,
                "ServiceAlreadyRegisteredError": ServiceAlreadyRegisteredError,
                "get_container": get_container,
            })
        except Exception:
            pass
        _di_container_loaded = True

_telemetry_loaded = False
_telemetry_classes = {}

def _ensure_telemetry():
    global _telemetry_loaded, _telemetry_classes
    if not _telemetry_loaded:
        try:
            from itzraven.core.telemetry import Tracer, Span, TraceContext, trace, get_tracer
            _telemetry_classes.update({
                "Tracer": Tracer, "Span": Span, "TraceContext": TraceContext,
                "trace": trace, "get_tracer": get_tracer,
            })
        except Exception:
            pass
        _telemetry_loaded = True

_llm_deduplicator_loaded = False
_llm_deduplicator_classes = {}

def _ensure_llm_deduplicator():
    global _llm_deduplicator_loaded, _llm_deduplicator_classes
    if not _llm_deduplicator_loaded:
        try:
            from itzraven.core.llm_deduplicator import LLMDeduplicator, FindingRecord, DedupResult, get_llm_deduplicator
            _llm_deduplicator_classes.update({
                "LLMDeduplicator": LLMDeduplicator,
                "FindingRecord": FindingRecord,
                "DedupResult": DedupResult,
                "get_llm_deduplicator": get_llm_deduplicator,
            })
        except Exception:
            pass
        _llm_deduplicator_loaded = True

_chain_executor_loaded = False
_chain_executor_classes = {}

def _ensure_chain_executor():
    global _chain_executor_loaded, _chain_executor_classes
    if not _chain_executor_loaded:
        try:
            from itzraven.core.chain_executor import ChainExecutor, ChainExecutionResult, get_chain_executor
            _chain_executor_classes.update({
                "ChainExecutor": ChainExecutor, "ChainExecutionResult": ChainExecutionResult,
                "get_chain_executor": get_chain_executor,
            })
        except Exception:
            pass
        _chain_executor_loaded = True

_settings_loaded = False
_settings_classes = {}

def _ensure_settings():
    global _settings_loaded, _settings_classes
    if not _settings_loaded:
        try:
            from itzraven.core.settings import ItzravenSettings
            _settings_classes.update({
                "ItzravenSettings": ItzravenSettings,
            })
        except Exception:
            pass
        _settings_loaded = True


def __getattr__(name):
    _ensure_event_bus()
    if name in _event_bus_classes:
        return _event_bus_classes[name]
    _ensure_memory()
    if name in _memory_classes:
        return _memory_classes[name]
    _ensure_blackboard()
    if name in _blackboard_classes:
        return _blackboard_classes[name]
    _ensure_spawner()
    if name in _spawner_classes:
        return _spawner_classes[name]
    _ensure_tracker()
    if name in _tracker_classes:
        return _tracker_classes[name]
    _ensure_session()
    if name in _session_classes:
        return _session_classes[name]
    _ensure_rate_limiter()
    if name in _rate_limiter_classes:
        return _rate_limiter_classes[name]
    _ensure_plugin_loader()
    if name in _plugin_loader_classes:
        return _plugin_loader_classes[name]
    _ensure_auth_session()
    if name in _auth_session_classes:
        return _auth_session_classes[name]
    _ensure_fuzzer()
    if name in _fuzzer_classes:
        return _fuzzer_classes[name]
    _ensure_vulndb()
    if name in _vulndb_classes:
        return _vulndb_classes[name]
    _ensure_notifier()
    if name in _notifier_classes:
        return _notifier_classes[name]
    _ensure_ws_api()
    if name in _ws_api_classes:
        return _ws_api_classes[name]
    _ensure_anomaly()
    if name in _anomaly_classes:
        return _anomaly_classes[name]
    _ensure_graph_memory()
    if name in _graph_memory_classes:
        return _graph_memory_classes[name]
    # New modules
    _ensure_http_client()
    if name in _http_client_classes:
        return _http_client_classes[name]
    _ensure_bloom_filter()
    if name in _bloom_filter_classes:
        return _bloom_filter_classes[name]
    _ensure_adaptive_concurrency()
    if name in _adaptive_concurrency_classes:
        return _adaptive_concurrency_classes[name]
    _ensure_circuit_breaker()
    if name in _circuit_breaker_classes:
        return _circuit_breaker_classes[name]
    _ensure_di_container()
    if name in _di_container_classes:
        return _di_container_classes[name]
    _ensure_telemetry()
    if name in _telemetry_classes:
        return _telemetry_classes[name]
    _ensure_chain_executor()
    if name in _chain_executor_classes:
        return _chain_executor_classes[name]
    _ensure_llm_deduplicator()
    if name in _llm_deduplicator_classes:
        return _llm_deduplicator_classes[name]
    _ensure_settings()
    if name in _settings_classes:
        return _settings_classes[name]
    # Phase 3 modules
    _ensure_rag()
    if name in _rag_classes:
        return _rag_classes[name]
    _ensure_autopilot()
    if name in _autopilot_classes:
        return _autopilot_classes[name]
    _ensure_safety()
    if name in _safety_classes:
        return _safety_classes[name]
    raise AttributeError(f"module 'itzraven.core' has no attribute '{name}'")

# Define __all__ after __getattr__ so static analysis tools work
__all__ = [
    "Config", "get_config", "set_config",
    "ItzravenLogger", "get_logger", "setup_logging",
    "EventBus", "get_event_bus", "set_event_bus",
    "BaseEvent", "EventPriority",
    "AgentStartedEvent", "AgentProgressEvent", "AgentCompletedEvent", "AgentFailedEvent",
    "AgentThinkingEvent",
    "FindingDiscoveredEvent", "FindingValidatedEvent",
    "ScanStartedEvent", "ScanProgressEvent", "ScanCompletedEvent",
    "BrowserPageLoadedEvent", "ShellCommandExecutedEvent",
    "SystemErrorEvent", "SystemMetricEvent",
    "MemoryManager", "get_memory_manager", "set_memory_manager",
    "Vulnerability", "VulnerabilitySeverity", "Target", "Exploit",
    "ExploitType", "AttackPath", "AttackComplexity", "ScanState",
    "MEMORY_SYSTEM_AVAILABLE",
    # Blackboard
    "Blackboard", "get_blackboard", "set_blackboard",
    "FindingCategory", "BlackboardEntry",
    # Agent Spawner
    "AgentSpawner", "SubAgent",
    # Session Tracker
    "SessionTracker", "get_session_tracker",
    # Session Manager
    "SessionManager", "SessionData",
    # Rate Limiter
    "RateLimiter", "TokenBucket", "get_rate_limiter",
    # Plugin Loader
    "PluginLoader", "get_plugin_loader",
    # Auth Session
    "AuthSessionManager", "AuthSession",
    # Fuzzer
    "FuzzerEngine", "FuzzResult",
    # VulnDB
    "VulnDB", "CVELookup", "get_vulndb",
    # Notifier
    "Notifier", "get_notifier",
    # WebSocket API
    "WebSocketAPI", "get_ws_api",
    # Anomaly Detector
    "AnomalyDetector", "get_anomaly_detector",
    # Graph Memory
    "GraphMemory", "Entity", "Relationship",
    "EntityType", "RelationType",
    "get_graph_memory", "set_graph_memory",
    # New modules
    "SharedHttpClient", "get_http_client", "HttpClientStats",
    "BloomFilter", "FindingDeduplicator", "get_finding_dedup",
    "AdaptiveConcurrencyController", "TargetMetrics", "get_adaptive_concurrency",
    "CircuitBreaker", "CircuitBreakerConfig", "CircuitBreakerRegistry",
    "CircuitBreakerOpenError", "get_circuit_breaker_registry",
    "DIContainer", "ServiceLifecycle", "ServiceNotFoundError",
    "ServiceAlreadyRegisteredError", "get_container",
    "Tracer", "Span", "TraceContext", "trace", "get_tracer",
    "ChainExecutor", "ChainExecutionResult", "get_chain_executor",
    "LLMDeduplicator", "FindingRecord", "DedupResult", "get_llm_deduplicator",
    "ItzravenSettings",
    # Phase 3 modules
    "RagSearch", "PriorArt", "get_rag_search",
    "Autopilot", "HuntSession", "EndpointState", "get_autopilot",
    "SafetyRules", "SafetyViolation",
    # Phase 4 modules
    "CorpusPopulator", "populate_from_all_sources", "get_corpus_stats", "refresh_corpus",
    "EmbeddingEngine", "get_embedding_engine", "EMBEDDING_DIM",
    "ReactionEngine", "ReactionRule", "get_reaction_engine",
    # AI Enhancement Modules
    "SelfReflectionEngine", "SessionReflection", "get_self_reflection",
    "PromptEvolutionEngine", "get_prompt_evolution",
    "VulnChainingAI", "AttackChain", "get_vuln_chaining",
    "DebateEngine", "DebateResult", "get_debate_engine",
    "SelfHealingEngine", "HealingResult", "get_self_healing",
    "ToolGenerator", "GeneratedTool", "get_tool_generator",
    "ReinforcementLearningEngine", "get_rl_engine",
    "TargetProfiler", "TargetProfile", "get_target_profiler",
    "FailoverEngine", "get_failover_engine",
    "ReActEngineV2", "get_react_v2",
    "AIOrchestrator", "get_ai_orchestrator",
]
