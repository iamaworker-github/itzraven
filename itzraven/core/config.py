"""
Configuration management for Itzraven
"""

import os
import json
import contextlib
from pathlib import Path
from typing import Any, Optional, Dict, ClassVar, List
from dataclasses import dataclass, field
from dotenv import load_dotenv

from itzraven.core.settings import ItzravenSettings
from itzraven.core.logger import get_logger

logger = get_logger()

load_dotenv()

# ---------------------------------------------------------------------------
# Docker health check
# ---------------------------------------------------------------------------
def check_docker(timeout: int = 10) -> bool:
    """Check if Docker is available and running."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False

def ensure_docker_image(image: str = "itzraven-security/sandbox:latest", timeout: int = 60) -> bool:
    """Ensure Docker image is pulled. Returns True if available."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return True
        logger.info(f"Pulling Docker image: {image}")
        pull = subprocess.run(
            ["docker", "pull", image],
            capture_output=True, text=True, timeout=timeout,
        )
        return pull.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.warning(f"Docker image check failed: {e}")
        return False

# ---------------------------------------------------------------------------
# Centralized paths (used across the entire codebase)
# Replace all hardcoded path references with these constants.
# ---------------------------------------------------------------------------
ITZRAVEN_HOME: Path = Path.home() / ".itzraven"
ITZRAVEN_OUTPUT: Path = Path("./itzraven_results")
ITZRAVEN_MONITOR_DIR: Path = ITZRAVEN_HOME / "monitor"
ITZRAVEN_PLUGINS_DIR: Path = ITZRAVEN_HOME / "plugins"
ITZRAVEN_LEARNED_SKILLS_DIR: Path = ITZRAVEN_HOME / "learned_skills"
ITZRAVEN_CACHE_DIR: Path = ITZRAVEN_HOME / "cache"
ITZRAVEN_SESSION_DIR: Path = ITZRAVEN_HOME / "sessions"
ITZRAVEN_LOGS_DIR: Path = ITZRAVEN_HOME / "logs"

__all__ = [
    "Config", "get_config", "set_config",
    "ITZRAVEN_HOME", "ITZRAVEN_OUTPUT", "ITZRAVEN_MONITOR_DIR",
    "ITZRAVEN_PLUGINS_DIR", "ITZRAVEN_LEARNED_SKILLS_DIR",
    "ITZRAVEN_CACHE_DIR", "ITZRAVEN_SESSION_DIR", "ITZRAVEN_LOGS_DIR",
]

# ---------------------------------------------------------------------------
# Strix‑style configuration handling for Itzraven
# ---------------------------------------------------------------------------

class Config:
    """Configuration manager for Itzraven, modelled after Strix.

    - Values are read from environment variables.
    - A JSON file (default: ``~/.itzraven/cli-config.json``) can override env vars.
    - ``apply_saved_config`` loads the JSON file and populates ``os.environ``.
    - ``save_current_config`` writes the current env vars back to the JSON file.
    - Runtime overrides (e.g., CLI flags) can be passed via ``set_config`` which
      stores a temporary ``_runtime_overrides`` dict used by ``get``.
    """

    # Directory & file defaults (mirroring Strix)
    CONFIG_DIR: ClassVar[Path] = ITZRAVEN_HOME
    CONFIG_FILE: ClassVar[Path] = CONFIG_DIR / "cli-config.json"

    # Centralized path constants
    MONITOR_DIR: ClassVar[Path] = ITZRAVEN_MONITOR_DIR
    PLUGINS_DIR: ClassVar[Path] = ITZRAVEN_PLUGINS_DIR
    LEARNED_SKILLS_DIR: ClassVar[Path] = ITZRAVEN_LEARNED_SKILLS_DIR
    CACHE_DIR: ClassVar[Path] = ITZRAVEN_CACHE_DIR
    SESSION_DIR: ClassVar[Path] = ITZRAVEN_SESSION_DIR
    LOGS_DIR: ClassVar[Path] = ITZRAVEN_LOGS_DIR

    # ---------------------------------------------------------------------
    # Strix-compatible configuration (also supports legacy Itzraven names)
    # ---------------------------------------------------------------------
    # LLM Configuration (Strix-style: STRIX_LLM = "openai/gpt-5.4")
    strix_llm: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_api_base: Optional[str] = None
    llm_timeout: int = 300
    strix_llm_max_retries: int = 5
    strix_reasoning_effort: str = "high"

    # Legacy Itzraven LLM config
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ai_model: str = "opencode/deepseek-v4-flash-free"

    max_concurrent_agents: int = 5
    request_timeout: int = 30
    max_retries: int = 3

    headless_browser: bool = True
    browser_timeout: int = 30000

    output_dir: Path = Path("./itzraven_results")
    verbose: bool = False
    debug: bool = False

    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None

    requests_per_second: int = 10
    burst_size: int = 20

    # Sandbox execution settings
    use_docker: bool = True
    docker_image: str = "itzraven-security/sandbox:latest"
    docker_mandatory: bool = True

    # LiteLLM multi-provider config
    litellm_model: Optional[str] = None
    litellm_api_base: Optional[str] = None
    litellm_max_tokens: int = 4096
    litellm_fallbacks: str = "gpt-4o-mini,claude-3-haiku-20240307"

    # Provider-specific API keys
    google_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    mistral_api_key: Optional[str] = None

    # Strix optional features
    perplexity_api_key: Optional[str] = None
    strix_disable_browser: bool = False

    # OpenCode API (DeepSeek v4 Flash)
    opencode_api_key: Optional[str] = None
    opencode_api_base: str = "https://api.opencode.ai/v1"

    # BlockRun API (free DeepSeek V4 Flash - no key needed)
    blockrun_api_base: str = "https://blockrun.ai/api/v1"

    # AI Efficiency features
    ai_model_router_enabled: bool = True
    semantic_cache_enabled: bool = True
    semantic_similarity_threshold: float = 0.88
    scan_depth_quick_tokens: int = 500
    scan_depth_standard_tokens: int = 1500
    scan_depth_deep_tokens: int = 3000

    # Local model / GPU support
    local_model_enabled: bool = False
    local_model_provider: str = "ollama"  # ollama, llamacpp, vllm
    local_model_name: str = "llama3:8b"
    local_model_api_base: str = "http://localhost:11434/v1"
    gpu_enabled: bool = False
    gpu_backend: str = "cuda"  # cuda, rocm, cpu
    gpu_device_ids: str = "0"
    gpu_memory_limit: int = 8  # GB

    # Internal cache for runtime overrides (set via ``set_config``)
    _runtime_overrides: ClassVar[Dict[str, Any]] = {}

    # ---------------------------------------------------------------------
    # Helper methods
    # ---------------------------------------------------------------------
    @classmethod
    def _env_name(cls, name: str) -> str:
        return name.upper()

    @classmethod
    def _load_from_env(cls) -> Dict[str, Any]:
        """Load configuration values from the environment.

        Returns a dict with the same keys as the class attributes.
        """
        data: Dict[str, Any] = {}
        for field_name in cls._tracked_names():
            env_name = cls._env_name(field_name)
            value = os.getenv(env_name)
            if value is not None:
                # Basic type coercion for known types
                if field_name in {"max_concurrent_agents", "request_timeout", "max_retries", "browser_timeout", "requests_per_second", "burst_size"}:
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                elif field_name in {"headless_browser", "verbose", "debug", "use_docker", "docker_mandatory"}:
                    value = value.lower() == "true"
                elif field_name == "output_dir":
                    value = Path(value)
                data[field_name] = value
        return data

    @classmethod
    def _tracked_names(cls) -> list[str]:
        """Names of configuration attributes that may be overridden via env or JSON."""
        return [
            # Strix-style config
            "strix_llm",
            "llm_api_key",
            "llm_api_base",
            "llm_timeout",
            "strix_llm_max_retries",
            "strix_reasoning_effort",
            "perplexity_api_key",
            "strix_disable_browser",
            "opencode_api_key",
            "opencode_api_base",
            "blockrun_api_base",
            # LiteLLM multi-provider config
            "litellm_model",
            "litellm_api_base",
            "litellm_max_tokens",
            "litellm_fallbacks",
            # Provider-specific API keys
            "google_api_key",
            "groq_api_key",
            "mistral_api_key",
            # Legacy itzraven config
            "openai_api_key",
            "anthropic_api_key",
            "ai_model",
            "max_concurrent_agents",
            "request_timeout",
            "max_retries",
            "headless_browser",
            "browser_timeout",
            "output_dir",
            "verbose",
            "debug",
            "http_proxy",
            "https_proxy",
            "requests_per_second",
            "burst_size",
            "use_docker",
            "docker_image",
            # AI Efficiency features
            "ai_model_router_enabled",
            "semantic_cache_enabled",
            "semantic_similarity_threshold",
            "scan_depth_quick_tokens",
            "scan_depth_standard_tokens",
            "scan_depth_deep_tokens",
            "local_model_enabled",
            "local_model_provider",
            "local_model_name",
            "local_model_api_base",
            "gpu_enabled",
            "gpu_backend",
            "gpu_device_ids",
            "gpu_memory_limit",
        ]

    @classmethod
    def apply_saved_config(cls, force: bool = False) -> Dict[str, str]:
        """Load the JSON config file (if it exists) and apply its values to ``os.environ``.

        Returns a dict of the variables that were applied.
        """
        if not cls.CONFIG_FILE.exists():
            return {}
        try:
            with cls.CONFIG_FILE.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            return {}
        env_vars = raw.get("env", {})
        applied: Dict[str, str] = {}
        for var_name, var_value in env_vars.items():
            if var_name in cls.tracked_vars():
                if force or var_name not in os.environ:
                    os.environ[var_name] = var_value
                    applied[var_name] = var_value
        return applied

    @classmethod
    def save_current_config(cls) -> bool:
        """Capture the current environment variables (for tracked keys) and write them to the JSON file."""
        cls.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        env_vars: Dict[str, str] = {}
        for var_name in cls.tracked_vars():
            value = os.getenv(var_name)
            if value:
                env_vars[var_name] = value
        try:
            with cls.CONFIG_FILE.open("w", encoding="utf-8") as f:
                json.dump({"env": env_vars}, f, indent=2)
        except OSError:
            return False
        with contextlib.suppress(OSError):
            cls.CONFIG_FILE.chmod(0o600)
        return True

    @classmethod
    def tracked_vars(cls) -> list[str]:
        return [name.upper() for name in cls._tracked_names()]

    # ---------------------------------------------------------------------
    # Public API – ``get`` mirrors Strix's ``Config.get``
    # ---------------------------------------------------------------------
    @classmethod
    def get(cls, name: str) -> Any:
        """Retrieve a configuration value.

        Order of precedence:
        1. Runtime overrides set via ``set_config``.
        2. Environment variable (including those loaded from the JSON file).
        3. Class default.
        """
        # Runtime overrides take highest priority
        if name in cls._runtime_overrides:
            return cls._runtime_overrides[name]
        env_name = cls._env_name(name)
        if env_name in os.environ:
            raw = os.getenv(env_name)
            # Coerce to appropriate type based on the attribute name
            if name in {"max_concurrent_agents", "request_timeout", "max_retries", "browser_timeout", "requests_per_second", "burst_size"}:
                try:
                    return int(raw)
                except ValueError:
                    return raw
            if name in {"headless_browser", "verbose", "debug", "use_docker"}:
                return raw.lower() == "true"
            if name == "output_dir":
                return Path(raw)
            return raw
        # Fallback to class attribute default
        return getattr(cls, name, None)

    # ---------------------------------------------------------------------
    # Runtime configuration helpers (used by the CLI)
    # ---------------------------------------------------------------------
    @classmethod
    def set_runtime_overrides(cls, **kwargs: Any) -> None:
        """Set temporary overrides for the current process (e.g., CLI flags)."""
        for key, value in kwargs.items():
            cls._runtime_overrides[key] = value

    # ---------------------------------------------------------------------
    # Convenience helpers used elsewhere in Itzraven
    # ---------------------------------------------------------------------
    @property
    def has_ai_enabled(self) -> bool:
        model = (self.get("ai_model") or "").lower()
        free_models = {"opencode/deepseek-v4-flash-free", "opencode/mimo-v2.5-free", "blockrun/nvidia/deepseek-v4-flash"}
        if model in free_models or any(f in model for f in free_models):
            return True
        return bool(
            self.get("llm_api_key")
            or self.get("openai_api_key")
            or self.get("anthropic_api_key")
            or self.get("opencode_api_key")
            or self.get("google_api_key")
            or self.get("groq_api_key")
            or self.get("mistral_api_key")
        )

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        http = self.get("http_proxy")
        https = self.get("https_proxy")
        if http or https:
            return {"http": http or "", "https": https or ""}
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Return a shallow dict of the current configuration (excluding secrets)."""
        return {
            "ai_model": self.get("ai_model"),
            "max_concurrent_agents": self.get("max_concurrent_agents"),
            "request_timeout": self.get("request_timeout"),
            "max_retries": self.get("max_retries"),
            "headless_browser": self.get("headless_browser"),
            "browser_timeout": self.get("browser_timeout"),
            "output_dir": str(self.get("output_dir")),
            "verbose": self.get("verbose"),
            "debug": self.get("debug"),
            "requests_per_second": self.get("requests_per_second"),
            "burst_size": self.get("burst_size"),
            "use_docker": self.get("use_docker"),
            "docker_image": self.get("docker_image"),
            "has_ai_enabled": self.has_ai_enabled,
            "http_max_connections": self.get("http_max_connections"),
            "http_max_keepalive": self.get("http_max_keepalive"),
            "ai_model_router_enabled": self.get("ai_model_router_enabled"),
            "semantic_cache_enabled": self.get("semantic_cache_enabled"),
            "semantic_similarity_threshold": self.get("semantic_similarity_threshold"),
        }

    @classmethod
    def get_settings(cls) -> ItzravenSettings:
        """Get Pydantic-validated settings (lazy init, cached)."""
        return ItzravenSettings()

    @classmethod
    def validate_current(cls) -> Dict[str, Any]:
        """Validate current configuration and return warnings."""
        warnings = {}
        settings = ItzravenSettings()
        try:
            settings.model_validate({
                k: cls.get(k) for k in cls._tracked_names()
            })
        except Exception as e:
            warnings["validation_error"] = str(e)
        mc = cls.get("max_concurrent_agents")
        if mc and mc > 50:
            warnings["max_concurrent_agents"] = f"High concurrency ({mc}) may cause resource issues"
        to = cls.get("request_timeout")
        if to and to < 5:
            warnings["request_timeout"] = f"Low timeout ({to}s) may cause frequent failures"
        return warnings

# ---------------------------------------------------------------------------
# Global helpers – kept for backward compatibility with existing imports
# ---------------------------------------------------------------------------

# Global singleton instance (mirrors original Itzraven behaviour)
_config_instance: Optional[Config] = None

def get_config() -> Config:
    global _config_instance
    if _config_instance is None:
        # Load any persisted config first
        Config.apply_saved_config()
        _config_instance = Config()
    return _config_instance

def set_config(**kwargs: Any) -> None:
    """Update runtime overrides for the global config.

    This replaces the previous ``set_config(config: Config)`` signature.
    It now accepts keyword arguments matching configuration names (e.g.,
    ``verbose=True``) and stores them via ``Config.set_runtime_overrides``.
    """
    Config.set_runtime_overrides(**kwargs)

