from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

from dotenv import load_dotenv

load_dotenv()


class ItzravenSettings(BaseSettings):
    model_config = {
        "env_prefix": "",
        "case_sensitive": False,
        "extra": "ignore",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "frozen": False,
    }

    strix_llm: Optional[str] = Field(None, description="LLM model string (e.g. openai/gpt-4o)")
    llm_api_key: Optional[str] = Field(None, description="LLM API key")
    llm_api_base: Optional[str] = Field(None, description="LLM API base URL")
    llm_timeout: int = Field(300, ge=1, le=3600, description="LLM request timeout in seconds")
    strix_llm_max_retries: int = Field(5, ge=0, le=20)
    strix_reasoning_effort: str = Field("high", pattern="^(none|low|medium|high)$")

    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ai_model: str = Field("opencode/deepseek-v4-flash-free", description="AI model name")

    max_concurrent_agents: int = Field(5, ge=1, le=100, description="Max parallel agents")
    request_timeout: int = Field(30, ge=1, le=300)
    max_retries: int = Field(3, ge=0, le=20)

    headless_browser: bool = True
    browser_timeout: int = Field(30000, ge=1000, le=300000)

    output_dir: Path = Field(Path("./itzraven_results"), description="Output directory for reports")
    verbose: bool = False
    debug: bool = False

    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None

    requests_per_second: int = Field(10, ge=1, le=1000)
    burst_size: int = Field(20, ge=1, le=1000)

    use_docker: bool = False
    docker_image: str = "itzraven-security/sandbox:latest"

    litellm_model: Optional[str] = None
    litellm_api_base: Optional[str] = None
    litellm_max_tokens: int = Field(4096, ge=256, le=128000)
    litellm_fallbacks: str = "gpt-4o-mini,claude-3-haiku-20240307"

    google_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    mistral_api_key: Optional[str] = None

    perplexity_api_key: Optional[str] = None
    strix_disable_browser: bool = False

    opencode_api_key: Optional[str] = None
    opencode_api_base: str = "https://api.opencode.ai/v1"

    http_max_connections: int = Field(100, ge=10, le=1000, description="HTTP connection pool size")
    http_max_keepalive: int = Field(20, ge=5, le=200)
    http_timeout: float = Field(30.0, ge=1.0, le=120.0)

    circuit_breaker_failure_threshold: int = Field(5, ge=1, le=50)
    circuit_breaker_recovery_timeout: float = Field(30.0, ge=1.0, le=300.0)

    bloom_filter_capacity: int = Field(100_000, ge=1000, le=1_000_000)

    monitor_enabled: bool = Field(False, description="Enable continuous monitoring")
    monitor_interval_hours: float = Field(24.0, ge=0.5, le=720.0)

    def to_dict(self, exclude_secrets: bool = True) -> Dict[str, Any]:
        data = self.model_dump()
        if exclude_secrets:
            for key in list(data.keys()):
                if "api_key" in key or "key" in key or "token" in key or "secret" in key:
                    if data[key] is not None:
                        data[key] = "***"
        return data

    @field_validator("output_dir", mode="before")
    @classmethod
    def validate_output_dir(cls, v):
        if isinstance(v, str):
            return Path(v)
        return v
