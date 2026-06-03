import asyncio
import time
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from itzraven.core.config import get_config
from itzraven.core.logger import get_logger
from itzraven.core.circuit_breaker import get_circuit_breaker_registry, CircuitBreakerConfig

logger = get_logger()

# ========================================================================
# Model Router — task difficulty → model mapping
# ========================================================================
MODEL_ROUTES = {
    "recon_dns_lookup":     {"model": "groq/llama3-8b",       "max_tokens": 300,  "reasoning": "none"},
    "recon_subdomain":      {"model": "groq/llama3-8b",       "max_tokens": 500,  "reasoning": "none"},
    "tech_fingerprint":     {"model": "groq/llama3-70b",      "max_tokens": 500,  "reasoning": "low"},
    "port_analysis":        {"model": "google/gemini-2.5-flash","max_tokens": 800,  "reasoning": "low"},
    "sqli_detection":       {"model": "openai/gpt-4o-mini",    "max_tokens": 1000, "reasoning": "medium"},
    "sqli_deep_analysis":   {"model": "anthropic/claude-sonnet-4", "max_tokens": 2000, "reasoning": "high"},
    "xss_detection":        {"model": "openai/gpt-4o-mini",    "max_tokens": 1000, "reasoning": "medium"},
    "ssrf_detection":       {"model": "openai/gpt-4o-mini",    "max_tokens": 1000, "reasoning": "medium"},
    "auth_analysis":        {"model": "anthropic/claude-sonnet-4", "max_tokens": 2000, "reasoning": "high"},
    "idor_detection":       {"model": "openai/gpt-4o-mini",    "max_tokens": 1000, "reasoning": "medium"},
    "command_injection":    {"model": "openai/gpt-4o-mini",    "max_tokens": 1000, "reasoning": "medium"},
    "poc_validation":       {"model": "openai/gpt-4o-mini",    "max_tokens": 800,  "reasoning": "low"},
    "remediation_gen":      {"model": "anthropic/claude-sonnet-4", "max_tokens": 1500, "reasoning": "high"},
    "report_summary":       {"model": "google/gemini-2.5-flash","max_tokens": 2000, "reasoning": "low"},
    "osint_analysis":       {"model": "google/gemini-2.5-flash","max_tokens": 1500, "reasoning": "low"},
    "ctf_solve":            {"model": "anthropic/claude-sonnet-4", "max_tokens": 3000, "reasoning": "high"},
    "exploit_gen":          {"model": "anthropic/claude-sonnet-4", "max_tokens": 2500, "reasoning": "high"},
    "vuln_dedup":           {"model": "openai/gpt-4o-mini",    "max_tokens": 200,  "reasoning": "low"},
    "default":              {"model": "openai/gpt-4o-mini",    "max_tokens": 1000, "reasoning": "medium"},
}

SCAN_DEPTH_PARAMS = {
    "quick":    {"max_tokens": 500,  "temperature": 0.3, "reasoning_effort": "low",   "route_prefix": "fast"},
    "standard": {"max_tokens": 1500, "temperature": 0.5, "reasoning_effort": "medium","route_prefix": "std"},
    "deep":     {"max_tokens": 3000, "temperature": 0.7, "reasoning_effort": "high",  "route_prefix": ""},
}

def get_route_for_task(task: str, scan_depth: str = "deep") -> dict:
    """Get model/config for a given task, tuned by scan depth."""
    params = SCAN_DEPTH_PARAMS.get(scan_depth, SCAN_DEPTH_PARAMS["deep"])
    route = MODEL_ROUTES.get(task, MODEL_ROUTES["default"]).copy()
    route["max_tokens"] = min(route["max_tokens"], params["max_tokens"])
    route["temperature"] = params["temperature"]
    if params["reasoning_effort"] not in ("none", None):
        route["reasoning"] = params["reasoning_effort"]
    else:
        route["reasoning"] = "none"
    return route
config = get_config()


class LLMProvider(Enum):
    LITELLM = "litellm"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    GROQ = "groq"
    MISTRAL = "mistral"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    OPENCODE = "opencode"
    DEEPSEEK = "deepseek"
    BLOCKRUN = "blockrun"
    CUSTOM = "custom"


@dataclass
class LLMResponse:
    content: str
    model: str
    tokens_used: int
    finish_reason: str
    provider: str = ""
    cost: float = 0.0
    latency_ms: float = 0.0


@dataclass
class LLMCallRecord:
    provider: str
    model: str
    tokens_in: int
    tokens_out: int
    cost: float
    latency_ms: float
    timestamp: float = field(default_factory=time.time)
    success: bool = True
    error: Optional[str] = None


RATES = {
    "openai/gpt-4o": {"in": 2.50, "out": 10.00},
    "openai/gpt-4o-mini": {"in": 0.15, "out": 0.60},
    "openai/gpt-4-turbo": {"in": 10.00, "out": 30.00},
    "anthropic/claude-3-opus": {"in": 15.00, "out": 75.00},
    "anthropic/claude-3-sonnet": {"in": 3.00, "out": 15.00},
    "anthropic/claude-3-haiku": {"in": 0.25, "out": 1.25},
    "anthropic/claude-sonnet-4": {"in": 3.00, "out": 15.00},
    "google/gemini-2.5-flash": {"in": 0.15, "out": 0.60},
    "google/gemini-2.0-flash": {"in": 0.10, "out": 0.40},
    "groq/llama3-70b": {"in": 0.59, "out": 0.79},
    "groq/llama3-8b": {"in": 0.05, "out": 0.10},
    "mistral/mistral-large": {"in": 2.00, "out": 6.00},
    "ollama/llama3": {"in": 0.0, "out": 0.0},
    "opencode/deepseek-v4-flash": {"in": 0.50, "out": 2.00},
    "opencode/deepseek-v4-flash-free": {"in": 0.0, "out": 0.0},
    "opencode/mimo-v2.5-free": {"in": 0.0, "out": 0.0},
    "deepseek/deepseek-v4-flash": {"in": 0.50, "out": 2.00},
    "deepseek-chat": {"in": 0.50, "out": 2.00},
    "blockrun/nvidia/deepseek-v4-flash": {"in": 0.0, "out": 0.0},
}


def estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    key = model.lower().rsplit("/", 1)[0] if "/" in model else model
    for k, v in RATES.items():
        if k in model.lower() or model.lower() in k:
            return (tokens_in / 1000 * v["in"]) + (tokens_out / 1000 * v["out"])
    return 0.0


class CostTracker:
    def __init__(self):
        self.records: List[LLMCallRecord] = []

    def record(self, provider: str, model: str, tokens_in: int, tokens_out: int, latency_ms: float, success: bool = True, error: Optional[str] = None) -> LLMCallRecord:
        cost = estimate_cost(f"{provider}/{model}", tokens_in, tokens_out)
        rec = LLMCallRecord(provider=provider, model=model, tokens_in=tokens_in, tokens_out=tokens_out, cost=cost, latency_ms=latency_ms, success=success, error=error)
        self.records.append(rec)
        return rec

    @property
    def total_cost(self) -> float:
        return sum(r.cost for r in self.records if r.success)

    @property
    def total_tokens(self) -> int:
        return sum(r.tokens_in + r.tokens_out for r in self.records if r.success)

    def get_summary(self) -> Dict[str, Any]:
        if not self.records:
            return {"total_cost": 0.0, "total_tokens": 0, "call_count": 0, "calls": []}
        return {
            "total_cost": round(self.total_cost, 4),
            "total_tokens": self.total_tokens,
            "call_count": len([r for r in self.records if r.success]),
            "calls": [
                {
                    "provider": r.provider,
                    "model": r.model,
                    "tokens_in": r.tokens_in,
                    "tokens_out": r.tokens_out,
                    "cost": round(r.cost, 6),
                    "latency_ms": round(r.latency_ms, 1),
                    "success": r.success,
                }
                for r in self.records[-50:]
            ],
        }


_cost_tracker: Optional[CostTracker] = None

def get_cost_tracker() -> CostTracker:
    global _cost_tracker
    if _cost_tracker is None:
        _cost_tracker = CostTracker()
    return _cost_tracker


class LLMClient:
    SUPPORTED_PROVIDERS = {
        "openai": LLMProvider.OPENAI,
        "anthropic": LLMProvider.ANTHROPIC,
        "claude": LLMProvider.ANTHROPIC,
        "google": LLMProvider.GOOGLE,
        "gemini": LLMProvider.GOOGLE,
        "groq": LLMProvider.GROQ,
        "mistral": LLMProvider.MISTRAL,
        "ollama": LLMProvider.OLLAMA,
        "lm_studio": LLMProvider.LM_STUDIO,
        "local": LLMProvider.OLLAMA,
        "opencode": LLMProvider.OPENCODE,
        "deepseek": LLMProvider.DEEPSEEK,
        "blockrun": LLMProvider.BLOCKRUN,
    }

    def __init__(self):
        self.config = config
        self.litellm_available = False
        self._provider_cache: Optional[str] = None

        strix_llm = (self.config.get("strix_llm") or "").strip()
        if strix_llm:
            self._provider_cache = strix_llm
            logger.info(f"LLM configured: {strix_llm}")

        try:
            import litellm
            self.litellm = litellm
            self.litellm_available = True
            self.litellm.drop_params = True
            logger.info("LiteLLM available — multi-provider support enabled")
        except ImportError:
            self.litellm = None
            logger.warning("LiteLLM not installed. Only direct OpenAI/Anthropic SDK will work.")

        self._legacy_openai = None
        self._legacy_anthropic = None
        self._init_legacy_clients()

        opencode_key = self.config.get("opencode_api_key")
        if opencode_key:
            logger.info("OpenCode API key detected — DeepSeek v4 Flash available")

    def _init_legacy_clients(self):
        openai_key = self.config.get("openai_api_key") or self.config.get("opencode_api_key")
        if openai_key:
            try:
                from openai import AsyncOpenAI
                base_url = self.config.get("opencode_api_base") or "https://opencode.ai/zen/v1"
                is_opencode = bool(self.config.get("opencode_api_key"))
                self._legacy_openai = AsyncOpenAI(
                    api_key=openai_key,
                    base_url=base_url if is_opencode else None,
                )
            except ImportError:
                pass
        api_key = self.config.get("anthropic_api_key")
        if api_key:
            try:
                from anthropic import AsyncAnthropic
                self._legacy_anthropic = AsyncAnthropic(api_key=api_key)
            except ImportError:
                pass

    @property
    def model(self) -> str:
        cached = self._provider_cache
        if cached:
            return cached
        return self.config.get("ai_model") or "gpt-4o"

    @property
    def api_key(self) -> Optional[str]:
        m = self.model.lower()
        if "blockrun" in m:
            return None
        if "opencode" in m or "deepseek" in m:
            val = self.config.get("opencode_api_key")
            if val:
                return val
        for key in ["llm_api_key", "openai_api_key", "anthropic_api_key"]:
            val = self.config.get(key)
            if val:
                return val
        return None

    @property
    def provider_name(self) -> str:
        m = self.model.lower()
        for name in self.SUPPORTED_PROVIDERS:
            if name in m:
                return name
        return "openai"

    def _get_litellm_kwargs(self) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {}
        api_key = self.api_key
        if api_key:
            kwargs["api_key"] = api_key

        m = self.model.lower()
        if "blockrun" in m:
            api_base = self.config.get("blockrun_api_base")
            if not api_base:
                api_base = "https://blockrun.ai/api/v1"
            kwargs["custom_llm_provider"] = "openai"
        elif "opencode" in m:
            api_base = self.config.get("opencode_api_base")
            if not api_base:
                api_base = "https://opencode.ai/zen/v1"
            kwargs["custom_llm_provider"] = "openai"
        elif "deepseek" in m:
            api_base = self.config.get("deepseek_api_base")
            if not api_base:
                api_base = "https://api.deepseek.com/v1"
        else:
            api_base = self.config.get("llm_api_base")
        if api_base:
            kwargs["api_base"] = api_base
        reasoning = self.config.get("strix_reasoning_effort")
        if reasoning and reasoning != "none":
            kwargs["reasoning_effort"] = reasoning
        max_retries = self.config.get("strix_llm_max_retries")
        if max_retries:
            kwargs["num_retries"] = int(max_retries)
        timeout = self.config.get("llm_timeout")
        if timeout:
            kwargs["timeout"] = int(timeout)
        return kwargs

    def _get_circuit_breaker(self, model: str) -> Any:
        registry = get_circuit_breaker_registry()
        provider = self.provider_name
        cb_name = f"llm:{provider}:{model}"
        return registry.get(cb_name, CircuitBreakerConfig(
            failure_threshold=config.get("circuit_breaker_failure_threshold") or 5,
            recovery_timeout=config.get("circuit_breaker_recovery_timeout") or 30.0,
        ))

    async def generate(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2000, model: Optional[str] = None, temperature: float = 0.7, task: Optional[str] = None) -> LLMResponse:
        start = time.time()
        used_model = model or self.model

        # Check cache
        try:
            from itzraven.core.llm_cache import _cache as llm_cache
            cached = llm_cache.get(prompt, system, used_model)
            if cached:
                resp = LLMResponse(content=cached, model=used_model, tokens_used=0, finish_reason="cached", provider="cache", latency_ms=(time.time() - start) * 1000)
                return resp
        except Exception:
            pass

        # Circuit breaker wraps the actual generation
        cb = self._get_circuit_breaker(used_model)

        async def _do_generate():
            if self.litellm_available:
                return await self._generate_litellm(prompt, system, max_tokens, used_model, temperature, start)
            return await self._generate_legacy(prompt, system, max_tokens, used_model, temperature, start)

        resp = await cb.call(_do_generate)

        # Store in cache
        try:
            from itzraven.core.llm_cache import _cache as llm_cache
            llm_cache.set(prompt, resp.content, system, used_model)
        except Exception:
            pass

        # Record LLM call in learning engine for future routing decisions
        if task:
            try:
                from itzraven.core.learning_engine import get_learning_engine
                le = get_learning_engine()
                le.record_llm_call(
                    task=task,
                    model=used_model,
                    tokens_used=resp.tokens_used,
                    success=resp.finish_reason not in ("error", "cancelled"),
                    latency_ms=resp.latency_ms,
                    cost=resp.cost,
                )
            except Exception:
                pass

        return resp

    async def generate_with_fallback(self, prompt: str, system: Optional[str] = None, max_tokens: int = 2000, models: Optional[List[str]] = None, temperature: float = 0.7) -> LLMResponse:
        fallbacks = models or [self.model, "gpt-4o-mini", "claude-3-haiku-20240307"]
        errors = []
        for fb_model in fallbacks:
            try:
                return await self.generate(prompt, system, max_tokens, fb_model, temperature)
            except Exception as e:
                errors.append(f"{fb_model}: {e}")
                logger.warning(f"Fallback model {fb_model} failed: {e}")
                continue
        raise RuntimeError(f"All {len(fallbacks)} fallback models failed. Errors: {errors}")

    async def _generate_litellm(self, prompt: str, system: Optional[str], max_tokens: int, model: str, temperature: float, start: float) -> LLMResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs = self._get_litellm_kwargs()
        # Normalize opencode/ → openai/ for LiteLLM (OpenCode is OpenAI-compatible)
        litellm_model = model
        if litellm_model.startswith("blockrun/"):
            litellm_model = "openai/" + litellm_model[len("blockrun/"):]
        if litellm_model.startswith("opencode/"):
            litellm_model = "openai/" + litellm_model[len("opencode/"):]
        kwargs["model"] = litellm_model
        kwargs["messages"] = messages
        kwargs["max_tokens"] = max_tokens
        kwargs["temperature"] = temperature

        try:
            response = await self.litellm.acompletion(**kwargs)
            latency = (time.time() - start) * 1000
            choice = response.choices[0]
            usage = getattr(response, "usage", None)
            tokens_in = getattr(usage, "prompt_tokens", 0) if usage else 0
            tokens_out = getattr(usage, "completion_tokens", 0) if usage else 0
            total_tokens = getattr(usage, "total_tokens", 0) if usage else (tokens_in + tokens_out)
            provider = self.provider_name

            get_cost_tracker().record(provider, model, tokens_in, tokens_out, latency)

            msg = choice.message
            reply = msg.content or getattr(msg, "reasoning_content", "") or ""
            return LLMResponse(
                content=reply,
                model=getattr(response, "model", model),
                tokens_used=total_tokens,
                finish_reason=getattr(choice, "finish_reason", "") or "",
                provider=provider,
                cost=estimate_cost(f"{provider}/{model}", tokens_in, tokens_out),
                latency_ms=latency,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            get_cost_tracker().record(self.provider_name, model, 0, 0, latency, success=False, error=str(e))
            raise

    async def _generate_legacy(self, prompt: str, system: Optional[str], max_tokens: int, model: str, temperature: float, start: float) -> LLMResponse:
        model_lower = model.lower()

        if "claude" in model_lower and self._legacy_anthropic:
            response = await self._legacy_anthropic.messages.create(
                model=model, max_tokens=max_tokens, system=system or "",
                messages=[{"role": "user", "content": prompt}],
            )
            latency = (time.time() - start) * 1000
            tokens_in = getattr(response.usage, "input_tokens", 0)
            tokens_out = getattr(response.usage, "output_tokens", 0)
            get_cost_tracker().record("anthropic", model, tokens_in, tokens_out, latency)
            return LLMResponse(
                content=response.content[0].text,
                model=getattr(response, "model", model),
                tokens_used=tokens_in + tokens_out,
                finish_reason=getattr(response, "stop_reason", ""),
                provider="anthropic",
                cost=estimate_cost(f"anthropic/{model}", tokens_in, tokens_out),
                latency_ms=latency,
            )

        if self._legacy_openai:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            api_model = model.split("/", 1)[-1] if "/" in model else model
            response = await self._legacy_openai.chat.completions.create(
                model=api_model, messages=messages, max_tokens=max_tokens, temperature=temperature,
            )
            latency = (time.time() - start) * 1000
            usage = getattr(response, "usage", None)
            tokens_in = getattr(usage, "prompt_tokens", 0) if usage else 0
            tokens_out = getattr(usage, "completion_tokens", 0) if usage else 0
            get_cost_tracker().record("openai", model, tokens_in, tokens_out, latency)
            msg = response.choices[0].message
            reply = msg.content or getattr(msg, "reasoning_content", "") or ""
            return LLMResponse(
                content=reply,
                model=getattr(response, "model", model),
                tokens_used=tokens_in + tokens_out,
                finish_reason=getattr(response.choices[0], "finish_reason", ""),
                provider="openai",
                cost=estimate_cost(f"openai/{model}", tokens_in, tokens_out),
                latency_ms=latency,
            )

        raise RuntimeError("No LLM provider available. Configure an API key.")

    async def analyze_vulnerability(self, target: str, context: str) -> Dict[str, Any]:
        system = (
            "You are a security expert analyzing potential vulnerabilities.\n"
            "Provide detailed analysis including:\n"
            "1. Vulnerability type\n2. Severity (critical/high/medium/low)\n"
            "3. Exploitation steps\n4. Proof of concept\n5. Remediation advice"
        )
        prompt = f"Target: {target}\nContext: {context}\n\nAnalyze this for security vulnerabilities and provide a structured response."
        response = await self.generate(prompt, system)
        return {"analysis": response.content, "model": response.model, "tokens": response.tokens_used}

    async def generate_exploit(self, vulnerability: str, target: str) -> str:
        system = "You are a security researcher generating proof-of-concept exploit code for authorized testing."
        prompt = f"Generate a Python exploit for:\nVulnerability: {vulnerability}\nTarget: {target}\n\nProvide clean, commented Python code."
        response = await self.generate(prompt, system, max_tokens=2500)
        return response.content

    # ========================================================================
    # Structured Output — Pydantic schema enforcement
    # ========================================================================
    async def generate_structured(self, prompt: str, schema: Any, system: Optional[str] = None,
                                   model: Optional[str] = None, scan_depth: str = "deep") -> Any:
        """Generate LLM response and parse into a Pydantic model.

        Args:
            prompt: The prompt to send
            schema: A Pydantic BaseModel class
            system: Optional system prompt
            model: Optional model override (uses router if not specified)
            scan_depth: Scan depth for token/reasoning tuning

        Returns:
            An instance of the schema class
        """
        task_name = getattr(schema, "__task_name__", "default")
        route = get_route_for_task(task_name, scan_depth)
        used_model = model or route["model"]

        struct_system = (
            f"{system or ''}\n\n"
            f"You MUST respond with valid JSON only (no markdown fences, no explanations).\n"
            f"The JSON must conform to this schema:\n"
            f"{schema.model_json_schema()}"
        ).strip()

        struct_prompt = (
            f"{prompt}\n\n"
            f"Respond with a JSON object matching the schema above."
        )

        resp = await self.generate(
            prompt=struct_prompt,
            system=struct_system,
            max_tokens=route["max_tokens"],
            model=used_model,
            temperature=route["temperature"],
        )

        try:
            from itzraven.core.json_utils import extract_json
            parsed = extract_json(resp.content) or {}
            if isinstance(parsed, dict):
                return schema(**parsed)
            return schema()
        except Exception as e:
            logger.warning(f"Structured output parse failed for {schema.__name__}: {e}")
            logger.debug(f"Raw response: {resp.content[:500]}")
            return schema()

    # ========================================================================
    # Speculative Decoding — parallel hypothesis generation
    # ========================================================================
    async def generate_with_speculative_decode(
        self,
        prompt: str,
        system: Optional[str] = None,
        task: str = "default",
        scan_depth: str = "deep",
        num_candidates: int = 3,
        validator: Optional[Callable] = None,
    ) -> LLMResponse:
        """Generate multiple candidate responses in parallel, pick the best.

        Uses multiple temperatures for diverse hypotheses, then validates
        and picks the best (first valid by default, or via custom validator).

        Args:
            prompt: The prompt
            system: Optional system prompt
            task: Task name for model routing
            scan_depth: Scan depth
            num_candidates: Number of parallel candidates (1-5)
            validator: Optional async callable(response) -> bool
                      If None, picks the fastest valid response.

        Returns:
            Best LLMResponse
        """
        route = get_route_for_task(task, scan_depth)
        temperatures = [0.1, 0.3, 0.5, 0.7, 0.9][:num_candidates]
        models = [route["model"]] * num_candidates

        async def try_candidate(temp: float, mod: str) -> Optional[LLMResponse]:
            try:
                return await self.generate(
                    prompt=prompt,
                    system=system,
                    max_tokens=route["max_tokens"],
                    model=mod,
                    temperature=temp,
                )
            except Exception as e:
                logger.debug(f"Speculative candidate failed (t={temp}, model={mod}): {e}")
                return None

        tasks = [try_candidate(t, m) for t, m in zip(temperatures, models)]
        results = await asyncio.gather(*tasks)

        valid = [r for r in results if r is not None]
        if not valid:
            raise RuntimeError("All speculative decode candidates failed")

        if validator is not None:
            for r in valid:
                try:
                    if await validator(r.content):
                        return r
                except Exception:
                    continue
            return valid[0]

        return min(valid, key=lambda r: r.latency_ms)

    # ========================================================================
    # Batch LLM Processing — group similar prompts into one call
    # ========================================================================
    async def generate_batch(
        self,
        prompts: List[str],
        system: Optional[str] = None,
        task: str = "default",
        scan_depth: str = "deep",
        items_per_call: int = 10,
    ) -> List[str]:
        """Process multiple prompts in batched LLM calls.

        Groups prompts and sends them in batches to reduce API overhead.
        Each batch asks the LLM to process all items at once.

        Args:
            prompts: List of individual prompts to process
            system: System prompt
            task: Task name for routing
            scan_depth: Scan depth
            items_per_call: Max items per batched call

        Returns:
            List of responses, one per input prompt
        """
        if not prompts:
            return []

        route = get_route_for_task(task, scan_depth)

        batches = [prompts[i:i + items_per_call] for i in range(0, len(prompts), items_per_call)]
        results = []

        for batch in batches:
            batch_prompt = (
                f"Process the following {len(batch)} items. "
                f"For EACH item, provide a brief analysis on a separate line starting with 'ITEM<N>:'.\n\n"
            )
            for idx, p in enumerate(batch):
                batch_prompt += f"ITEM{idx + 1}: {p}\n"

            resp = await self.generate(
                prompt=batch_prompt,
                system=system,
                max_tokens=route["max_tokens"] * len(batch),
                model=route["model"],
                temperature=route["temperature"],
            )

            parsed = self._parse_batch_response(resp.content, len(batch))
            results.extend(parsed)

        return results

    @staticmethod
    def _parse_batch_response(content: str, expected_count: int) -> List[str]:
        """Parse batched response into individual items."""
        items = []
        for i in range(1, expected_count + 1):
            pattern = rf"ITEM{i}\s*:\s*(.*?)(?=\nITEM{i + 1}|\Z)"
            match = re.search(pattern, content, re.DOTALL)
            if match:
                items.append(match.group(1).strip())
            else:
                lines = content.split("\n")
                for line in lines:
                    if line.strip().startswith(f"ITEM{i}:"):
                        items.append(line.split(":", 1)[1].strip())
                        break
                else:
                    items.append("")
        return items

    # ========================================================================
    # Mixture of Agents (MoA) — small model ensemble + aggregator
    # ========================================================================
    MOA_ENSEMBLE_MODELS = [
        "groq/llama3-8b",
        "groq/llama3-8b",
        "groq/llama3-8b",
    ]

    MOA_AGGREGATOR_MODEL = "anthropic/claude-sonnet-4"

    async def generate_with_moa(
        self,
        prompt: str,
        system: Optional[str] = None,
        task: str = "default",
        scan_depth: str = "deep",
        ensemble_models: Optional[List[str]] = None,
        aggregator_model: Optional[str] = None,
    ) -> LLMResponse:
        """Mixture of Agents — runs small models in parallel, then aggregates.

        Architecture:
            Input → [small_model_1, small_model_2, small_model_3] (parallel)
                    ↓
                    Aggregator (large model) produces final response

        This is cheaper than using a single large model for everything,
        while maintaining quality through ensemble + aggregation.

        Args:
            prompt: The prompt
            system: System prompt
            task: Task name
            scan_depth: Scan depth
            ensemble_models: List of small models to use (default: 3x llama3-8b)
            aggregator_model: Large model for final aggregation

        Returns:
            Aggregated LLMResponse
        """
        route = get_route_for_task(task, scan_depth)
        ensemble = ensemble_models or self.MOA_ENSEMBLE_MODELS
        aggregator = aggregator_model or self.MOA_AGGREGATOR_MODEL

        start = time.time()

        async def run_ensemble(model: str) -> Optional[str]:
            try:
                resp = await self.generate(
                    prompt=prompt,
                    system=system,
                    max_tokens=route["max_tokens"],
                    model=model,
                    temperature=0.5,
                )
                return resp.content
            except Exception as e:
                logger.debug(f"MoA ensemble member {model} failed: {e}")
                return None

        ensemble_tasks = [run_ensemble(m) for m in ensemble]
        ensemble_responses = await asyncio.gather(*ensemble_tasks)
        valid_responses = [r for r in ensemble_responses if r is not None]

        if not valid_responses:
            logger.warning("MoA: all ensemble members failed, falling back to single model")
            return await self.generate(prompt, system, max_tokens=route["max_tokens"],
                                        model=route["model"], temperature=route["temperature"])

        if len(valid_responses) == 1:
            return LLMResponse(
                content=valid_responses[0],
                model=ensemble[0],
                tokens_used=0,
                finish_reason="moa_single",
                provider="moa",
                cost=0.0,
                latency_ms=(time.time() - start) * 1000,
            )

        # Aggregator: combine diverse responses into one
        aggregation_prompt = (
            f"You are a senior security analyst reviewing multiple analysis reports.\n\n"
            f"Original question:\n{prompt}\n\n"
            f"Here are {len(valid_responses)} independent analyses:\n\n"
        )
        for i, resp_text in enumerate(valid_responses, 1):
            aggregation_prompt += f"--- Analysis {i} ---\n{resp_text}\n\n"

        aggregation_prompt += (
            "Synthesize these analyses into a single comprehensive, accurate response. "
            "Resolve any contradictions, highlight the most important findings, "
            "and provide a clear final assessment."
        )

        try:
            final = await self.generate(
                prompt=aggregation_prompt,
                system=system,
                max_tokens=route["max_tokens"] * 2,
                model=aggregator,
                temperature=0.3,
            )
            final.model = f"moa({','.join(ensemble)})→{aggregator}"
            final.provider = "moa"
            final.latency_ms = (time.time() - start) * 1000
            return final
        except Exception as e:
            logger.warning(f"MoA aggregator failed: {e}, returning first ensemble response")
            return LLMResponse(
                content=valid_responses[0],
                model=ensemble[0],
                tokens_used=0,
                finish_reason="moa_fallback",
                provider="moa",
                cost=0.0,
                latency_ms=(time.time() - start) * 1000,
            )
