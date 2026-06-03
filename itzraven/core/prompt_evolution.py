"""
Autonomous Prompt Evolution — LLM apne prompts/skills ko dynamically improve kare.
Past scan failures se seekh kar better prompts banaye.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient

logger = get_logger()

EVOLUTION_STORE = Path.home() / ".itzraven" / "prompt_evolution.json"


@dataclass
class PromptVersion:
    prompt_text: str
    system_prompt: str
    technique: str
    target_tech: str
    success_rate: float = 0.0
    attempts: int = 0
    successes: int = 0
    avg_latency_ms: float = 0.0
    created_at: float = field(default_factory=time.time)
    parent_hash: str = ""
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            raw = f"{self.prompt_text}:{self.system_prompt}:{self.technique}:{time.time()}"
            self.hash = hashlib.md5(raw.encode()).hexdigest()[:12]

    def record_result(self, success: bool, latency_ms: float):
        self.attempts += 1
        if success:
            self.successes += 1
        self.success_rate = self.successes / max(self.attempts, 1)
        self.avg_latency_ms = (self.avg_latency_ms * (self.attempts - 1) + latency_ms) / max(self.attempts, 1)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "target_tech": self.target_tech,
            "success_rate": self.success_rate,
            "attempts": self.attempts,
            "avg_latency_ms": self.avg_latency_ms,
            "hash": self.hash,
            "parent_hash": self.parent_hash,
        }


class PromptEvolutionEngine:
    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self._versions: Dict[str, List[PromptVersion]] = {}
        self._active_prompts: Dict[str, PromptVersion] = {}
        self._load()

    @classmethod
    def get_instance(cls) -> "PromptEvolutionEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_prompt(self, technique: str, target_tech: str) -> Optional[PromptVersion]:
        key = f"{technique}:{target_tech}"
        return self._active_prompts.get(key)

    async def evolve_prompt(self, technique: str, target_tech: str,
                            failure_context: str) -> Optional[PromptVersion]:
        key = f"{technique}:{target_tech}"
        current = self._active_prompts.get(key)

        prompt = (
            f"I am a security AI. My current prompt for '{technique}' on '{target_tech}' "
            f"is not working well.\n\n"
            f"Context of failures:\n{failure_context[:1000]}\n\n"
            f"Current prompt:\n{current.prompt_text if current else 'None'}\n\n"
            "Generate a BETTER prompt that will produce more effective results. "
            "Consider:\n"
            "1. What payloads to try first\n"
            "2. What indicators to look for\n"
            "3. What bypass techniques to use\n"
            "4. What alternative approaches exist\n\n"
            "Output JSON: {\"prompt\": \"improved prompt text\", "
            "\"system\": \"improved system prompt\", "
            "\"reasoning\": \"why this is better\"}"
        )
        system = "You are a prompt engineering expert optimizing security testing prompts."

        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=1000, task="evolve_prompt")
            parsed = json.loads(resp.content) if isinstance(resp.content, dict) else json.loads(resp.content)
        except Exception as e:
            logger.debug(f"Prompt evolution failed: {e}")
            return None

        new_version = PromptVersion(
            prompt_text=parsed.get("prompt", current.prompt_text if current else ""),
            system_prompt=parsed.get("system", current.system_prompt if current else ""),
            technique=technique,
            target_tech=target_tech,
            parent_hash=current.hash if current else "",
        )
        if key not in self._versions:
            self._versions[key] = []
        self._versions[key].append(new_version)
        self._active_prompts[key] = new_version
        self._save()

        logger.info(f"Prompt evolved for {technique} on {target_tech}: "
                    f"v{len(self._versions[key])} (reason: {parsed.get('reasoning', 'N/A')[:100]})")
        return new_version

    def record_result(self, technique: str, target_tech: str, success: bool, latency_ms: float):
        key = f"{technique}:{target_tech}"
        current = self._active_prompts.get(key)
        if current:
            current.record_result(success, latency_ms)

    def should_evolve(self, technique: str, target_tech: str, threshold: float = 0.3) -> bool:
        key = f"{technique}:{target_tech}"
        current = self._active_prompts.get(key)
        if not current:
            return True
        return current.attempts >= 3 and current.success_rate < threshold

    def get_stats(self) -> dict:
        return {
            "total_prompts": sum(len(v) for v in self._versions.values()),
            "active_prompts": len(self._active_prompts),
            "techniques": list(self._active_prompts.keys()),
            "versions_per_technique": {k: len(v) for k, v in self._versions.items()},
        }

    def _save(self):
        EVOLUTION_STORE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "versions": {
                k: [{"hash": v.hash, "parent_hash": v.parent_hash, "technique": v.technique,
                     "target_tech": v.target_tech, "attempts": v.attempts, "successes": v.successes,
                     "success_rate": v.success_rate}
                    for v in versions]
                for k, versions in self._versions.items()
            },
            "active": {k: v.hash for k, v in self._active_prompts.items()},
        }
        EVOLUTION_STORE.write_text(json.dumps(data, indent=2))

    def _load(self):
        try:
            if EVOLUTION_STORE.exists():
                data = json.loads(EVOLUTION_STORE.read_text())
                logger.info(f"Loaded {sum(len(v) for v in data.get('versions', {}).values())} prompt versions")
        except Exception:
            pass


get_prompt_evolution = PromptEvolutionEngine.get_instance
