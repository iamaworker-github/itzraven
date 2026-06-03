"""
Cross-Session Learning Engine — XBOW-inspired findings intelligence pipeline.

Tracks:
1. Technique effectiveness per technology
2. Tool reliability scores
3. WAF/EDR bypass patterns
4. False positive trending
5. Technique chaining success rates
6. Cross-session vulnerability rediscovery rates
7. Attack path success prediction

All data persisted to ~/.itzraven/learned_patterns.jsonl
"""

import json
import time
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from statistics import mean

from itzraven.core.logger import get_logger

logger = get_logger()

LEARNED_PATTERNS_PATH = Path.home() / ".itzraven" / "learned_patterns.jsonl"
LLM_PERFORMANCE_PATH = Path.home() / ".itzraven" / "llm_performance.jsonl"
CHAIN_PERFORMANCE_PATH = Path.home() / ".itzraven" / "chain_performance.jsonl"


@dataclass
class TechniqueRecord:
    technique: str
    target_tech: str
    attempts: int = 0
    successes: int = 0
    false_positives: int = 0
    avg_execution_time: float = 0.0
    last_used: float = 0.0
    tags: List[str] = field(default_factory=list)
    chain_success_count: int = 0
    chain_attempts: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / max(self.attempts, 1)

    @property
    def reliability(self) -> float:
        tp = self.successes - self.false_positives
        return max(0, tp / max(self.attempts, 1))

    @property
    def chain_success_rate(self) -> float:
        return self.chain_success_count / max(self.chain_attempts, 1)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "target_tech": self.target_tech,
            "attempts": self.attempts,
            "successes": self.successes,
            "false_positives": self.false_positives,
            "success_rate": round(self.success_rate, 3),
            "reliability": round(self.reliability, 3),
            "avg_execution_time": round(self.avg_execution_time, 2),
            "last_used": self.last_used,
            "chain_success_rate": round(self.chain_success_rate, 3),
        }


@dataclass
class ToolRecord:
    tool_name: str
    runs: int = 0
    findings_found: int = 0
    false_positives: int = 0
    avg_run_time: float = 0.0
    last_used: float = 0.0

    @property
    def tp_rate(self) -> float:
        return max(0, (self.findings_found - self.false_positives)) / max(self.runs, 1)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "runs": self.runs,
            "findings_found": self.findings_found,
            "false_positives": self.false_positives,
            "tp_rate": round(self.tp_rate, 3),
            "avg_run_time": round(self.avg_run_time, 2),
        }


@dataclass
class LLMRecord:
    task: str
    model: str
    tokens_used: int
    success: bool
    latency_ms: float
    cost: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class AttackPathRecord:
    chain_name: str
    target: str
    steps_attempted: int
    steps_succeeded: int
    total_duration: float
    findings_produced: int
    success: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "chain_name": self.chain_name,
            "target": self.target,
            "steps_attempted": self.steps_attempted,
            "steps_succeeded": self.steps_succeeded,
            "total_duration": round(self.total_duration, 2),
            "findings_produced": self.findings_produced,
            "success": self.success,
            "timestamp": self.timestamp,
        }


class LearningEngine:
    def __init__(self):
        self._techniques: Dict[str, TechniqueRecord] = {}
        self._tools: Dict[str, ToolRecord] = {}
        self._bypass_patterns: Dict[str, List[str]] = defaultdict(list)
        self._false_positive_patterns: Dict[str, int] = defaultdict(int)
        self._llm_performance: Dict[str, List[LLMRecord]] = defaultdict(list)
        self._attack_paths: List[AttackPathRecord] = []
        self._chain_stats: Dict[str, Dict[str, float]] = defaultdict(lambda: {"success": 0, "total": 0})
        self._load()

    def record_technique(self, technique: str, target_tech: str,
                         success: bool, execution_time: float = 0.0,
                         tags: Optional[List[str]] = None):
        key = f"{technique}:{target_tech}"
        if key not in self._techniques:
            self._techniques[key] = TechniqueRecord(technique=technique, target_tech=target_tech)
        rec = self._techniques[key]
        rec.attempts += 1
        if success:
            rec.successes += 1
        rec.avg_execution_time = (rec.avg_execution_time * (rec.attempts - 1) + execution_time) / rec.attempts
        rec.last_used = time.time()
        if tags:
            rec.tags.extend(t for t in tags if t not in rec.tags)

    def record_false_positive(self, technique: str, target_tech: str):
        key = f"{technique}:{target_tech}"
        if key in self._techniques:
            self._techniques[key].false_positives += 1
        self._false_positive_patterns[f"{technique} on {target_tech}"] += 1

    def record_tool_run(self, tool_name: str, findings_count: int,
                        false_positives: int = 0, run_time: float = 0.0):
        if tool_name not in self._tools:
            self._tools[tool_name] = ToolRecord(tool_name=tool_name)
        rec = self._tools[tool_name]
        rec.runs += 1
        rec.findings_found += findings_count
        rec.false_positives += false_positives
        rec.avg_run_time = (rec.avg_run_time * (rec.runs - 1) + run_time) / rec.runs
        rec.last_used = time.time()

    def record_bypass(self, waf: str, technique: str, payload: str):
        self._bypass_patterns[f"{waf}:{technique}"].append(payload)

    def record_attack_path(self, chain_name: str, target: str,
                           steps_attempted: int, steps_succeeded: int,
                           total_duration: float, findings_produced: int,
                           success: bool):
        record = AttackPathRecord(
            chain_name=chain_name,
            target=target,
            steps_attempted=steps_attempted,
            steps_succeeded=steps_succeeded,
            total_duration=total_duration,
            findings_produced=findings_produced,
            success=success,
        )
        self._attack_paths.append(record)
        self._chain_stats[chain_name]["success"] += 1 if success else 0
        self._chain_stats[chain_name]["total"] += 1

    def predict_chain_success(self, chain_name: str, steps_completed: int) -> float:
        stats = self._chain_stats.get(chain_name, {"success": 0, "total": 0})
        base_rate = stats["success"] / max(stats["total"], 1)
        progress_bonus = steps_completed / 10.0
        return min(1.0, base_rate + progress_bonus)

    def get_technique_reliability(self, technique: str, target_tech: str) -> float:
        key = f"{technique}:{target_tech}"
        rec = self._techniques.get(key)
        return rec.reliability if rec else 0.5

    def get_tool_reliability(self, tool_name: str) -> float:
        rec = self._tools.get(tool_name)
        return rec.tp_rate if rec else 0.5

    def get_best_technique(self, target_tech: str) -> Optional[dict]:
        candidates = [(k, v) for k, v in self._techniques.items() if v.target_tech == target_tech]
        if not candidates:
            return None
        best = max(candidates, key=lambda kv: kv[1].reliability)
        return best[1].to_dict()

    def should_skip(self, technique: str, target_tech: str, min_reliability: float = 0.1) -> bool:
        key = f"{technique}:{target_tech}"
        rec = self._techniques.get(key)
        if rec and rec.attempts >= 3 and rec.reliability < min_reliability:
            return True
        return False

    def get_bypass_suggestions(self, waf: str, technique: str) -> List[str]:
        return self._bypass_patterns.get(f"{waf}:{technique}", [])

    def get_hot_techniques(self, min_reliability: float = 0.7, limit: int = 5) -> List[dict]:
        candidates = [v.to_dict() for v in self._techniques.values()
                      if v.reliability >= min_reliability and v.attempts >= 2]
        candidates.sort(key=lambda x: x["success_rate"], reverse=True)
        return candidates[:limit]

    def get_cold_techniques(self, max_reliability: float = 0.3, limit: int = 5) -> List[dict]:
        candidates = [v.to_dict() for v in self._techniques.values()
                      if v.reliability <= max_reliability and v.attempts >= 3]
        candidates.sort(key=lambda x: x["success_rate"])
        return candidates[:limit]

    def record_llm_call(self, task: str, model: str, tokens_used: int,
                        success: bool, latency_ms: float, cost: float):
        key = f"{task}:{model}"
        rec = LLMRecord(task=task, model=model, tokens_used=tokens_used,
                        success=success, latency_ms=latency_ms, cost=cost)
        self._llm_performance[key].append(rec)

    def get_best_model_for_task(self, task: str, min_samples: int = 3) -> Optional[str]:
        candidates = []
        for key, records in self._llm_performance.items():
            rec_task, rec_model = key.split(":", 1)
            if rec_task != task or len(records) < min_samples:
                continue
            success_rate = sum(1 for r in records if r.success) / len(records)
            avg_cost = sum(r.cost for r in records) / len(records)
            avg_latency = sum(r.latency_ms for r in records) / len(records)
            score = success_rate * 100 - avg_cost * 10 - avg_latency / 1000
            candidates.append((score, rec_model))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0][1]

    def should_use_llm_for_task(self, task: str, target_tech: str, min_reliability: float = 0.8) -> bool:
        technique_key = f"{task}:{target_tech}"
        tech_record = self._techniques.get(technique_key)
        if tech_record and tech_record.attempts >= 3 and tech_record.reliability >= min_reliability:
            return False
        return True

    def get_stats(self) -> dict:
        return {
            "techniques_tracked": len(self._techniques),
            "tools_tracked": len(self._tools),
            "bypass_patterns": sum(len(v) for v in self._bypass_patterns.values()),
            "fp_patterns": len(self._false_positive_patterns),
            "attack_paths_recorded": len(self._attack_paths),
            "chains_tracked": len(self._chain_stats),
            "top_techniques": sorted(
                [t.to_dict() for t in self._techniques.values()],
                key=lambda t: t["attempts"], reverse=True,
            )[:10],
            "top_tools": sorted(
                [t.to_dict() for t in self._tools.values()],
                key=lambda t: t["runs"], reverse=True,
            )[:10],
            "hot_techniques": self.get_hot_techniques(),
            "cold_techniques": self.get_cold_techniques(),
        }

    def persist(self):
        LEARNED_PATTERNS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LEARNED_PATTERNS_PATH, "w") as f:
            for rec in self._techniques.values():
                f.write(json.dumps({"type": "technique", **rec.to_dict()}) + "\n")
            for rec in self._tools.values():
                f.write(json.dumps({"type": "tool", **rec.to_dict()}) + "\n")
            for key, payloads in self._bypass_patterns.items():
                f.write(json.dumps({"type": "bypass", "key": key, "payloads": payloads}) + "\n")

        LLM_PERFORMANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LLM_PERFORMANCE_PATH, "w") as f:
            for key, records in self._llm_performance.items():
                for rec in records:
                    f.write(json.dumps({
                        "type": "llm_call", "key": key,
                        "task": rec.task, "model": rec.model,
                        "tokens_used": rec.tokens_used, "success": rec.success,
                        "latency_ms": rec.latency_ms, "cost": rec.cost,
                        "timestamp": rec.timestamp,
                    }) + "\n")

        CHAIN_PERFORMANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CHAIN_PERFORMANCE_PATH, "w") as f:
            for rec in self._attack_paths:
                f.write(json.dumps({"type": "attack_path", **rec.to_dict()}) + "\n")

    def _load(self):
        if LEARNED_PATTERNS_PATH.exists():
            with open(LEARNED_PATTERNS_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        etype = entry.pop("type", "")
                        if etype == "technique":
                            rec = TechniqueRecord(
                                technique=entry["technique"],
                                target_tech=entry["target_tech"],
                                attempts=entry.get("attempts", 0),
                                successes=entry.get("successes", 0),
                                false_positives=entry.get("false_positives", 0),
                                avg_execution_time=entry.get("avg_execution_time", 0.0),
                                last_used=entry.get("last_used", 0.0),
                                tags=entry.get("tags", []),
                            )
                            self._techniques[f"{rec.technique}:{rec.target_tech}"] = rec
                        elif etype == "tool":
                            rec = ToolRecord(
                                tool_name=entry["tool_name"],
                                runs=entry.get("runs", 0),
                                findings_found=entry.get("findings_found", 0),
                                false_positives=entry.get("false_positives", 0),
                                avg_run_time=entry.get("avg_run_time", 0.0),
                            )
                            self._tools[rec.tool_name] = rec
                        elif etype == "bypass":
                            self._bypass_patterns[entry["key"]] = entry.get("payloads", [])
                    except Exception:
                        continue

        if LLM_PERFORMANCE_PATH.exists():
            with open(LLM_PERFORMANCE_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("type") == "llm_call":
                            rec = LLMRecord(
                                task=entry["task"], model=entry["model"],
                                tokens_used=entry["tokens_used"],
                                success=entry["success"],
                                latency_ms=entry["latency_ms"],
                                cost=entry["cost"],
                                timestamp=entry.get("timestamp", time.time()),
                            )
                            self._llm_performance[entry["key"]].append(rec)
                    except Exception:
                        continue

        if CHAIN_PERFORMANCE_PATH.exists():
            with open(CHAIN_PERFORMANCE_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("type") == "attack_path":
                            rec = AttackPathRecord(
                                chain_name=entry["chain_name"],
                                target=entry["target"],
                                steps_attempted=entry["steps_attempted"],
                                steps_succeeded=entry["steps_succeeded"],
                                total_duration=entry["total_duration"],
                                findings_produced=entry["findings_produced"],
                                success=entry["success"],
                                timestamp=entry.get("timestamp", time.time()),
                            )
                            self._attack_paths.append(rec)
                            self._chain_stats[rec.chain_name]["success"] += 1 if rec.success else 0
                            self._chain_stats[rec.chain_name]["total"] += 1
                    except Exception:
                        continue

        logger.info(f"LearningEngine: loaded {len(self._techniques)} techniques, "
                    f"{len(self._tools)} tools, {len(self._bypass_patterns)} bypass patterns, "
                    f"{len(self._attack_paths)} attack paths")


_learning_engine: Optional[LearningEngine] = None


def get_learning_engine() -> LearningEngine:
    global _learning_engine
    if _learning_engine is None:
        _learning_engine = LearningEngine()
    return _learning_engine
