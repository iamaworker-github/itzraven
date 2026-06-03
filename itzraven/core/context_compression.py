"""
Context Compression Layer — importance-scored sliding window for long engagements.
LLM-powered summarization for intelligent context pruning.

Prevents context overflow by:
1. Scoring each finding by importance (severity + confidence + graph centrality)
2. Sliding window: keeps top-K findings, compresses low-importance ones
3. LLM summarization: groups related low-importance findings into brief summaries
4. Temporal decay: older findings lose importance unless reinforced
5. Semantic dedup: near-duplicate findings merged automatically
"""

import time
import math
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set, Callable
from collections import defaultdict

from itzraven.core.logger import get_logger
from itzraven.core.graph_memory import (
    GraphMemory, EntityType, RelationType, get_graph_memory,
)

logger = get_logger()

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

COMPRESSION_CATEGORIES = {
    "dns_record": {"default_keep": 3, "compress_method": "summary"},
    "subdomain": {"default_keep": 10, "compress_method": "summary"},
    "port_scan": {"default_keep": 20, "compress_method": "summary"},
    "tech_fingerprint": {"default_keep": 5, "compress_method": "keep_all"},
    "vulnerability": {"default_keep": 50, "compress_method": "keep_all"},
    "osint_lead": {"default_keep": 15, "compress_method": "summary"},
    "email": {"default_keep": 5, "compress_method": "summary"},
    "breach": {"default_keep": 10, "compress_method": "keep_all"},
    "default": {"default_keep": 5, "compress_method": "summary"},
}


@dataclass
class ScoredFinding:
    finding_id: str
    title: str
    description: str
    severity: str
    confidence: float
    category: str
    importance_score: float = 0.0
    timestamp: float = field(default_factory=time.time)
    compressed: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "importance": round(self.importance_score, 3),
            "compressed": self.compressed,
            "summary": self.summary or self.title,
        }


class ContextCompressor:
    """Importance-scored sliding window for long engagement context management."""

    def __init__(self, max_findings: int = 200, graph: Optional[GraphMemory] = None):
        self.max_findings = max_findings
        self._graph = graph or get_graph_memory()
        self._findings: List[ScoredFinding] = []
        self._compressed_groups: Dict[str, List[str]] = defaultdict(list)
        self._importance_history: List[dict] = []

    def add_finding(self, finding_id: str, title: str, description: str,
                    severity: str = "info", confidence: float = 0.5,
                    category: str = "default", tags: Optional[List[str]] = None):
        score = self._calculate_importance(severity, confidence, category, tags)
        scored = ScoredFinding(
            finding_id=finding_id,
            title=title, description=description,
            severity=severity, confidence=confidence,
            category=category, importance_score=score,
        )
        self._findings.append(scored)
        self._importance_history.append({
            "finding_id": finding_id, "score": score, "timestamp": time.time(),
        })
        self._maybe_compress()
        return scored

    def get_active_context(self, max_tokens: int = 4000) -> str:
        """Generate compressed context string for LLM prompts."""
        active = [f for f in self._findings if not f.compressed]
        active.sort(key=lambda f: f.importance_score, reverse=True)

        lines = []
        severity_count = defaultdict(int)
        for f in active:
            severity_count[f.severity] += 1

        lines.append(f"[CONTEXT: {len(active)} active findings | "
                     f"Compressed: {len(self._findings) - len(active)} | "
                     f"Severity: {dict(severity_count)}]")
        lines.append("")

        token_estimate = len("\n".join(lines))
        for f in active:
            entry = f"[{f.severity.upper()}] {f.title} (score={f.importance_score:.2f})"
            if f.confidence < 1.0:
                entry += f" [conf={f.confidence:.2f}]"
            lines.append(entry)
            token_estimate += len(entry)
            if token_estimate > max_tokens * 4:
                remaining = len(active) - active.index(f) - 1
                lines.append(f"... and {remaining} more findings")
                break

        if self._compressed_groups:
            lines.append("")
            lines.append(f"[COMPRESSED: {sum(len(v) for v in self._compressed_groups.values())} grouped items]")
            for group, items in list(self._compressed_groups.items())[:5]:
                lines.append(f"  {group}: {len(items)} items ({items[0][:60]}...)")

        return "\n".join(lines)

    def get_high_importance(self, min_score: float = 5.0) -> List[ScoredFinding]:
        return [f for f in self._findings if not f.compressed and f.importance_score >= min_score]

    def get_top_findings(self, n: int = 20) -> List[ScoredFinding]:
        sorted_f = sorted(self._findings, key=lambda f: f.importance_score, reverse=True)
        return sorted_f[:n]

    def decay_importance(self, half_life_hours: float = 24.0):
        """Decay importance of older findings."""
        now = time.time()
        half_life_secs = half_life_hours * 3600
        for f in self._findings:
            age = now - f.timestamp
            if age > half_life_secs:
                factor = math.pow(0.5, age / half_life_secs)
                f.importance_score *= factor
        self._maybe_compress()

    def reinforce(self, finding_id: str, amount: float = 2.0):
        """Reinforce a finding's importance (called on verification)."""
        for f in self._findings:
            if f.finding_id == finding_id:
                f.importance_score += amount
                f.timestamp = time.time()  # Reset decay
                if f.compressed:
                    f.compressed = False
                    f.summary = ""
                break

    def _calculate_importance(self, severity: str, confidence: float,
                              category: str, tags: Optional[List[str]]) -> float:
        base = SEVERITY_WEIGHTS.get(severity, 1)
        conf_factor = 0.5 + (confidence * 0.5)
        cat_config = COMPRESSION_CATEGORIES.get(category, COMPRESSION_CATEGORIES["default"])
        cat_bonus = 0.0
        if cat_config["compress_method"] == "keep_all":
            cat_bonus = 1.0

        # Graph centrality bonus
        centrality_bonus = 0.0
        if self._graph:
            try:
                entity_count = len(self._graph._entities)
                if entity_count > 0:
                    centrality_bonus = min(1.0, entity_count / 100)
            except Exception:
                pass

        return base * conf_factor + cat_bonus + centrality_bonus

    def _maybe_compress(self):
        if len(self._findings) <= self.max_findings:
            return

        # Sort by importance
        self._findings.sort(key=lambda f: f.importance_score, reverse=True)

        # Keep top findings, compress rest
        to_compress = self._findings[self.max_findings:]
        self._findings = self._findings[:self.max_findings]

        # Group and compress
        groups = defaultdict(list)
        for f in to_compress:
            groups[f.category].append(f)

        for category, items in groups.items():
            cat_config = COMPRESSION_CATEGORIES.get(category, COMPRESSION_CATEGORIES["default"])
            keep_count = cat_config["default_keep"]

            if cat_config["compress_method"] == "keep_all":
                for item in items:
                    self._findings.append(item)
                continue

            items.sort(key=lambda f: f.importance_score, reverse=True)
            keep = items[:keep_count]
            compress = items[keep_count:]

            for item in keep:
                self._findings.append(item)

            if compress:
                group_key = f"{category}_compressed_{len(self._compressed_groups)}"
                compressed_titles = [f.title for f in compress]
                self._compressed_groups[group_key] = compressed_titles
                summary = ScoredFinding(
                    finding_id=group_key,
                    title=f"[Compressed] {len(compress)} {category} findings",
                    description=f"Grouped {len(compress)} low-importance {category} findings",
                    severity="info", confidence=0.3,
                    category="compressed",
                    importance_score=1.0,
                    compressed=True,
                    summary=", ".join(compressed_titles[:5]) + ("..." if len(compressed_titles) > 5 else ""),
                )
                self._findings.append(summary)

        logger.info(f"Context compressed: kept {len(self._findings)}, "
                    f"grouped {sum(len(v) for v in self._compressed_groups.values())} items")

    # =====================================================================
    # LLM-Powered Summarization
    # =====================================================================

    def set_llm_callable(self, llm_func: Optional[Callable] = None):
        """Set an async callable(prompt: str) -> str for LLM summarization."""
        self._llm_func = llm_func

    async def compress_with_llm(self, max_findings: int = 50) -> List[ScoredFinding]:
        """Use LLM to intelligently compress findings beyond simple truncation.

        Groups low-importance findings by category and asks LLM to produce
        a concise summary for each group.

        Returns:
            List of findings (high-importance kept intact + compressed summaries)
        """
        if not self._findings:
            return []

        self._findings.sort(key=lambda f: f.importance_score, reverse=True)
        keep = [f for f in self._findings if f.importance_score >= 5.0][:max_findings]
        compressible = [f for f in self._findings if f.importance_score < 5.0]

        if not compressible:
            self._findings = keep
            return keep

        # Group compressible findings by category
        groups = defaultdict(list)
        for f in compressible:
            groups[f.category].append(f)

        # Use LLM to summarize each group
        if self._llm_func is not None:
            for category, items in list(groups.items())[:10]:
                titles = "\n".join(f"- [{f.severity}] {f.title}" for f in items[:20])
                prompt = (
                    f"Summarize these {len(items)} {category} security findings "
                    f"into 2-3 concise bullet points. Keep critical details:\n{titles}"
                )
                try:
                    summary = await self._llm_func(prompt)
                except Exception:
                    summary = f"{len(items)} {category} findings"
                compressed = ScoredFinding(
                    finding_id=f"llm_summary_{category}",
                    title=f"[LLM Summary] {len(items)} {category} findings",
                    description=summary[:500],
                    severity="info", confidence=0.5,
                    category="compressed",
                    importance_score=3.0,
                    compressed=True,
                    summary=summary[:200],
                )
                keep.append(compressed)

        self._findings = keep
        return keep

    # =====================================================================
    # Semantic Dedup — merge near-identical findings across agents
    # =====================================================================

    def merge_similar(self, title_similarity_threshold: float = 0.75) -> int:
        """Merge findings with similar titles (case-insensitive substring match).

        Returns:
            Number of duplicate findings removed.
        """
        if len(self._findings) < 2:
            return 0

        merged = 0
        seen_titles: List[str] = []
        to_remove: Set[int] = set()

        for i, f in enumerate(self._findings):
            t_lower = f.title.lower()
            is_dup = False
            for seen in seen_titles:
                if len(t_lower) > 10 and len(seen) > 10:
                    if t_lower in seen or seen in t_lower:
                        is_dup = True
                        break
            if is_dup:
                to_remove.add(i)
                merged += 1
            else:
                seen_titles.append(t_lower)

        if to_remove:
            self._findings = [f for i, f in enumerate(self._findings) if i not in to_remove]

        return merged

    def clear(self):
        self._findings.clear()
        self._compressed_groups.clear()
        self._importance_history.clear()
