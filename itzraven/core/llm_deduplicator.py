"""
LLM-based Vulnerability Deduplication — semantic similarity merging.

Strix v0.6.0 inspired: uses LLM to detect semantically similar findings
and merge them into a single canonical finding. Falls back to bloom filter
for exact-match fast path.

Architecture:
  1. Exact hash match (bloom filter) — O(1) fast path
  2. LLM semantic comparison — compares new finding against recent findings
  3. Merge duplicate findings — consolidate evidence, PoCs, remediation
"""

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.bloom_filter import BloomFilter
from itzraven.agents.llm_client import LLMClient

logger = get_logger()


@dataclass
class DedupResult:
    is_duplicate: bool
    merged_into: Optional[str] = None
    similarity_score: float = 0.0
    reason: str = ""
    llm_verified: bool = False


@dataclass
class FindingRecord:
    finding_id: str
    title: str
    description: str
    category: str
    severity: str
    agent_name: str
    evidence: str
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cvss_score: Optional[float] = None
    timestamp: float = field(default_factory=time.time)


DEDUP_SYSTEM_PROMPT = """You are a vulnerability deduplication expert.
Your task is to determine if two security findings are semantically the same vulnerability.

Compare the TWO findings below and decide:
- SAME: They describe the same underlying vulnerability (even if wording differs)
- DIFFERENT: They are distinct vulnerabilities

Consider:
- Same vulnerability type (e.g., both are SQL injection on the same endpoint)
- Same root cause even if different evidence/screenshots
- Same location (file, endpoint, parameter)
- Different exploitation methods for same bug => SAME
- Different bugs on same endpoint => DIFFERENT

Respond with JSON only:
{"is_duplicate": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}
"""


class LLMDeduplicator:
    def __init__(
        self,
        max_recent_findings: int = 50,
        llm_threshold: float = 0.75,
        cache_size: int = 500,
    ):
        self._bloom = BloomFilter(capacity=100_000)
        self._exact_set: Dict[str, str] = {}  # key -> finding_id
        self._recent_findings: OrderedDict[str, FindingRecord] = OrderedDict()
        self._canonical_findings: Dict[str, FindingRecord] = {}  # merged targets
        self._llm_cache: Dict[str, DedupResult] = {}
        self._llm_client: Optional[LLMClient] = None

        self.max_recent_findings = max_recent_findings
        self.llm_threshold = llm_threshold
        self.cache_size = cache_size

        self.stats = {
            "exact_hits": 0,
            "llm_checks": 0,
            "llm_dedup_hits": 0,
            "llm_cache_hits": 0,
            "merges": 0,
            "unique_findings": 0,
        }

    def _get_llm(self) -> LLMClient:
        if self._llm_client is None:
            self._llm_client = LLMClient()
        return self._llm_client

    def _make_exact_key(self, finding: FindingRecord) -> str:
        raw = f"{finding.title}:{finding.category}:{finding.file_path}:{finding.line_number}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _make_llm_cache_key(self, a: FindingRecord, b: FindingRecord) -> str:
        raw = f"{a.finding_id}:{b.finding_id}"
        return hashlib.md5(raw.encode()).hexdigest()

    def add_finding_record(self, finding: FindingRecord) -> None:
        key = self._make_exact_key(finding)
        self._exact_set[key] = finding.finding_id
        self._bloom.add(key)

        self._recent_findings[finding.finding_id] = finding
        self._recent_findings.move_to_end(finding.finding_id)
        if len(self._recent_findings) > self.max_recent_findings:
            self._recent_findings.popitem(last=False)

        if finding.finding_id not in self._canonical_findings:
            self._canonical_findings[finding.finding_id] = finding
            self.stats["unique_findings"] += 1

    def exact_match(self, finding: FindingRecord) -> Optional[str]:
        key = self._make_exact_key(finding)
        if key in self._exact_set:
            self.stats["exact_hits"] += 1
            return self._exact_set[key]
        if self._bloom.check(key):
            self.stats["exact_hits"] += 1
            return self._exact_set.get(key)
        return None

    async def semantic_match(self, finding: FindingRecord) -> Optional[DedupResult]:
        candidates = list(self._recent_findings.values())
        if not candidates:
            return None

        best_match: Optional[Tuple[FindingRecord, float]] = None

        for candidate in candidates:
            if candidate.finding_id == finding.finding_id:
                continue

            cache_key = self._make_llm_cache_key(finding, candidate)
            if cache_key in self._llm_cache:
                cached = self._llm_cache[cache_key]
                if cached.is_duplicate and cached.similarity_score > best_match[1] if best_match else 0:
                    self.stats["llm_cache_hits"] += 1
                    best_match = (candidate, cached.similarity_score)
                    continue

            self.stats["llm_checks"] += 1
            result = await self._llm_compare(finding, candidate)

            self._llm_cache[cache_key] = result
            if len(self._llm_cache) > self.cache_size:
                oldest = next(iter(self._llm_cache))
                del self._llm_cache[oldest]

            if result.is_duplicate and result.similarity_score > (best_match[1] if best_match else 0):
                best_match = (candidate, result.similarity_score)

            if result.is_duplicate and result.similarity_score >= self.llm_threshold:
                break

        if best_match and best_match[1] >= self.llm_threshold:
            candidate, score = best_match
            self.stats["llm_dedup_hits"] += 1
            return DedupResult(
                is_duplicate=True,
                merged_into=candidate.finding_id,
                similarity_score=score,
                reason=f"Merged into {candidate.title} (confidence: {score})",
                llm_verified=True,
            )

        return DedupResult(is_duplicate=False, similarity_score=0.0, reason="No semantic match found")

    async def _llm_compare(self, a: FindingRecord, b: FindingRecord) -> DedupResult:
        prompt = (
            f"Finding A:\n"
            f"  Title: {a.title}\n"
            f"  Description: {a.description[:300]}\n"
            f"  Category: {a.category}\n"
            f"  Severity: {a.severity}\n"
            f"  File: {a.file_path or 'N/A'}:{a.line_number or 'N/A'}\n"
            f"  Evidence: {a.evidence[:200]}\n\n"
            f"Finding B:\n"
            f"  Title: {b.title}\n"
            f"  Description: {b.description[:300]}\n"
            f"  Category: {b.category}\n"
            f"  Severity: {b.severity}\n"
            f"  File: {b.file_path or 'N/A'}:{b.line_number or 'N/A'}\n"
            f"  Evidence: {b.evidence[:200]}\n"
        )
        try:
            llm = self._get_llm()
            resp = await llm.generate(
                prompt=prompt,
                system=DEDUP_SYSTEM_PROMPT,
                max_tokens=200,
                model="openai/gpt-4o-mini",
                temperature=0.1,
            )
            import json as j
            parsed = j.loads(resp.content.strip())
            return DedupResult(
                is_duplicate=bool(parsed.get("is_duplicate", False)),
                similarity_score=float(parsed.get("confidence", 0.0)),
                reason=parsed.get("reason", ""),
                llm_verified=True,
            )
        except Exception as e:
            logger.debug(f"LLM dedup compare failed: {e}")
            return DedupResult(is_duplicate=False, similarity_score=0.0, reason=f"LLM error: {e}")

    def merge_findings(self, primary_id: str, duplicate_id: str) -> FindingRecord:
        primary = self._canonical_findings.get(primary_id)
        duplicate = self._canonical_findings.get(duplicate_id)
        if not primary or not duplicate:
            raise ValueError(f"Cannot merge: {primary_id} or {duplicate_id} not found")

        merged_evidence = primary.evidence
        if duplicate.evidence and duplicate.evidence not in merged_evidence:
            merged_evidence += f"\n[Also detected by: {duplicate.agent_name}]\n{duplicate.evidence}"

        merged_poc = primary.proof_of_concept or duplicate.proof_of_concept
        merged_remediation = primary.remediation or duplicate.remediation
        merged_severity = max(primary.severity, duplicate.severity, key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0))

        merged = FindingRecord(
            finding_id=primary_id,
            title=primary.title,
            description=primary.description,
            category=primary.category,
            severity=merged_severity,
            agent_name=f"{primary.agent_name}+{duplicate.agent_name}",
            evidence=merged_evidence,
            proof_of_concept=merged_poc,
            remediation=merged_remediation,
            file_path=primary.file_path or duplicate.file_path,
            line_number=primary.line_number or duplicate.line_number,
            cvss_score=max(primary.cvss_score or 0, duplicate.cvss_score or 0) or None,
        )

        self._canonical_findings[primary_id] = merged
        if duplicate_id in self._canonical_findings:
            del self._canonical_findings[duplicate_id]
        if duplicate_id in self._recent_findings:
            del self._recent_findings[duplicate_id]

        self.stats["merges"] += 1
        logger.info(f"Merged {duplicate.title} ({duplicate_id}) into {primary.title} ({primary_id})")
        return merged

    async def check_and_dedup(self, finding: FindingRecord) -> DedupResult:
        exact = self.exact_match(finding)
        if exact:
            return DedupResult(
                is_duplicate=True,
                merged_into=exact,
                similarity_score=1.0,
                reason="Exact match (bloom filter)",
                llm_verified=False,
            )

        semantic = await self.semantic_match(finding)
        if semantic and semantic.is_duplicate:
            self.merge_findings(semantic.merged_into, finding.finding_id)
            return semantic

        self.add_finding_record(finding)
        return DedupResult(is_duplicate=False, similarity_score=0.0, reason="New unique finding")

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "canonical_findings": len(self._canonical_findings),
            "recent_findings": len(self._recent_findings),
            "llm_cache_size": len(self._llm_cache),
        }

    def clear(self):
        self._bloom.clear()
        self._exact_set.clear()
        self._recent_findings.clear()
        self._canonical_findings.clear()
        self._llm_cache.clear()
        for k in self.stats:
            self.stats[k] = 0


_deduplicator: Optional[LLMDeduplicator] = None


def get_llm_deduplicator() -> LLMDeduplicator:
    global _deduplicator
    if _deduplicator is None:
        _deduplicator = LLMDeduplicator()
    return _deduplicator
