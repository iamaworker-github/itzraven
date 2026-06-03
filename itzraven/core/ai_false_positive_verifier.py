"""
AI False Positive Verifier — LLM cross-validates findings against actual request/response.
Har finding ko LLM se verify karata hai: "yeh real vulnerability hai ya false positive?"
"""
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class VerificationResult:
    finding_id: str
    title: str
    is_true_positive: bool
    confidence: float
    reason: str
    suggested_verification: Optional[str] = None
    false_positive_type: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "is_true_positive": self.is_true_positive,
            "confidence": self.confidence,
            "reason": self.reason,
            "suggested_verification": self.suggested_verification,
            "false_positive_type": self.false_positive_type,
            "timestamp": self.timestamp,
        }


class AIVerifier:
    def __init__(self):
        self._verified: Dict[str, VerificationResult] = {}
        self._llm = None

    async def _get_llm(self):
        if self._llm is None:
            from itzraven.agents.llm_client import LLMClient
            self._llm = LLMClient()
        return self._llm

    async def verify_finding(self, finding: Dict[str, Any], target: str) -> VerificationResult:
        """LLM se finding verify karaye."""
        llm = await self._get_llm()

        prompt = f"""You are a security expert verifying a penetration testing finding.

Target: {target}
Finding Title: {finding.get('title', '')}
Description: {finding.get('description', '')}
Severity: {finding.get('severity', '')}
Category: {finding.get('category', '')}
Evidence: {finding.get('evidence', '')[:500]}
PoC: {finding.get('proof_of_concept', '')[:300]}
Confidence: {finding.get('confidence', 1.0)}

Analyze this finding. Is it a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE?

Consider:
1. Would this actually work against a real application?
2. Is the evidence conclusive or circumstantial?
3. Could this be caused by WAF/IDS interference?
4. Is the PoC technically valid?
5. Is this a common scanner false positive pattern?

Respond in JSON format:
{{
    "is_true_positive": true/false,
    "confidence": 0.0-1.0,
    "reason": "brief explanation",
    "suggested_verification": "how to manually verify",
    "false_positive_type": "waf_noise/misconfiguration/scan_artifact/not_applicable/behavior_expected" or null if true positive
}}"""

        try:
            response = await llm.generate(
                prompt=prompt,
                system="You are a security expert. Respond with valid JSON only.",
                max_tokens=500,
                temperature=0.1,
                task="fp_verification",
            )
            text = response.text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            result_data = json.loads(text)
        except Exception as e:
            logger.debug(f"LLM verification failed, using fallback: {e}")
            # Fallback: heuristic-based verification
            result_data = self._heuristic_verify(finding)

        result = VerificationResult(
            finding_id=finding.get("finding_id", "unknown"),
            title=finding.get("title", "Unknown"),
            is_true_positive=result_data.get("is_true_positive", True),
            confidence=result_data.get("confidence", 0.5),
            reason=result_data.get("reason", "No LLM analysis available"),
            suggested_verification=result_data.get("suggested_verification"),
            false_positive_type=result_data.get("false_positive_type"),
        )
        self._verified[finding["finding_id"]] = result
        return result

    def _heuristic_verify(self, finding: Dict[str, Any]) -> dict:
        """Fallback heuristic verification."""
        evidence = (finding.get("evidence") or "").lower()
        description = (finding.get("description") or "").lower()
        category = (finding.get("category") or "").lower()

        fp_patterns = [
            "default page", "welcome to", "it works", "example.com",
            "test page", "under construction", "placeholder",
        ]
        for pat in fp_patterns:
            if pat in evidence or pat in description:
                return {"is_true_positive": False, "confidence": 0.3,
                        "reason": f"Matches common false positive pattern: '{pat}'",
                        "false_positive_type": "scan_artifact"}

        if category in ("info", "low") and not finding.get("proof_of_concept"):
            return {"is_true_positive": False, "confidence": 0.4,
                    "reason": "Low severity finding without PoC — likely informational only",
                    "false_positive_type": "not_applicable"}

        if "error" in evidence and "warning" in evidence and category in ("info", "low"):
            return {"is_true_positive": False, "confidence": 0.5,
                    "reason": "Evidence contains error/warning messages but no exploit confirmed",
                    "false_positive_type": "misconfiguration"}

        return {"is_true_positive": True, "confidence": 0.7,
                "reason": "Heuristic check passed — no obvious FP patterns detected"}

    async def verify_batch(self, findings: List[Dict[str, Any]], target: str) -> List[VerificationResult]:
        results = []
        for f in findings:
            result = await self.verify_finding(f, target)
            results.append(result)
        return results

    def get_stats(self) -> dict:
        if not self._verified:
            return {"total": 0, "true_positives": 0, "false_positives": 0, "avg_confidence": 0}
        tp = sum(1 for v in self._verified.values() if v.is_true_positive)
        fp = sum(1 for v in self._verified.values() if not v.is_true_positive)
        avg_conf = sum(v.confidence for v in self._verified.values()) / len(self._verified)
        return {
            "total": len(self._verified),
            "true_positives": tp,
            "false_positives": fp,
            "avg_confidence": round(avg_conf, 2),
        }


_instance_verifier: Optional[AIVerifier] = None


def get_ai_verifier() -> AIVerifier:
    global _instance_verifier
    if _instance_verifier is None:
        _instance_verifier = AIVerifier()
    return _instance_verifier
