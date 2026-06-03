"""
Anti-Hallucination Pipeline — Confidence scoring + proof-of-execution validation.
NeuroSploit-inspired: every finding goes through multi-stage validation before reporting.
"""
import re
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class ValidatedFinding:
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    proof_of_concept: str
    remediation: str
    raw_confidence: float = 0.0
    validated: bool = False
    validation_details: Dict[str, Any] = field(default_factory=dict)


class HallucinationDetector:
    """Stage 1: Detect potential hallucination patterns in findings."""

    HALLUCINATION_PATTERNS = [
        r"(?i)(may|might|could|possibly)\s+(contain|allow|lead to)",
        r"(?i)(theoretical|potential)\s+(vulnerability|exploit|attack)",
        r"(?i)(without proper|insufficient)\s+(validation|testing|evidence)",
        r"(?i)(this\s+is\s+a|likely\s+a)\s+(critical|high)\s+severity",
        r"^(I\s+think|I\s+believe|It\s+seems|Probably)",
        r"(?i)no\s+(evidence|proof|concrete)\s+(found|provided|shown)",
    ]

    @staticmethod
    def check(finding: Dict[str, Any]) -> Tuple[float, List[str]]:
        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('evidence', '')}"
        flags = []
        for pattern in HallucinationDetector.HALLUCINATION_PATTERNS:
            if re.search(pattern, text):
                flags.append(f"HALLUCINATION_PATTERN: {pattern}")
        score = max(0.0, 1.0 - (len(flags) * 0.25))
        return score, flags


class ProofOfExecutionValidator:
    """Stage 2: Verify findings have concrete proof of execution."""

    MIN_POC_LENGTH = 15
    REQUIRED_ELEMENTS = {
        "http_request": [r"(GET|POST|PUT|DELETE)\s+", r"https?://"],
        "payload_reflection": [r"(<script|alert\(|onerror=|onload=)"],
        "sql_error": [r"(SQL|syntax|ORA-|mysql_fetch|unclosed quotation)"],
        "file_content": [r"(root:|bin/bash|uid=|DRIVER)"],
        "status_code": [r"(200|201|301|302|401|403|500)"],
        "timing_diff": [r"(SLEEP|WAITFOR|pg_sleep|benchmark)"],
    }

    @staticmethod
    def validate(finding: Dict[str, Any]) -> Dict[str, Any]:
        poc = finding.get("proof_of_concept", "") or ""
        evidence = finding.get("evidence", "") or ""
        combined = f"{poc} {evidence}"

        results = {"has_poc": bool(poc and len(poc) >= ProofOfExecutionValidator.MIN_POC_LENGTH),
                   "has_evidence": bool(evidence and len(evidence) >= 20),
                   "detected_indicators": [],
                   "missing_indicators": []}

        for indicator, patterns in ProofOfExecutionValidator.REQUIRED_ELEMENTS.items():
            matched = False
            for pattern in patterns:
                if re.search(pattern, combined):
                    results["detected_indicators"].append(indicator)
                    matched = True
                    break
            if not matched:
                results["missing_indicators"].append(indicator)

        return results


class SeverityCalibrator:
    """Stage 3: Calibrate severity based on evidence strength."""

    @staticmethod
    def calibrate(finding: Dict[str, Any], poc_result: Dict[str, Any], hallu_score: float) -> Tuple[str, float]:
        confidence = hallu_score
        severity = finding.get("severity", "info").lower()

        # Boost confidence for strong evidence
        indicators = poc_result.get("detected_indicators", [])
        if len(indicators) >= 2:
            confidence = min(1.0, confidence + 0.3)
        if poc_result.get("has_poc"):
            confidence = min(1.0, confidence + 0.15)
        if "http_request" in indicators and ("sql_error" in indicators or "payload_reflection" in indicators):
            confidence = min(1.0, confidence + 0.2)

        # Penalize weak evidence
        missing = poc_result.get("missing_indicators", [])
        if len(missing) >= 3:
            confidence = max(0.0, confidence - 0.3)
        if not poc_result.get("has_evidence"):
            confidence = max(0.0, confidence - 0.2)

        if confidence < 0.3:
            severity = "info"
        elif confidence < 0.5:
            severity = "low" if severity not in ("info",) else severity
        elif confidence < 0.7 and severity in ("critical",):
            severity = "high"

        return severity, round(confidence, 2)


class AntiHallucinationPipeline:
    def __init__(self):
        self.detector = HallucinationDetector()
        self.validator = ProofOfExecutionValidator()
        self.calibrator = SeverityCalibrator()

    def process(self, finding: Dict[str, Any]) -> ValidatedFinding:
        # Stage 1: Hallucination detection
        hallu_score, hallu_flags = self.detector.check(finding)
        if hallu_flags:
            logger.debug(f"  🔍 Hallucination flags: {hallu_flags}")

        # Stage 2: Proof-of-execution validation
        poc_result = self.validator.validate(finding)

        # Stage 3: Severity calibration
        calibrated_severity, calibrated_confidence = self.calibrator.calibrate(finding, poc_result, hallu_score)

        validated = calibrated_confidence >= 0.4 and len(poc_result.get("detected_indicators", [])) > 0

        return ValidatedFinding(
            title=finding.get("title", ""),
            severity=calibrated_severity,
            category=finding.get("category", ""),
            description=finding.get("description", ""),
            evidence=finding.get("evidence", ""),
            proof_of_concept=finding.get("proof_of_concept", ""),
            remediation=finding.get("remediation", ""),
            raw_confidence=calibrated_confidence,
            validated=validated,
            validation_details={
                "hallucination_score": hallu_score,
                "hallucination_flags": hallu_flags,
                "poc_indicators": poc_result.get("detected_indicators", []),
                "missing_indicators": poc_result.get("missing_indicators", []),
                "has_poc": poc_result.get("has_poc", False),
                "has_evidence": poc_result.get("has_evidence", False),
            },
        )


_pipeline: Optional[AntiHallucinationPipeline] = None


def get_anti_hallucination_pipeline() -> AntiHallucinationPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AntiHallucinationPipeline()
    return _pipeline
