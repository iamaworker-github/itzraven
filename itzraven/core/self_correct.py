"""
Error-Driven Self-Correction — Deadend CLI-inspired.

When an attack/action fails:
1. Read error response
2. Infer what defense/WAF blocked it
3. Write custom bypass code
4. Retry with modified approach
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from itzraven.core.logger import get_logger

logger = get_logger()


WAF_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-wan"],
    "cloudfront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "akamai": ["akamai", "akamaighost"],
    "mod_security": ["mod_security", "modsecurity", "406 not acceptable"],
    "aws_waf": ["awswaf", "x-amzn-requestid", "x-amzn-trace-id"],
    "f5_bigip": ["bigip", "f5", "x-cnection"],
    "imperva": ["imperva", "incapsula", "x-iinfo"],
    "sucuri": ["sucuri", "cloudproxy", "x-sucuri-id"],
}


@dataclass
class ErrorAnalysis:
    action_type: str
    error_text: str
    waf_detected: Optional[str] = None
    likely_cause: str = ""
    bypass_suggestion: str = ""
    confidence: float = 0.0


class SelfCorrectionEngine:
    def __init__(self):
        self._attempts: Dict[str, List[ErrorAnalysis]] = {}

    def analyze_error(self, action_type: str, error_text: str, params: Dict[str, Any]) -> ErrorAnalysis:
        analysis = ErrorAnalysis(action_type=action_type, error_text=error_text[:500])
        err_lower = error_text.lower()

        # WAF detection
        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(s in err_lower for s in signatures):
                analysis.waf_detected = waf_name
                analysis.confidence = 0.8
                analysis.likely_cause = f"Blocked by {waf_name} WAF"
                break

        # Common error patterns
        if not analysis.waf_detected:
            if "timeout" in err_lower or "timed out" in err_lower:
                analysis.likely_cause = "Request timeout"
                analysis.confidence = 0.9
                analysis.bypass_suggestion = "Reduce payload count, increase timeout, or use async requests"
            elif "403" in err_lower or "forbidden" in err_lower:
                analysis.likely_cause = "Access forbidden"
                analysis.confidence = 0.7
                analysis.bypass_suggestion = "Try path traversal, different HTTP methods, or auth bypass headers"
            elif "500" in err_lower or "internal server" in err_lower:
                analysis.likely_cause = "Server error - payload may have caused crash"
                analysis.confidence = 0.6
                analysis.bypass_suggestion = "Simplify payload, check for buffer overflow, retry with smaller input"
            elif "connection refused" in err_lower:
                analysis.likely_cause = "Port closed or service not running"
                analysis.confidence = 0.9
                analysis.bypass_suggestion = "Try different port or protocol"
            elif "connection reset" in err_lower:
                analysis.likely_cause = "Connection reset by peer"
                analysis.confidence = 0.7
                analysis.bypass_suggestion = "Rate limiting suspected. Add delays between requests"
            elif "dns" in err_lower and "resolution" in err_lower:
                analysis.likely_cause = "DNS resolution failed"
                analysis.confidence = 0.9
                analysis.bypass_suggestion = "Use IP address directly or check domain spelling"
            elif ("sql" in err_lower and ("syntax" in err_lower or "error" in err_lower)) \
                    or "ora-" in err_lower or "sqlexception" in err_lower:
                analysis.likely_cause = "SQL error - potential SQLi indicator"
                analysis.confidence = 0.5
                analysis.bypass_suggestion = "This may be a SQL injection finding, not an error"
            else:
                analysis.likely_cause = "Unknown error"
                analysis.confidence = 0.3
                analysis.bypass_suggestion = "Retry with different parameters"

        # Generate bypass suggestion for WAF
        if analysis.waf_detected:
            analysis.bypass_suggestion = self._generate_waf_bypass(analysis.waf_detected, action_type)

        key = f"{action_type}:{params.get('param','?')}"
        if key not in self._attempts:
            self._attempts[key] = []
        self._attempts[key].append(analysis)

        return analysis

    def _generate_waf_bypass(self, waf: str, action_type: str) -> str:
        bypasses = {
            "cloudflare": "Use HTTP/1.0 instead of HTTP/1.1, add random comment tags, encode payload in base64",
            "mod_security": "Use case variations, comment injection, chunked encoding",
            "aws_waf": "Use lowercase/uppercase alternation, parameter pollution, add junk parameters",
            "akamai": "Use unicode encoding, null bytes, double URL encoding",
            "f5_bigip": "Use HTTP/0.9, add transfer-encoding: chunked with garbled chunks",
            "imperva": "Use parameter fragmentation, cookie-based payloads, JSON encoding",
        }
        base = bypasses.get(waf, "Use encoding variations, parameter pollution, or alternative attack vectors")
        if action_type == "test_sqli":
            base += ". For SQLi: try 'OR 1=1--, OR 1=2--, waitfor delay variants"
        elif action_type == "test_xss":
            base += ". For XSS: try polyglots, mutation XSS, svg-based payloads"
        return base

    def get_attempts(self, key: str) -> List[ErrorAnalysis]:
        return self._attempts.get(key, [])

    def should_retry(self, key: str, max_attempts: int = 3) -> bool:
        attempts = self._attempts.get(key, [])
        if len(attempts) >= max_attempts:
            return False
        last = attempts[-1] if attempts else None
        if last and last.waf_detected:
            return True  # always retry with bypass if WAF detected
        return True


_self_correct: Optional[SelfCorrectionEngine] = None


def get_self_correction() -> SelfCorrectionEngine:
    global _self_correct
    if _self_correct is None:
        _self_correct = SelfCorrectionEngine()
    return _self_correct
