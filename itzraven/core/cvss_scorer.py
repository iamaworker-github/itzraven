"""
CVSS Scorer — CVSS 3.1 scoring for security findings.

Strix v0.8.0 inspired: assigns CVSS scores and vectors based on
vulnerability characteristics. Maps Itzraven severity to CVSS base scores
and generates CVSS 3.1 vector strings for structured reporting.

CVSS 3.1 Reference: https://www.first.org/cvss/v3-1/
"""

import re
import math
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field


SEVERITY_TO_CVSS: Dict[str, Tuple[float, str]] = {
    "critical": (9.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"),
    "medium":   (5.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    "low":      (3.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    "info":     (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}


CATEGORY_TO_CVSS: Dict[str, Dict[str, str]] = {
    "injection": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "H",
        "integrity": "H", "availability": "H",
    },
    "xss": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "H",
        "integrity": "L", "availability": "N",
    },
    "ssrf": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "H",
        "integrity": "L", "availability": "N",
    },
    "auth": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "H",
        "integrity": "H", "availability": "H",
    },
    "idor": {
        "attack_vector": "N", "privilege": "L", "confidentiality": "H",
        "integrity": "N", "availability": "N",
    },
    "command_injection": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "H",
        "integrity": "H", "availability": "H",
    },
    "recon": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "L",
        "integrity": "N", "availability": "N",
    },
    "misconfiguration": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "L",
        "integrity": "L", "availability": "N",
    },
    "default": {
        "attack_vector": "N", "privilege": "N", "confidentiality": "H",
        "integrity": "L", "availability": "L",
    },
}


@dataclass
class CVSSResult:
    score: float
    vector: str
    severity: str

    def to_dict(self) -> dict:
        return {"score": round(self.score, 1), "vector": self.vector, "severity": self.severity}

    def to_xml(self) -> str:
        return f"<cvss><score>{self.score:.1f}</score><vector>{self.vector}</vector><severity>{self.severity}</severity></cvss>"


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"


def _compute_cvss_vector(category: str, severity: str, has_poc: bool, has_auth: bool) -> str:
    cat_cfg = CATEGORY_TO_CVSS.get(category.lower(), CATEGORY_TO_CVSS["default"])

    av = cat_cfg.get("attack_vector", "N")
    ac = "L" if severity in ("critical", "high") else "H" if severity == "low" else "L"
    pr = "N" if not has_auth else "L"
    ui = "N"
    s = "U"
    c = cat_cfg.get("confidentiality", "H")
    i = cat_cfg.get("integrity", "L")
    a = cat_cfg.get("availability", "N")

    if has_poc:
        c = "H" if c != "N" else c
        i = "H" if i != "N" else i

    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def _compute_cvss_score(vector: str) -> float:
    """Compute CVSS 3.1 base score from vector string.

    Simplified calculation following the CVSS 3.1 specification.
    """
    def _extract(key: str) -> str:
        m = re.search(rf"/{key}:([^/]+)", vector)
        return m.group(1) if m else "N"

    def _metric_value(code: str) -> float:
        values = {
            "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
            "AC": {"L": 0.77, "H": 0.44},
            "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
            "UI": {"N": 0.85, "R": 0.62},
            "S": {"U": 0.0, "C": 1.0},
            "C": {"H": 0.56, "L": 0.22, "N": 0.0},
            "I": {"H": 0.56, "L": 0.22, "N": 0.0},
            "A": {"H": 0.56, "L": 0.22, "N": 0.0},
        }
        for prefix, mapping in values.items():
            if code.startswith(prefix):
                val = code[len(prefix):].strip()
                return mapping.get(val, 0.0)
        return 0.0

    try:
        av = _metric_value("AV:" + _extract("AV"))
        ac = _metric_value("AC:" + _extract("AC"))
        pr = _metric_value("PR:" + _extract("PR"))
        ui = _metric_value("UI:" + _extract("UI"))
        s = _metric_value("S:" + _extract("S"))
        c = _metric_value("C:" + _extract("C"))
        i = _metric_value("I:" + _extract("I"))
        a = _metric_value("A:" + _extract("A"))

        impact = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if s > 0:
            impact = 1.0 - ((1.0 - impact) * (1.0 - impact))

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if s > 0:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        return round(score, 1)
    except Exception:
        return 0.0


def score_finding(
    category: str,
    severity: str,
    has_poc: bool = False,
    has_auth: bool = False,
    evidence_length: int = 0,
) -> CVSSResult:
    """Assign CVSS score and vector to a finding.

    Args:
        category: Finding category (injection, xss, auth, etc.)
        severity: Finding severity (critical, high, medium, low, info)
        has_poc: Whether proof-of-concept exists
        has_auth: Whether authentication was used
        evidence_length: Length of evidence string

    Returns:
        CVSSResult with score, vector, and mapped severity
    """
    vector = _compute_cvss_vector(category, severity, has_poc, has_auth)
    score = _compute_cvss_score(vector)

    if score == 0.0:
        base_score, base_vector = SEVERITY_TO_CVSS.get(severity, SEVERITY_TO_CVSS["info"])
        score = base_score
        vector = base_vector

    if evidence_length < 20:
        score = max(0.0, score - 1.0)

    mapped_severity = _score_to_severity(score)

    return CVSSResult(score=score, vector=vector, severity=mapped_severity)


def score_from_finding(finding_dict: dict) -> CVSSResult:
    """Score a finding dict (from Finding.to_dict() or similar)."""
    return score_finding(
        category=finding_dict.get("category", "default"),
        severity=finding_dict.get("severity", "info"),
        has_poc=bool(finding_dict.get("proof_of_concept")),
        has_auth=bool(finding_dict.get("auth_required", False)),
        evidence_length=len(finding_dict.get("evidence", "") or ""),
    )


def generate_code_location_xml(
    file_path: Optional[str],
    line_number: Optional[int],
    code_snippet: Optional[str],
) -> str:
    """Generate XML code location block (Strix v0.8.0 style)."""
    parts = ["<code_location>"]
    if file_path:
        parts.append(f"  <file>{_escape_xml(file_path)}</file>")
    if line_number is not None:
        parts.append(f"  <line>{line_number}</line>")
    if code_snippet:
        parts.append(f"  <snippet><![CDATA[{code_snippet}]]></snippet>")
    parts.append("</code_location>")
    return "\n".join(parts)


def generate_finding_xml(finding: dict) -> str:
    """Generate full XML for a finding (Strix v0.8.0 nested format)."""
    cvss = score_from_finding(finding)
    lines = [
        "<vulnerability>",
        f"  <title><![CDATA[{finding.get('title', '')}]]></title>",
        f"  <description><![CDATA[{finding.get('description', '')}]]></description>",
        f"  <category>{_escape_xml(finding.get('category', ''))}</category>",
        f"  <severity>{cvss.severity}</severity>",
        f"  <confidence>{finding.get('confidence', 0)}</confidence>",
        cvss.to_xml(),
        generate_code_location_xml(
            finding.get("file_path"),
            finding.get("line_number"),
            finding.get("code_snippet"),
        ),
    ]
    if finding.get("proof_of_concept"):
        lines.append(f"  <proof_of_concept><![CDATA[{finding['proof_of_concept']}]]></proof_of_concept>")
    if finding.get("remediation"):
        lines.append(f"  <remediation><![CDATA[{finding['remediation']}]]></remediation>")
    if finding.get("cwe_id"):
        lines.append(f"  <cwe>{_escape_xml(finding['cwe_id'])}</cwe>")
    evidence = finding.get("evidence", "")
    if evidence:
        lines.append(f"  <evidence><![CDATA[{evidence[:500]}]]></evidence>")
    lines.append("</vulnerability>")
    return "\n".join(lines)


def generate_report_xml(findings: list, target: str) -> str:
    """Generate complete XML report (Strix v0.8.0 style)."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<itzraven_scan_report>",
        f"  <target>{_escape_xml(target)}</target>",
        f"  <timestamp>{__import__('datetime').datetime.now().isoformat()}</timestamp>",
        f"  <total_findings>{len(findings)}</total_findings>",
        "  <vulnerabilities>",
    ]
    for finding in findings:
        lines.append(generate_finding_xml(finding))
    lines.extend(["  </vulnerabilities>", "</itzraven_scan_report>"])
    return "\n".join(lines)


def _escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")
