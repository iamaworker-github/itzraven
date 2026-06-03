"""
Medusa AI Security Scanner integration for Itzraven toolkit

Wraps Medusa CLI (pip install medusa-security) and parses its JSON output
into Itzraven Finding format.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNDEFINED": "info",
}


@dataclass
class MedusaIssue:
    scanner: str
    file: str
    line: int
    severity: str
    confidence: str
    issue: str
    cwe: Optional[str] = None
    code: Optional[str] = None
    is_likely_fp: bool = False


@dataclass
class MedusaScanResult:
    total_issues: int
    files_scanned: int
    security_score: int
    risk_level: str
    severity_breakdown: Dict[str, int]
    findings: List[MedusaIssue] = field(default_factory=list)
    error: Optional[str] = None


class MedusaIntegration:
    AVAILABLE: bool = False

    @classmethod
    def check_available(cls) -> bool:
        try:
            subprocess.run(
                ["medusa", "--version"],
                capture_output=True, timeout=10, check=False,
            )
            cls.AVAILABLE = True
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            cls.AVAILABLE = False
            return False

    @staticmethod
    def scan_path(
        target_path: str,
        workers: Optional[int] = None,
        fail_on: Optional[str] = None,
        exclude: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> MedusaScanResult:
        if not MedusaIntegration.check_available():
            return MedusaScanResult(
                total_issues=0, files_scanned=0,
                security_score=100, risk_level="N/A",
                severity_breakdown={},
                error="medusa not installed. Run: pip install medusa-security",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ["medusa", "scan", target_path, "--format", "json", "-o", tmpdir]
            if workers:
                cmd.extend(["--workers", str(workers)])
            if fail_on:
                cmd.extend(["--fail-on", fail_on])
            if exclude:
                for e in exclude:
                    cmd.extend(["--exclude", e])

            try:
                logger.info(f"Running medusa scan on {target_path}...")
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout,
                )
                if result.returncode not in (0, 2):
                    logger.warning(f"medusa scan exited with code {result.returncode}: {result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                return MedusaScanResult(
                    total_issues=0, files_scanned=0,
                    security_score=100, risk_level="N/A",
                    severity_breakdown={},
                    error="medusa scan timed out",
                )

            json_files = list(Path(tmpdir).glob("medusa-scan-*.json"))
            if not json_files:
                return MedusaScanResult(
                    total_issues=0, files_scanned=0,
                    security_score=100, risk_level="N/A",
                    severity_breakdown={},
                    error="No medusa output JSON found",
                )

            with open(json_files[0]) as f:
                data = json.load(f)

        summary = data.get("scan_summary", {})
        findings_raw = data.get("findings", [])
        severity_breakdown = data.get("severity_breakdown", {})

        findings = []
        for item in findings_raw:
            fp_info = item.get("fp_analysis", {})
            findings.append(MedusaIssue(
                scanner=item.get("scanner", "unknown"),
                file=item.get("file", ""),
                line=item.get("line", 0),
                severity=item.get("severity", "UNDEFINED"),
                confidence=item.get("confidence", "LOW"),
                issue=item.get("issue", ""),
                cwe=item.get("cwe"),
                code=item.get("code"),
                is_likely_fp=fp_info.get("is_likely_fp", False) if fp_info else False,
            ))

        return MedusaScanResult(
            total_issues=summary.get("total_issues", 0),
            files_scanned=summary.get("files_scanned", 0),
            security_score=summary.get("security_score", 100),
            risk_level=summary.get("risk_level", "N/A"),
            severity_breakdown=severity_breakdown,
            findings=findings,
        )

    @staticmethod
    def scan_git_repo(
        repo_url: str,
        workers: Optional[int] = None,
        timeout: int = 600,
    ) -> MedusaScanResult:
        if not MedusaIntegration.check_available():
            return MedusaScanResult(
                total_issues=0, files_scanned=0,
                security_score=100, risk_level="N/A",
                severity_breakdown={},
                error="medusa not installed. Run: pip install medusa-security",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "medusa", "scan", "--git", repo_url,
                "--format", "json", "-o", tmpdir,
            ]
            if workers:
                cmd.extend(["--workers", str(workers)])

            try:
                logger.info(f"Running medusa git scan on {repo_url}...")
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return MedusaScanResult(
                    total_issues=0, files_scanned=0,
                    security_score=100, risk_level="N/A",
                    severity_breakdown={},
                    error="medusa git scan timed out",
                )

            json_files = list(Path(tmpdir).glob("medusa-scan-*.json"))
            if not json_files:
                return MedusaScanResult(
                    total_issues=0, files_scanned=0,
                    security_score=100, risk_level="N/A",
                    severity_breakdown={},
                    error="No medusa output JSON found",
                )

            with open(json_files[0]) as f:
                data = json.load(f)

        summary = data.get("scan_summary", {})
        findings_raw = data.get("findings", [])
        severity_breakdown = data.get("severity_breakdown", {})

        findings = []
        for item in findings_raw:
            fp_info = item.get("fp_analysis", {})
            findings.append(MedusaIssue(
                scanner=item.get("scanner", "unknown"),
                file=item.get("file", ""),
                line=item.get("line", 0),
                severity=item.get("severity", "UNDEFINED"),
                confidence=item.get("confidence", "LOW"),
                issue=item.get("issue", ""),
                cwe=item.get("cwe"),
                code=item.get("code"),
                is_likely_fp=fp_info.get("is_likely_fp", False) if fp_info else False,
            ))

        return MedusaScanResult(
            total_issues=summary.get("total_issues", 0),
            files_scanned=summary.get("files_scanned", 0),
            security_score=summary.get("security_score", 100),
            risk_level=summary.get("risk_level", "N/A"),
            severity_breakdown=severity_breakdown,
            findings=findings,
        )
