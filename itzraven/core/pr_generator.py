"""
Auto-fix PR Suggestions — generate ready-to-merge GitHub PRs.

Strix v0.8.0 inspired: takes validated findings with code locations
and generates GitHub PRs with suggested fixes.

Supports:
  - GitHub API integration (create PR from findings)
  - Markdown PR description with CVSS, CWE, code diffs
  - Multi-finding PR (group related fixes)
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.cvss_scorer import score_finding, generate_finding_xml

logger = get_logger()


@dataclass
class PRSuggestion:
    finding_id: str
    title: str
    severity: str
    cvss_score: float
    cwe_id: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    description: str
    remediation: str
    code_snippet: Optional[str] = None
    patch_diff: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "remediation": self.remediation,
            "code_snippet": self.code_snippet,
            "patch_diff": self.patch_diff,
        }


class PRGenerator:
    def __init__(self, repo_path: Optional[str] = None):
        self._repo_path = repo_path or self._detect_repo()
        self._suggestions: List[PRSuggestion] = []

    @staticmethod
    def _detect_repo() -> Optional[str]:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    @property
    def repo_path(self) -> Optional[str]:
        return self._repo_path

    def add_suggestion(self, finding: dict) -> PRSuggestion:
        cvss = score_finding(
            category=finding.get("category", "default"),
            severity=finding.get("severity", "info"),
            has_poc=bool(finding.get("proof_of_concept")),
        )
        suggestion = PRSuggestion(
            finding_id=finding.get("finding_id", "unknown"),
            title=finding.get("title", ""),
            severity=cvss.severity,
            cvss_score=cvss.score,
            cwe_id=finding.get("cwe_id"),
            file_path=finding.get("file_path"),
            line_number=finding.get("line_number"),
            description=finding.get("description", ""),
            remediation=finding.get("remediation", ""),
            code_snippet=finding.get("code_snippet"),
            patch_diff=self._generate_patch(finding),
        )
        self._suggestions.append(suggestion)
        return suggestion

    def _generate_patch(self, finding: dict) -> Optional[str]:
        file_path = finding.get("file_path")
        if not file_path or not self._repo_path:
            return None
        full_path = Path(self._repo_path) / file_path
        if not full_path.exists():
            return None
        try:
            content = full_path.read_text()
            line = finding.get("line_number")
            if line and finding.get("remediation"):
                return self._create_patch_diff(file_path, content, line, finding["remediation"])
        except Exception:
            return None
        return None

    def _create_patch_diff(self, file_path: str, content: str, line: int, remediation: str) -> str:
        lines = content.split("\n")
        context_start = max(0, line - 3)
        context_end = min(len(lines), line + 3)
        diff_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -{context_start + 1},{context_end - context_start} +{context_start + 1},{context_end - context_start} @@",
        ]
        for i in range(context_start, context_end):
            if i == line - 1:
                diff_lines.append(f"-{lines[i]}")
                diff_lines.append(f"+// FIX: {remediation[:80]}")
                diff_lines.append(f"+{lines[i]}")
            else:
                diff_lines.append(f" {lines[i]}")
        return "\n".join(diff_lines)

    def generate_pr_description(self, repo_name: Optional[str] = None) -> str:
        if not self._suggestions:
            return ""
        critical = [s for s in self._suggestions if s.severity == "critical"]
        high = [s for s in self._suggestions if s.severity == "high"]
        medium = [s for s in self._suggestions if s.severity == "medium"]

        lines = [
            f"# 🔒 Security Auto-Fix: {len(self._suggestions)} vulnerabilities found",
            "",
            f"Itzraven discovered {len(self._suggestions)} security issues in {repo_name or 'your repository'}.",
            "This PR contains suggested fixes for the following findings:",
            "",
        ]
        if critical:
            lines.append(f"### 🔴 Critical ({len(critical)})")
            for s in critical:
                lines.append(f"- **{s.title}** (CVSS {s.cvss_score}) — {s.file_path}:{s.line_number}")
            lines.append("")

        if high:
            lines.append(f"### 🟠 High ({len(high)})")
            for s in high:
                lines.append(f"- **{s.title}** (CVSS {s.cvss_score}) — {s.file_path}:{s.line_number}")
            lines.append("")

        if medium:
            lines.append(f"### 🟡 Medium ({len(medium)})")
            for s in medium:
                lines.append(f"- **{s.title}** (CVSS {s.cvss_score}) — {s.file_path}:{s.line_number}")
            lines.append("")

        lines.extend([
            "## Details",
            "",
        ])
        for s in self._suggestions:
            lines.extend([
                f"### {s.title}",
                f"- **Severity:** {s.severity.upper()}",
                f"- **CVSS:** {s.cvss_score}",
                f"- **CWE:** {s.cwe_id or 'N/A'}",
                f"- **Location:** {s.file_path}:{s.line_number}" if s.file_path else "",
                f"- **Description:** {s.description[:200]}",
                f"- **Remediation:** {s.remediation[:200]}",
                "",
            ])

        lines.extend([
            "---",
            "_Generated by Itzraven Security Platform_",
        ])
        return "\n".join(lines)

    def create_github_pr(self, token: str, repo: str, branch: str = "main", title_prefix: str = "fix: security") -> Optional[str]:
        if not self._suggestions:
            logger.warning("No suggestions to create PR")
            return None
        import urllib.request
        import urllib.error

        pr_title = f"{title_prefix} - {len(self._suggestions)} vulnerabilities found"
        pr_body = self.generate_pr_description(repo)

        branch_name = f"itzraven-security-fix-{self._suggestions[0].finding_id[:8]}"

        data = json.dumps({
            "title": pr_title,
            "body": pr_body,
            "head": branch_name,
            "base": branch,
        }).encode()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github.v3+json",
        }
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/pulls",
            data=data, headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read())
                pr_url = result.get("html_url", "")
                logger.success(f"PR created: {pr_url}")
                return pr_url
        except urllib.error.HTTPError as e:
            logger.error(f"GitHub API error: {e.code} {e.read().decode()[:200]}")
            return None
        except Exception as e:
            logger.error(f"Failed to create PR: {e}")
            return None

    def get_suggestions(self) -> List[PRSuggestion]:
        return self._suggestions.copy()


_generator: Optional[PRGenerator] = None


def get_pr_generator(repo_path: Optional[str] = None) -> PRGenerator:
    global _generator
    if _generator is None:
        _generator = PRGenerator(repo_path=repo_path)
    return _generator
