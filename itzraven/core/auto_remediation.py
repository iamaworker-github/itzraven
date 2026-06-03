"""
AutoRemediation — Auto-fix vulnerabilities + GitHub PR generation.
Redamon/CypherFix-inspired: finds vuln → implements fix → opens PR.
"""
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class PatchSuggestion:
    finding_title: str
    file_path: str
    line_number: int
    original: str
    patched: str
    description: str


class AutoRemediation:
    def __init__(self, repo_path: Optional[str] = None):
        self.repo_path = Path(repo_path or os.getcwd())
        self.patches: List[PatchSuggestion] = []

    def _is_git_repo(self) -> bool:
        return (self.repo_path / ".git").exists()

    def suggest_patch(self, finding: Dict[str, Any], file_path: str, original: str, patched: str, line: int = 0) -> Optional[PatchSuggestion]:
        ps = PatchSuggestion(
            finding_title=finding.get("title", "Unknown"),
            file_path=file_path,
            line_number=line,
            original=original,
            patched=patched,
            description=f"Fix: {finding.get('remediation', '')}",
        )
        self.patches.append(ps)
        return ps

    def apply_patches(self) -> int:
        applied = 0
        for patch in self.patches:
            filepath = self.repo_path / patch.file_path
            if not filepath.exists():
                logger.debug(f"  File not found: {patch.file_path}")
                continue
            try:
                content = filepath.read_text()
                if patch.original in content:
                    content = content.replace(patch.original, patch.patched, 1)
                    filepath.write_text(content)
                    applied += 1
                    logger.info(f"  ✅ Applied patch: {patch.file_path} L{patch.line_number}")
                else:
                    logger.debug(f"  Pattern not found in {patch.file_path}")
            except Exception as e:
                logger.debug(f"  Failed to patch {patch.file_path}: {e}")
        return applied

    def create_pr(self, branch_name: str = "fix/auto-remediation", title: str = "Auto-Remediation: Security Fixes") -> Dict[str, Any]:
        if not self._is_git_repo():
            return {"success": False, "error": "Not a git repository"}

        try:
            subprocess.run(["git", "checkout", "-b", branch_name], cwd=str(self.repo_path), capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=str(self.repo_path), capture_output=True)
            commit_msg = f"{title}\n\n"
            for p in self.patches:
                commit_msg += f"- {p.finding_title}: {p.file_path} L{p.line_number}\n"
            subprocess.run(["git", "commit", "-m", commit_msg], cwd=str(self.repo_path), capture_output=True)

            result = subprocess.run(["git", "push", "origin", branch_name], cwd=str(self.repo_path), capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"  🚀 Created PR branch: {branch_name}")
                return {"success": True, "branch": branch_name, "commit_msg": commit_msg}
            return {"success": False, "error": result.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_patch_from_finding(self, finding: Dict[str, Any]) -> Optional[PatchSuggestion]:
        category = finding.get("category", "")
        remediation = finding.get("remediation", "")
        title = finding.get("title", "")

        if "sql" in category and "parameterized" in remediation.lower():
            return PatchSuggestion(
                finding_title=title, file_path="",
                line_number=0, original="", patched="",
                description="Use prepared statements: cursor.execute('SELECT * FROM users WHERE id = ?', [user_id])",
            )
        if "xss" in category and ("encode" in remediation.lower() or "escape" in remediation.lower()):
            return PatchSuggestion(
                finding_title=title, file_path="",
                line_number=0, original="", patched="",
                description="Use html.escape() or Content-Security-Policy header",
            )
        return None


def get_auto_remediation(repo_path: Optional[str] = None) -> AutoRemediation:
    return AutoRemediation(repo_path)
