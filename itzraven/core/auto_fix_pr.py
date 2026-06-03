"""
Auto Remediation PR — finding se lekar GitHub PR tak full cycle.
LLM fix suggestion generate kare → patch apply kare → PR create kare.
"""
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class FixSuggestion:
    finding_id: str
    title: str
    category: str
    severity: str
    file_path: str
    original_code: str
    fixed_code: str
    description: str
    language: str = ""
    branch_name: str = ""


class AutoFixPR:
    def __init__(self, repo_path: Optional[str] = None, github_token: Optional[str] = None):
        self._repo_path = Path(repo_path or os.getcwd()) if repo_path else self._detect_repo()
        self._token = github_token or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        self._fixes: List[FixSuggestion] = []
        self._llm = None

    def _detect_repo(self) -> Optional[Path]:
        try:
            r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                               capture_output=True, text=True, timeout=5)
            return Path(r.stdout.strip()) if r.returncode == 0 else None
        except Exception:
            return None

    @property
    def is_git_repo(self) -> bool:
        return self._repo_path and (self._repo_path / ".git").exists()

    async def _get_llm(self):
        if self._llm is None:
            from itzraven.agents.llm_client import LLMClient
            self._llm = LLMClient()
        return self._llm

    async def generate_fix(self, finding: Dict[str, Any]) -> Optional[FixSuggestion]:
        """LLM se finding ke liye fix suggestion generate karaye."""
        if not finding.get("file_path") and not finding.get("code_snippet"):
            logger.debug(f"Cannot generate fix for {finding.get('title')}: no file_path or code_snippet")
            return None

        llm = await self._get_llm()
        code_snippet = finding.get("code_snippet", "") or ""
        file_path = finding.get("file_path", "") or "unknown"
        lang = Path(file_path).suffix.lstrip(".") or "python"

        prompt = f"""You are a security engineer fixing a vulnerability.

Vulnerability: {finding.get('title', '')}
Category: {finding.get('category', '')}
Severity: {finding.get('severity', '')}
Description: {finding.get('description', '')[:500]}
Remediation: {finding.get('remediation', '')[:500]}
File: {file_path}
Code:
```{lang}
{code_snippet[:1000]}
```

Generate a fix for this vulnerability. Return ONLY the fixed code.

Respond in JSON:
{{
    "original_code": "exact code to replace",
    "fixed_code": "replacement code with fix applied",
    "description": "what was changed and why"
}}"""

        try:
            response = await llm.generate(
                prompt=prompt,
                system="You are a security engineer. Fix the vulnerability. Return valid JSON only.",
                max_tokens=800,
                temperature=0.1,
                task="remediation_fix",
            )
            text = response.text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            fix_data = json.loads(text)

            suggestion = FixSuggestion(
                finding_id=finding.get("finding_id", "unknown"),
                title=finding.get("title", "Unknown"),
                category=finding.get("category", ""),
                severity=finding.get("severity", "info"),
                file_path=file_path,
                original_code=fix_data.get("original_code", ""),
                fixed_code=fix_data.get("fixed_code", ""),
                description=fix_data.get("description", "No description"),
                language=lang,
            )
            self._fixes.append(suggestion)
            return suggestion
        except Exception as e:
            logger.debug(f"LLM fix generation failed: {e}")
            return self._template_fix(finding, file_path, lang)

    def _template_fix(self, finding: Dict[str, Any], file_path: str, lang: str) -> Optional[FixSuggestion]:
        """Template-based fix when LLM fails."""
        category = (finding.get("category") or "").lower()
        code_snippet = (finding.get("code_snippet") or "")[:200]

        patches = {
            "sql_injection": {
                "original": code_snippet,
                "fixed": code_snippet.replace("$query", "$stmt = $pdo->prepare($query); $stmt->execute()")
                                  if "$query" in code_snippet else code_snippet,
                "desc": "Use parameterized queries instead of string concatenation",
            },
            "xss": {
                "original": code_snippet,
                "fixed": code_snippet.replace("echo $", "echo htmlspecialchars($, ENT_QUOTES, 'UTF-8')")
                                    if "echo" in code_snippet else code_snippet,
                "desc": "Apply output encoding for XSS prevention",
            },
        }

        for key, patch in patches.items():
            if key in category:
                sug = FixSuggestion(
                    finding_id=finding.get("finding_id", "unknown"),
                    title=finding.get("title", "Unknown"),
                    category=category,
                    severity=finding.get("severity", "info"),
                    file_path=file_path,
                    original_code=patch["original"],
                    fixed_code=patch["fixed"],
                    description=patch["desc"],
                    language=lang,
                )
                self._fixes.append(sug)
                return sug
        return None

    def apply_patches(self) -> int:
        """Apply fixes to local files."""
        if not self._repo_path:
            return 0
        applied = 0
        for fix in self._fixes:
            filepath = self._repo_path / fix.file_path
            if not filepath.exists():
                logger.debug(f"File not found: {fix.file_path}")
                continue
            try:
                content = filepath.read_text()
                if fix.original_code in content:
                    content = content.replace(fix.original_code, fix.fixed_code, 1)
                    filepath.write_text(content)
                    applied += 1
                    logger.info(f"✅ Applied fix to {fix.file_path}")
                else:
                    logger.debug(f"Original code not found in {fix.file_path}")
            except Exception as e:
                logger.debug(f"Failed to patch {fix.file_path}: {e}")
        return applied

    def create_github_pr(self, repo: str, branch: str = "fix/auto-remediation") -> Dict[str, Any]:
        """Create GitHub PR via API."""
        if not self._token:
            return {"success": False, "error": "No GitHub token configured"}
        if not self._fixes:
            return {"success": False, "error": "No fixes to submit"}

        # Build PR body
        body_lines = ["## Auto-Generated Security Fixes\n"]
        for fix in self._fixes:
            body_lines.append(f"### {fix.title}")
            body_lines.append(f"- **Category:** {fix.category}")
            body_lines.append(f"- **Severity:** {fix.severity}")
            body_lines.append(f"- **File:** {fix.file_path}")
            body_lines.append(f"- **Description:** {fix.description}")
            body_lines.append(f"```diff\n- {fix.original_code[:100]}\n+ {fix.fixed_code[:100]}\n```\n")

        title = f"[Itzraven] Security Fix: {len(self._fixes)} vulnerability(ies)"
        body = "\n".join(body_lines)

        try:
            import urllib.request
            import urllib.error

            # Create branch
            subprocess.run(["git", "checkout", "-b", branch], cwd=str(self._repo_path), capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=str(self._repo_path), capture_output=True)
            subprocess.run(["git", "commit", "-m", title], cwd=str(self._repo_path), capture_output=True)
            push = subprocess.run(["git", "push", "origin", branch], cwd=str(self._repo_path),
                                  capture_output=True, text=True)
            if push.returncode != 0:
                return {"success": False, "error": push.stderr}

            # Create PR via GitHub API
            api_url = f"https://api.github.com/repos/{repo}/pulls"
            pr_data = json.dumps({
                "title": title,
                "body": body,
                "head": branch,
                "base": "main",
            }).encode()

            req = urllib.request.Request(api_url, data=pr_data,
                headers={
                    "Authorization": f"token {self._token}",
                    "Content-Type": "application/json",
                },
                method="POST")

            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read())
                pr_url = result.get("html_url", "")
                logger.info(f"🚀 PR created: {pr_url}")
                return {"success": True, "url": pr_url, "branch": branch}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_branch_name(self) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        cats = "_".join(set(f.category[:8] for f in self._fixes)) or "fix"
        return f"itzraven/{cats}_{ts}"


_instance_autofix: Optional[AutoFixPR] = None


def get_autofix_pr(repo_path: Optional[str] = None, github_token: Optional[str] = None) -> AutoFixPR:
    global _instance_autofix
    if _instance_autofix is None:
        _instance_autofix = AutoFixPR(repo_path=repo_path, github_token=github_token)
    return _instance_autofix
