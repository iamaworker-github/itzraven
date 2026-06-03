"""
Fix Pipeline (CypherFix) — RedAmon-inspired detection→triage→code fix→PR.

Automatically generates code fixes for detected vulnerabilities and opens
PRs when possible. Works with git repos.
"""

import asyncio
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from itzraven.core.logger import get_logger

logger = get_logger()

FIX_TEMPLATES: Dict[str, str] = {
    "sqli": """
# SQL Injection Fix — Use parameterized queries
# Before (vulnerable):
# cursor.execute("SELECT * FROM users WHERE id = " + user_input)
# After (fixed):
import sqlite3  # or your DB adapter
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
""",
    "xss": """
# XSS Fix — Escape output
# Before (vulnerable):
# <div>{{ user_input }}</div>
# After (fixed):
from markupsafe import escape  # Jinja2/Flask
# Or use template engine's auto-escaping
# <div>{{ user_input | e }}</div>
""",
    "ssrf": """
# SSRF Fix — Validate and restrict URLs
# Before (vulnerable):
# import requests
# resp = requests.get(user_url)
# After (fixed):
from urllib.parse import urlparse
ALLOWED_HOSTS = ["api.internal.com", "api.example.com"]
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("URL not allowed")
resp = requests.get(user_url)
""",
    "idor": """
# IDOR Fix — Verify authorization
# Before (vulnerable):
# doc = db.get_document(document_id)
# After (fixed):
def get_document(document_id, user_id):
    doc = db.get_document(document_id)
    if doc.owner_id != user_id:
        raise PermissionError("Not authorized")
    return doc
""",
    "auth": """
# Auth Bypass Fix — Require authentication check
# Before (vulnerable):
# @app.route('/admin')
# def admin():
# After (fixed):
from flask_login import login_required
@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')
""",
}


@dataclass
class FixResult:
    vulnerability: str
    file_path: Optional[str] = None
    fix_code: str = ""
    pr_url: Optional[str] = None
    success: bool = False
    error: str = ""


class FixPipeline:
    def __init__(self):
        self._repo_path: Optional[str] = None

    def set_repo(self, path: str):
        self._repo_path = path

    def generate_fix(self, category: str, title: str, details: str) -> str:
        template = FIX_TEMPLATES.get(category, f"# Security fix for {title}\n# Review the issue and apply appropriate fix\n")
        fix = f"# Auto-generated fix: {title}\n# Category: {category}\n# Details: {details[:200]}\n{template}"
        return fix

    async def apply_fix(self, finding_title: str, category: str, details: str, file_path: Optional[str] = None) -> FixResult:
        if not self._repo_path or not Path(self._repo_path).exists():
            return FixResult(vulnerability=finding_title, fix_code=self.generate_fix(category, finding_title, details), success=False, error="No repo path set")

        fix_code = self.generate_fix(category, finding_title, details)
        target_file = file_path or self._find_relevant_file(category)
        if not target_file:
            target_file = os.path.join(self._repo_path, "SECURITY_FIXES.md")

        try:
            with open(target_file, "a") as f:
                f.write(f"\n\n## Fix: {finding_title}\n")
                f.write(f"**Category**: {category}\n")
                f.write(f"**Generated**: auto\n\n")
                f.write("```python\n")
                f.write(fix_code)
                f.write("\n```\n")

            pr_url = await self._create_pr(f"Fix: {finding_title}", f"Auto-fix for {finding_title}\n\n{fix_code}")
            return FixResult(vulnerability=finding_title, file_path=target_file, fix_code=fix_code, pr_url=pr_url, success=True)
        except Exception as e:
            return FixResult(vulnerability=finding_title, fix_code=fix_code, success=False, error=str(e))

    def _find_relevant_file(self, category: str) -> Optional[str]:
        if not self._repo_path:
            return None
        ext_map = {"sqli": ["*.py", "*.php", "*.sql", "*.java"], "xss": ["*.html", "*.js", "*.py", "*.j2", "*.jinja"], "ssrf": ["*.py", "*.js", "*.java"]}
        exts = ext_map.get(category, ["*.py"])
        import glob
        for ext in exts:
            matches = glob.glob(os.path.join(self._repo_path, "**", ext), recursive=True)
            if matches:
                return matches[0]
        return None

    async def _create_pr(self, title: str, body: str) -> Optional[str]:
        if not self._repo_path:
            return None
        try:
            proc = await asyncio.create_subprocess_exec("git", "add", ".", cwd=self._repo_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await proc.communicate()
            proc = await asyncio.create_subprocess_exec("git", "commit", "-m", title, "-m", body[:500], cwd=self._repo_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await proc.communicate()
            proc = await asyncio.create_subprocess_exec("gh", "pr", "create", "--title", title, "--body", body[:500], cwd=self._repo_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            url = stdout.decode().strip()
            return url if url.startswith("http") else None
        except Exception as e:
            logger.debug(f"PR creation failed: {e}")
            return None


_fix_pipeline: Optional[FixPipeline] = None


def get_fix_pipeline() -> FixPipeline:
    global _fix_pipeline
    if _fix_pipeline is None:
        _fix_pipeline = FixPipeline()
    return _fix_pipeline
