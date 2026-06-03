from pathlib import Path
from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class CodeAnalysisAgent(CategoryAgent):
    category_name = "code"
    relevant_tags = ["code-review", "secret-scan", "dep-check"]

    SECRET_PATTERNS = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        ("Generic API Key", r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
        ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        ("JWT Token", r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        ("Password in Code", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
        ("Connection String", r"(?i)(connectionstring|conn_str)\s*[=:]\s*['\"][^'\"]+['\"]"),
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
    ]

    async def _run_static_tests(self) -> None:
        target_path = Path(self.target)
        if not target_path.exists():
            return

        import re
        scanned = 0
        secrets_found = 0

        for filepath in target_path.rglob("*"):
            if not filepath.is_file():
                continue
            ext = filepath.suffix.lower()
            if ext in (".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".bin", ".jpg", ".png", ".gif", ".svg", ".ico", ".ttf"):
                continue
            if filepath.name.startswith("."):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                scanned += 1

                for name, pattern in self.SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches[:1]:
                        relpath = filepath.relative_to(target_path)
                        self.add_finding(Finding(
                            title=f"{name} Found: {relpath}",
                            severity="high", category="secret_scan",
                            description=f"Potential secret in {relpath}",
                            evidence=f"Pattern '{name}' matched in {relpath}",
                            remediation="Remove secrets from code, use environment variables",
                            confidence=0.7,
                        ))
                        secrets_found += 1
                        if secrets_found >= 5:
                            return
            except Exception:
                continue

        if scanned > 0 and secrets_found == 0:
            self.add_finding(Finding(
                title="Code Scan Complete",
                severity="info", category="code_scan",
                description=f"Scanned {scanned} files, no secrets found",
                evidence="Clean scan result",
                confidence=1.0,
            ))

        logger.info(f"{self.name}: Scanned {scanned} files, found {secrets_found} potential secrets")
