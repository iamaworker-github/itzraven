from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class IdentityAccessAgent(CategoryAgent):
    category_name = "identity"
    relevant_tags = ["auth", "zero-trust", "secret-scan"]

    async def _run_static_tests(self) -> None:
        if not self._is_web_target():
            return

        import httpx
        base = self.target.rstrip("/")
        auth_paths = ["/login", "/admin", "/wp-admin", "/.env", "/.git/config", "/admin/"]
        auth_payloads = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "administrator", "password": "administrator"},
        ]

        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            for path in ["/.env", "/.git/config", "/backup.sql", "/env", "/.aws/credentials"]:
                try:
                    r = await client.get(base + path)
                    if r.status_code < 400 and len(r.text) > 10:
                        sensitive_keywords = ["aws_secret", "api_key", "password=", "SECRET_KEY", "DB_PASSWORD", "sk-"]
                        if any(k in r.text.lower() for k in sensitive_keywords):
                            self.add_finding(Finding(
                                title=f"Sensitive File Exposed: {path}",
                                severity="critical", category="secret_exposure",
                                description=f"Sensitive file accessible at {base}{path}",
                                evidence=f"HTTP {r.status_code} | Contains credential patterns",
                                remediation="Remove sensitive files from web root",
                                confidence=0.95,
                            ))
                except Exception:
                    pass

            for payload in auth_payloads[:2]:
                for path in ["/login", "/admin", "/api/login"]:
                    try:
                        r = await client.post(base + path, data=payload, timeout=5)
                        if r.status_code == 200 and "invalid" not in r.text.lower()[:100]:
                            self.add_finding(Finding(
                                title=f"Default Credentials at {path}",
                                severity="high", category="auth",
                                description=f"Login succeeded with {payload['username']}:{payload['password']}",
                                evidence=f"HTTP 200 on {path} with default creds",
                                remediation="Change default credentials immediately",
                                confidence=0.85,
                            ))
                    except Exception:
                        pass
