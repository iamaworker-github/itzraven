import httpx
from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class WebSecurityAgent(CategoryAgent):
    category_name = "web"
    relevant_tags = ["sqli", "xss", "ssrf", "command-injection", "idor", "auth", "xxe", "csrf", "path-traversal"]

    async def _run_static_tests(self) -> None:
        if not self._is_web_target():
            return

        base = self.target.rstrip("/")
        sqli_payloads = ["' OR '1'='1", "' UNION SELECT 1--", "1' AND 1=1--"]
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        paths = ["/", "/api", "/admin", "/login", "/search", "/user", "/product"]

        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            for path in paths[:5]:
                url = base + path
                for payload in sqli_payloads[:2]:
                    try:
                        r = await client.get(url, params={"id": payload, "q": payload})
                        body = r.text.lower()
                        if any(e in body for e in ["sql", "syntax", "mysql", "unclosed quotation mark"]):
                            self.add_finding(Finding(
                                title=f"SQL Injection at {path}",
                                severity="critical", category="injection",
                                description=f"Potential SQL injection at {url}",
                                evidence=f"SQL error detected with payload: {payload}",
                                remediation="Use parameterized queries",
                                confidence=0.7,
                            ))
                            break
                    except Exception:
                        pass

                for payload in xss_payloads[:1]:
                    try:
                        r = await client.get(url, params={"q": payload, "search": payload})
                        if payload in r.text:
                            self.add_finding(Finding(
                                title=f"Reflected XSS at {path}",
                                severity="high", category="xss",
                                description=f"XSS payload reflected at {url}",
                                evidence=f"Payload found in response",
                                remediation="HTML-encode all user input",
                                confidence=0.8,
                            ))
                            break
                    except Exception:
                        pass
