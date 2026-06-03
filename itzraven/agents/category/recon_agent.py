from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class ReconOSINTAgent(CategoryAgent):
    category_name = "recon"
    relevant_tags = ["osint", "network"]

    TECHNOLOGIES = {
        "nginx": ["server: nginx", "nginx/"],
        "apache": ["server: apache", "apache/"],
        "cloudflare": ["cloudflare", "__cfduid"],
        "wordpress": ["wp-content", "wp-includes", "wordpress"],
        "django": ["csrftoken", "django"],
        "rails": ["rails", "ruby on rails"],
        "laravel": ["laravel", "_token"],
        "express": ["x-powered-by: express"],
        "node.js": ["node.js", "nodejs"],
        "python": ["python", "flask", "django"],
        "java": ["java", "jsp", "servlet"],
        "iis": ["iis", "asp.net", "x-aspnet-version"],
    }

    async def _run_static_tests(self) -> None:
        if not self._is_web_target():
            return

        import httpx
        base = self.target.rstrip("/")

        try:
            r = httpx.get(base, timeout=10, follow_redirects=True)
            headers = {k.lower(): v.lower() for k, v in dict(r.headers).items()}
            body = r.text.lower()

            detected = []
            for tech, keywords in self.TECHNOLOGIES.items():
                for kw in keywords:
                    if kw in str(headers) or kw in body[:5000]:
                        detected.append(tech)
                        break

            if detected:
                self.add_finding(Finding(
                    title=f"Technologies: {', '.join(detected[:5])}",
                    severity="info", category="recon",
                    description=f"Detected technologies on {base}",
                    evidence=f"Server headers + body signatures matched",
                    remediation="N/A",
                    confidence=0.85,
                ))

            if r.status_code == 200:
                self.add_finding(Finding(
                    title="Target Reachable",
                    severity="info", category="recon",
                    description=f"{base} returned HTTP {r.status_code} ({len(r.text)} bytes)",
                    evidence=f"HTTP {r.status_code} | {len(r.text)} bytes",
                    remediation="N/A",
                    confidence=1.0,
                ))
        except Exception as e:
            self.add_finding(Finding(
                title="Target Unreachable",
                severity="medium", category="recon",
                description=f"Cannot connect to {base}: {e}",
                evidence=str(e),
                remediation="Check target availability",
                confidence=1.0,
            ))
