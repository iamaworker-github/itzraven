from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class APISecurityAgent(CategoryAgent):
    category_name = "api"
    relevant_tags = ["api", "graphql", "jwt"]

    async def _run_static_tests(self) -> None:
        if not self._is_web_target():
            return

        import httpx
        base = self.target.rstrip("/")
        api_paths = ["/api", "/api/v1", "/graphql", "/swagger.json", "/openapi.json", "/.well-known/openid-configuration"]

        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            for path in api_paths:
                try:
                    r = await client.get(base + path)
                    if r.status_code < 400:
                        body_lower = r.text.lower()
                        info_type = "info"
                        severity = "info"
                        desc = f"API endpoint exposed: {path}"

                        if any(k in body_lower for k in ["swagger", "openapi", "graphql schema"]):
                            info_type = "info_disclosure"
                            severity = "medium"
                            desc = f"API documentation exposed: {path}"

                        self.add_finding(Finding(
                            title=f"API Endpoint: {path}",
                            severity=severity, category=info_type,
                            description=desc,
                            evidence=f"HTTP {r.status_code} | {len(r.text)} bytes",
                            remediation="Restrict access to API documentation",
                            confidence=0.9,
                        ))
                except Exception:
                    pass
