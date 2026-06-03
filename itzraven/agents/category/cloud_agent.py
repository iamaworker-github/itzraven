from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class CloudSecurityAgent(CategoryAgent):
    category_name = "cloud"
    relevant_tags = ["cloud", "container"]

    async def _run_static_tests(self) -> None:
        if self._is_web_target():
            import httpx
            try:
                r = httpx.get("http://169.254.169.254/latest/meta-data/", timeout=3)
                if r.status_code < 400:
                    self.add_finding(Finding(
                        title="Cloud Metadata Accessible",
                        severity="critical", category="cloud",
                        description="AWS/cloud metadata endpoint is accessible from target",
                        evidence=f"HTTP {r.status_code} from 169.254.169.254",
                        remediation="Block metadata service access with firewall rules",
                        confidence=0.9,
                    ))
            except Exception:
                pass
