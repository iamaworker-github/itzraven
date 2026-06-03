"""
Reconnaissance agent for information gathering
"""


import asyncio
from typing import List, Dict, Any
import dns.resolver
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class ReconAgent(BaseAgent):
    """Agent for reconnaissance and information gathering"""

    def __init__(self, target: str, event_bus=None, memory_manager=None, mode: str = "pentest", scope=None):
        super().__init__("Recon Agent", target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.discovered_subdomains: List[str] = []
        self.technologies: List[str] = []
        self.mode = mode  # Store mode for blackbox testing

    async def _emit_thought(self, thought: str, thought_type: str = "reasoning", phase: str = "") -> None:
        if self.event_bus:
            try:
                from itzraven.core.events import AgentThinkingEvent
                await self.event_bus.publish_event(AgentThinkingEvent(
                    agent_name=self.name,
                    thought=thought,
                    thought_type=thought_type,
                    phase=phase or "",
                ))
            except Exception:
                pass

    async def execute(self) -> AgentResult:
        """Execute reconnaissance"""
        logger.info(f"{self.name}: Gathering intelligence on {self.target}")
        await self._emit_thought(f"Starting reconnaissance on {self.target}...", "analyzing", "recon")

        # Skip subdomain enumeration in pentest mode (blackbox only)
        if self.mode != "pentest":
            # DNS enumeration (only for OSINT/BugBounty modes)
            await self._dns_enumeration()

        # Blackbox testing (always run)
        # Technology detection
        await self._detect_technologies()

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={
                "subdomains": self.discovered_subdomains,
                "technologies": self.technologies,
            }
        )

    async def _dns_enumeration(self) -> None:
        """Perform DNS enumeration"""
        await self._emit_thought("Enumerating DNS records and subdomains...", "recon", "dns")
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            # Common subdomains to check
            common_subdomains = [
                "www", "mail", "ftp", "admin", "api", "dev", "staging",
                "test", "portal", "app", "dashboard", "blog", "shop"
            ]

            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{self.target}"
                    answers = resolver.resolve(full_domain, 'A')
                    if answers:
                        self.discovered_subdomains.append(full_domain)
                        logger.debug(f"Found subdomain: {full_domain}")
                except:
                    pass

            if self.discovered_subdomains:
                self.add_finding(Finding(
                    title="Subdomains discovered",
                    description=f"Found {len(self.discovered_subdomains)} subdomains",
                    severity="info",
                    category="recon",
                    evidence=f"Subdomains: {', '.join(self.discovered_subdomains[:5])}...",
                    confidence=1.0,
                ))

        except Exception as e:
            logger.debug(f"DNS enumeration error: {e}")

    @staticmethod
    def _find_httpx() -> str:
        import shutil
        return "httpx" if shutil.which("httpx") else "pd-httpx"

    async def _detect_technologies(self) -> None:
        """Detect web technologies and IP using httpx -ip -td"""
        import json as _json
        from urllib.parse import urlparse as _urlparse
        await self._emit_thought(f"Probing {self.target} with httpx -ip -td...", "recon", "tech_detection")
        try:
            domain = _urlparse(self.target).hostname or self.target.split('/')[0].split(':')[0]
            httpx_bin = self._find_httpx()
            httpx_cmd = [httpx_bin, "-u", domain, "-ip", "-td", "-json", "-sc", "-silent"]
            httpx_cmd.extend(self.format_auth_args())
            proc = await asyncio.create_subprocess_exec(
                *httpx_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            ip_addr = ""
            for line in stdout.decode().strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = _json.loads(line)
                    if data.get("ip") and not ip_addr:
                        ip_addr = data["ip"]
                    techs = data.get("tech", []) or []
                    if techs:
                        self.technologies.extend(techs)
                except Exception:
                    pass

            if ip_addr:
                await self._emit_thought(f"Target IP resolved via httpx: {ip_addr}", "recon", "ip_detection")

            if self.technologies:
                self.add_finding(Finding(
                    title="Technologies detected",
                    description=f"Identified {len(self.technologies)} technologies via httpx -ip -td",
                    severity="info",
                    category="recon",
                    evidence=f"Technologies: {', '.join(set(self.technologies))}",
                    confidence=0.9,
                ))
        except Exception as e:
            logger.debug(f"httpx -ip -td detection error: {e}")


