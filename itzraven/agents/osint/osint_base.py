import asyncio
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.core.blackboard import FindingCategory, get_blackboard
from itzraven.core.graph_memory import (
    EntityType, RelationType, get_graph_memory,
)
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.core.rate_limiter import get_rate_limiter

logger = get_logger()


class OSINTBaseAgent(BaseAgent):
    """Enhanced base for all OSINT agents.

    Integrates:
    1. Comprehensive osint_methodology.md knowledge module
    2. Graph Memory with feedback loop (entities + relationships + decay)
    3. Mandatory datasets (breach, WHOIS, DNS, social, EXIF, GitHub, paste, archive, geo)
    4. Passive-only enforcement
    5. Shared utilities for DNS, HTTP, WHOIS, certificate transparency

    Without graph memory + feedback, this is just a glorified search wrapper.
    """

    passive_only: bool = True

    def __init__(
        self,
        name: str,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope: Optional[List[str]] = None,
        depth: str = "standard",
    ):
        super().__init__(name, target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.depth = depth
        self._rate_limiter = get_rate_limiter()
        self._bb = get_blackboard()
        self._findings: List[Finding] = []
        self._methodology = self._load_methodology()
        self._http_client = None
        self._graph = get_graph_memory(namespace=f"osint_{name.lower()}")

    async def initialize_toolkit(self) -> None:
        from itzraven.toolkit import BrowserAutomation, HTTPProxy, PythonRuntime
        self.browser = BrowserAutomation()
        self.proxy = HTTPProxy()
        self.shell = None
        self.python = PythonRuntime()
        self._http_client = None
        logger.debug(f"{self.name}: Passive-only toolkit initialized")

    async def cleanup_toolkit(self) -> None:
        if self.browser:
            await self.browser.stop()
        if self.proxy:
            await self.proxy.stop()
        if self._http_client:
            await self._http_client.aclose()

    def check_passive(self) -> None:
        raise RuntimeError(f"{self.name} is passive-only. Use pentest-mode agent for active ops.")

    def _load_methodology(self) -> str:
        path = Path(__file__).parents[2] / "knowledge" / "osint_methodology.md"
        if path.exists():
            try:
                return path.read_text()
            except Exception:
                pass
        return ""

    def get_methodology_section(self, section: str) -> str:
        if not self._methodology:
            return ""
        lines = self._methodology.split("\n")
        in_section = False
        result = []
        for line in lines:
            if line.startswith(f"## {section}") or line.startswith(f"### {section}"):
                in_section = True
                continue
            if in_section:
                if line.startswith("## ") and not line.startswith(f"## {section}"):
                    break
                result.append(line)
        return "\n".join(result)

    async def ensure_http(self):
        if self._http_client is None or self._http_client.is_closed:
            import httpx
            self._http_client = httpx.AsyncClient(
                timeout=15.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ItzravenOSINT/2.0"},
            )
        return self._http_client

    async def http_get(self, url: str) -> Optional[Dict[str, Any]]:
        await self._rate_limiter.acquire(url)
        try:
            client = await self.ensure_http()
            resp = await client.get(url)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "text": resp.text,
                "url": str(resp.url),
            }
        except Exception as e:
            logger.debug(f"HTTP GET failed for {url}: {e}")
            return None

    async def dns_lookup(self, domain: str, record_type: str = "A") -> List[str]:
        try:
            import dns.resolver
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(domain, record_type, lifetime=5)
            )
            return [str(r) for r in answers]
        except Exception:
            return []

    async def whois_lookup(self, query: str) -> Optional[str]:
        try:
            import whois
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: whois.whois(query)
            )
            return str(result)
        except Exception:
            return None

    async def crt_sh_lookup(self, domain: str) -> List[Dict[str, str]]:
        data = await self.http_get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if data and data["status"] == 200:
            try:
                import json
                entries = json.loads(data["text"])
                return [
                    {"name": e.get("name_value", ""), "issuer": e.get("issuer_name", "")}
                    for e in entries
                ]
            except Exception:
                pass
        return []

    def add_finding(self, title: str, description: str, severity: str = "info",
                    category: str = "osint", evidence: str = "", confidence: float = 0.8,
                    bb_category: FindingCategory = FindingCategory.OSINT_LEAD):
        finding = Finding(
            title=title, description=description, severity=severity,
            category=category, evidence=evidence, confidence=confidence,
            agent_name=self.name,
        )
        self._findings.append(finding)
        self._bb.post(
            category=bb_category,
            key=f"{self.name}:{len(self._findings)}",
            data={"title": title, "severity": severity, "description": description},
            source_agent=self.name,
        )
        return finding

    # ─── Graph Memory Integration ───────────────────────────────────────────

    def graph_add_entity(self, etype: EntityType, name: str,
                         properties: Optional[Dict] = None,
                         confidence: float = 1.0, tags: Optional[List[str]] = None):
        return self._graph.add_entity(
            etype=etype, name=name, properties=properties,
            source=self.name, confidence=confidence, tags=tags,
        )

    def graph_add_relation(self, source_id: str, target_id: str,
                           rtype: RelationType, properties: Optional[Dict] = None,
                           confidence: float = 1.0, weight: float = 1.0):
        return self._graph.add_relation(
            source_id=source_id, target_id=target_id,
            rtype=rtype, properties=properties,
            source=self.name, confidence=confidence, weight=weight,
        )

    def graph_link(self, source_name: str, source_type: EntityType,
                   target_name: str, target_type: EntityType,
                   rtype: RelationType, properties: Optional[Dict] = None,
                   confidence: float = 1.0):
        """Add source entity, target entity, and relationship in one call."""
        src = self.graph_add_entity(source_type, source_name, confidence=confidence)
        tgt = self.graph_add_entity(target_type, target_name, confidence=confidence)
        if src and tgt:
            self.graph_add_relation(src.id, tgt.id, rtype, properties, confidence)
        return src, tgt

    def graph_give_feedback(self, entity_name: str, etype: EntityType,
                            positive: bool = True, amount: float = 0.2):
        """Provide feedback to reinforce or decay graph memory."""
        key = EntityType(etype).value if isinstance(etype, str) else etype.value
        eid = f"{key}:{entity_name.lower().strip()}"
        self._graph.give_feedback(eid, positive=positive, amount=amount, source=self.name)

    def graph_find_connections(self, name_a: str, type_a: EntityType,
                                name_b: str, type_b: EntityType) -> List[List[dict]]:
        """Find paths between two entities in the graph."""
        eid_a = f"{type_a.value}:{name_a.lower().strip()}"
        eid_b = f"{type_b.value}:{name_b.lower().strip()}"
        return self._graph.find_paths(eid_a, eid_b)

    def graph_get_cluster(self, name: str, etype: EntityType) -> Dict[str, Any]:
        """Get all entities connected to this one."""
        eid = f"{etype.value}:{name.lower().strip()}"
        return self._graph.get_cluster(eid)

    def graph_persist(self):
        self._graph.persist()

    async def execute(self) -> AgentResult:
        raise NotImplementedError
