"""
SmartBruteforceAgent — Extracts paths from BackMeUp-collected URLs, builds a focused wordlist,
then runs directory bruteforce to discover hidden endpoints.
"""
import asyncio
import httpx
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Set

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class SmartBruteforceAgent(BaseAgent):
    """Extracts paths from collected URLs and runs focused directory bruteforce."""

    def __init__(self, target: str, event_bus=None, memory_manager=None,
                 collected_urls: Optional[List[str]] = None, custom_ports: Optional[List[int]] = None):
        super().__init__("Smart Brute Force", target, event_bus=event_bus, memory_manager=memory_manager)
        self.collected_urls = collected_urls or []
        self.custom_ports = custom_ports or []
        self._domain = self._extract_domain(target)
        self.discovered_endpoints: List[str] = []

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return parsed.netloc.split(":")[0] or target

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Building focused wordlist from {len(self.collected_urls)} URLs")

        wordlist = self._build_focused_wordlist()
        if not wordlist:
            logger.info(f"{self.name}: No paths extracted, skipping")
            return AgentResult(self.name, AgentStatus.COMPLETED, [], 0,
                               metadata={"discovered_endpoints": [], "wordlist_size": 0})

        logger.info(f"{self.name}: Focused wordlist has {len(wordlist)} unique paths")
        self.add_finding(Finding(
            title=f"Smart wordlist: {len(wordlist)} paths from {len(self.collected_urls)} URLs",
            severity="info", category="recon",
            evidence=f"Wordlist size: {len(wordlist)}", confidence=1.0,
        ))

        targets_to_scan = [f"https://{self._domain}", f"http://{self._domain}"]
        for port in self.custom_ports:
            if port not in [80, 443]:
                targets_to_scan.append(f"https://{self._domain}:{port}")
                targets_to_scan.append(f"http://{self._domain}:{port}")

        # Limit to first 5000 paths for speed (configurable via scope)
        scan_paths = wordlist[:5000] if len(wordlist) > 5000 else wordlist
        logger.info(f"{self.name}: Scanning {len(scan_paths)} paths across {len(targets_to_scan)} targets")

        async with httpx.AsyncClient(timeout=8, follow_redirects=False, headers=self.get_http_client_headers()) as client:
            for base_url in targets_to_scan:
                if self.should_stop:
                    logger.info(f"{self.name}: Cancelled during bruteforce")
                    break
                await self.check_pause()
                await self._bruteforce(client, base_url, scan_paths)

        return AgentResult(
            agent_name=self.name, status=AgentStatus.COMPLETED,
            findings=self.findings, execution_time=0,
            metadata={
                "discovered_endpoints": self.discovered_endpoints,
                "wordlist_size": len(wordlist),
                "wordlist": wordlist,
            },
        )

    def _load_wordlists(self) -> List[str]:
        paths: List[str] = []

        default_wl = Path(__file__).parent.parent / "data" / "wordlists" / "default_pentest_wordlist.txt"
        if default_wl.exists():
            try:
                content = default_wl.read_text(encoding="utf-8", errors="ignore")
                for line in content.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        paths.append(line if line.startswith("/") else "/" + line)
                logger.info(f"{self.name}: Loaded default wordlist ({len(paths)} paths)")
            except Exception as e:
                logger.debug(f"{self.name}: Failed to load default wordlist: {e}")

        return paths

    def _build_focused_wordlist(self) -> List[str]:
        paths: Set[str] = set()
        all_paths = self._load_wordlists()
        for p in all_paths:
            paths.add(p)
        for url in self.collected_urls:
            try:
                parsed = urlparse(url if "://" in url else f"https://{url}")
                path = parsed.path.rstrip("/")
                if not path or path == "/":
                    continue
                parts = path.split("/")
                for i in range(1, len(parts) + 1):
                    sub = "/" + "/".join(parts[1:i])
                    if sub:
                        paths.add(sub)
                ext = Path(path).suffix
                if ext:
                    base = path[: -len(ext)]
                    if base and base != "/":
                        paths.add(base)
            except Exception:
                continue
        sorted_paths = sorted(paths, key=lambda p: (len(p), p))
        logger.info(f"{self.name}: {len(sorted_paths)} total paths in wordlist")
        return sorted_paths

    async def _bruteforce(self, client: httpx.AsyncClient, base_url: str, wordlist: List[str]) -> None:
        header = self.get_http_client_headers({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        for path in wordlist:
            if self.should_stop:
                logger.info(f"{self.name}: Cancelled mid-bruteforce")
                break
            await self.check_pause()
            try:
                url = f"{base_url.rstrip('/')}{path}"
                resp = await client.get(url, headers=header, timeout=5)
                if resp.status_code in [200, 204, 301, 302, 401, 403, 500]:
                    if resp.status_code == 200 and self._is_empty_or_redirect(resp):
                        continue
                    self.discovered_endpoints.append(path)
                    sev = "medium" if resp.status_code in [401, 403] else "low"
                    self.add_finding(Finding(
                        title=f"Discovered: {path} ({resp.status_code})",
                        description=f"Path accessible: {url}",
                        severity=sev, category="recon",
                        evidence=f"HTTP {resp.status_code} at {url}",
                        confidence=0.85,
                    ))
                    if self.event_bus:
                        try:
                            from itzraven.core.events import FindingDiscoveredEvent
                            await self.event_bus.publish_event(FindingDiscoveredEvent(
                                agent_name=self.name, title=f"Discovered: {path}",
                                severity=sev, category="recon",
                                evidence=f"HTTP {resp.status_code} at {url}",
                                target=self.target, confidence=0.85,
                            ))
                        except Exception:
                            pass
            except Exception:
                continue

    def _is_empty_or_redirect(self, resp) -> bool:
        text = resp.text.strip()
        if not text or len(text) < 50:
            return True
        if resp.status_code in [301, 302]:
            return True
        return False

