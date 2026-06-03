"""
BackMeUpAgent — Go-tool-powered URL collector.
Runs waybackurls, gau, gauplus, cariddi, katana, gospider, hakrawler, crawley.
Filters out subdomains — only keeps main domain + www. Supports custom ports.
"""
import asyncio
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class BackMeUpAgent(BaseAgent):
    """Collects URLs via Go tools + filters for root domain only (no subdomains)."""

    def __init__(self, target: str, event_bus=None, memory_manager=None, scope=None, custom_ports: Optional[List[int]] = None, exclude_subs: bool = True):
        name = "BackMeUp Agent"
        super().__init__(name, target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self._domain, self._port = self._extract_domain_port(target)
        self._custom_ports = custom_ports or ([self._port] if self._port else [])
        self._exclude_subs = exclude_subs
        self._collected_urls: List[str] = []
        self._filtered_urls: List[str] = []
        self._leaked_data: List[str] = []
        self._run_stats: Dict[str, int] = {}

    def _extract_domain_port(self, target: str) -> tuple:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.netloc.split(":")[0] or parsed.path.split("/")[0] or target
        port = None
        try:
            if ":" in parsed.netloc:
                port = int(parsed.netloc.split(":")[1])
        except (ValueError, IndexError):
            port = None
        return host, port

    def _is_root_domain(self, host: str) -> bool:
        host = host.lower().split(":")[0]
        domain = self._domain.lower()
        return host == domain or host == f"www.{domain}"

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Running Go tools for {self._domain}")
        targets = [self._domain]
        if self._domain != f"www.{self._domain}":
            targets.append(f"www.{self._domain}")
        for port in self._custom_ports:
            if port not in [80, 443]:
                targets.append(f"{self._domain}:{port}")

        all_urls: Set[str] = set()
        for t in targets:
            if self.should_stop:
                logger.info(f"{self.name}: Cancelled during target iteration")
                break
            await self.check_pause()
            urls = await self._run_all_tools(t)
            all_urls.update(urls)

        self._collected_urls = []
        self._filtered_urls = []
        for url in all_urls:
            try:
                parsed = urlparse(url if "://" in url else f"https://{url}")
                if self._is_root_domain(parsed.netloc):
                    self._collected_urls.append(url)
                else:
                    self._filtered_urls.append(url)
            except Exception:
                self._filtered_urls.append(url)

        stats = ", ".join(f"{k}:{v}" for k, v in self._run_stats.items())
        logger.info(f"{self.name}: {len(self._collected_urls)} root URLs ({len(self._filtered_urls)} subs filtered) [{stats}]")

        if self.should_stop:
            logger.info(f"{self.name}: Cancelled, returning partial results")
            return AgentResult(
                agent_name=self.name, status=AgentStatus.FAILED,
                findings=self.findings, execution_time=0,
                metadata={"domain": self._domain, "total_urls": len(all_urls),
                          "root_urls": len(self._collected_urls),
                          "cancelled": True},
            )

        self._analyze_leaks()
        self.add_finding(Finding(
            title=f"BackMeUp: {len(self._collected_urls)} URLs for {self._domain}",
            severity="info", category="recon",
            description=f"Go tools: {stats}. Filtered {len(self._filtered_urls)} subdomains.",
            evidence=f"Root URLs: {len(self._collected_urls)}, Filtered: {len(self._filtered_urls)}",
            confidence=1.0,
        ))
        if self._collected_urls:
            self.add_finding(Finding(
                title=f"Sample ({min(10, len(self._collected_urls))} of {len(self._collected_urls)})",
                severity="info", category="recon",
                evidence="\n".join(self._collected_urls[:10]), confidence=0.9,
            ))

        return AgentResult(
            agent_name=self.name, status=AgentStatus.COMPLETED,
            findings=self.findings, execution_time=0,
            metadata={
                "domain": self._domain, "total_urls": len(all_urls),
                "root_urls": len(self._collected_urls),
                "filtered_subdomains": len(self._filtered_urls),
                "collected_urls": self._collected_urls[:200],
                "custom_ports": self._custom_ports,
                "tool_stats": self._run_stats,
            },
        )

    async def _run_tool(self, cmd: List[str], input_data: Optional[str] = None, name: str = "tool") -> Set[str]:
        if self.should_stop:
            return set()
        await self.check_pause()
        urls: Set[str] = set()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(
                    input=input_data.encode() if input_data else None
                ), timeout=120)
                for line in stdout.decode("utf-8", errors="ignore").split("\n"):
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.add(line)
                self._run_stats[name] = len(urls)
                if urls:
                    logger.debug(f"  ✅ {name}: {len(urls)} URLs")
            except asyncio.TimeoutError:
                proc.kill()
                logger.debug(f"  ⏰ {name}: timed out")
                self._run_stats[name] = -1
        except FileNotFoundError:
            logger.debug(f"  ❌ {name}: not installed")
            self._run_stats[name] = -2
        except Exception as e:
            logger.debug(f"  ❌ {name}: {e}")
            self._run_stats[name] = -3
        return urls

    async def _run_all_tools(self, target: str) -> Set[str]:
        all_urls: Set[str] = set()
        # Go tools (pre-compiled binaries)
        go_tasks = [
            self._run_tool(["waybackurls", target], name="waybackurls"),
            self._run_tool(["gau", target], name="gau"),
        ]
        # Cariddi
        if self._check_tool("cariddi"):
            go_tasks.append(self._run_tool(["cariddi", "-s", "-d", "2", "-c", "100", "-e", "-intensive", "-rua", target], name="cariddi"))
        # Katana passive
        if self._check_tool("katana"):
            katana_cmd = ["katana", "-passive", "-jc", "-silent"]
            katana_cmd.extend(self.format_auth_args())
            go_tasks.append(self._run_tool(katana_cmd, input_data=target, name="katana"))
        results = await asyncio.gather(*go_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, set):
                all_urls.update(r)
        if self.should_stop:
            return all_urls
        await self.check_pause()
        # Python-native API sources (always available)
        import httpx
        async with httpx.AsyncClient(timeout=30, headers=self.get_http_client_headers()) as client:
            api_tasks = [
                self._fetch_wayback(client, target),
                self._fetch_commoncrawl(client, target),
                self._fetch_otx(client, target),
                self._fetch_urlscan(client, target),
            ]
            api_results = await asyncio.gather(*api_tasks, return_exceptions=True)
            for r in api_results:
                if isinstance(r, set):
                    all_urls.update(r)
        return all_urls

    def _check_tool(self, name: str) -> bool:
        import shutil
        return shutil.which(name) is not None

    async def _fetch_wayback(self, client, target: str) -> Set[str]:
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey&limit=10000"
            resp = await client.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return set(row[0] for row in data[1:] if len(row) > 0 and row[0].strip())
        except Exception as e:
            logger.debug(f"Wayback failed: {e}")
        return set()

    async def _fetch_commoncrawl(self, client, target: str) -> Set[str]:
        try:
            idx = await client.get("https://index.commoncrawl.org/collinfo.json", timeout=10)
            if idx.status_code != 200: return set()
            indexes = idx.json()
            index_id = indexes[-1].get("id", "") if isinstance(indexes, list) and indexes else ""
            if not index_id: return set()
            resp = await client.get(f"https://index.commoncrawl.org/{index_id}-index?url={target}/*&output=json&limit=5000&fl=url", timeout=30)
            if resp.status_code == 200:
                urls = set()
                for line in resp.text.strip().split("\n"):
                    try:
                        entry = json.loads(line)
                        if "url" in entry: urls.add(entry["url"])
                    except Exception: continue
                return urls
        except Exception: pass
        return set()

    async def _fetch_otx(self, client, target: str) -> Set[str]:
        try:
            resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list?limit=1000", timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return set(item.get("url", "") for item in data.get("url_list", []) if item.get("url"))
        except Exception: pass
        return set()

    async def _fetch_urlscan(self, client, target: str) -> Set[str]:
        try:
            resp = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=1000", timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                urls = set()
                for r in data.get("results", []):
                    page = r.get("page", {})
                    if isinstance(page, dict) and page.get("url"):
                        urls.add(page["url"])
                return urls
        except Exception: pass
        return set()

    def _analyze_leaks(self):
        patterns = {
            "api_key": r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "password": r"(?i)(password|passwd|pwd|db_password)\s*[=:]\s*['\"][^'\"]{6,}",
            "token": r"(?i)(access_token|auth_token|bearer)\s*[=:]\s*['\"][A-Za-z0-9_\-\.]{10,}",
            "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        }
        found_types = set()
        for url in self._collected_urls:
            for leak_type, pattern in patterns.items():
                if re.search(pattern, url):
                    found_types.add(leak_type)
                    self._leaked_data.append(url)
        if found_types:
            self.add_finding(Finding(
                title=f"Sensitive Data in URLs: {', '.join(found_types)}",
                severity="critical" if "aws_key" in found_types or "private_key" in found_types else "high",
                category="secret_scan",
                evidence="\n".join(self._leaked_data[:10]),
                remediation="Rotate exposed credentials immediately",
                confidence=0.8,
            ))
