import re
import urllib.parse
from typing import List, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


class WebSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Web Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for web vulnerabilities")

        findings = []
        target_url = self.target if self.target.startswith("http") else f"http://{self.target}"

        try:
            findings.extend(await self._check_sqli(target_url))
            findings.extend(await self._check_ssti(target_url))
            findings.extend(await self._check_lfi(target_url))
            findings.extend(await self._check_command_injection(target_url))
            findings.extend(await self._check_source_comments(target_url))

            if self.browser:
                content = await self._fetch_page(target_url)
                if content:
                    flags = self.flag_extractor.extract(content)
                    for flag in flags:
                        f = Finding(
                            title="Flag Found in Web Content",
                            description="Extracted flag from web page content or headers",
                            severity="critical",
                            category="CTF",
                            evidence=flag,
                            confidence=1.0,
                        )
                        self.add_finding(f)
                        findings.append(f)

        except Exception as e:
            logger.error(f"{self.name} error: {e}")
            f = Finding(
                title="Web Analysis Error",
                description=str(e),
                severity="info",
                category="CTF",
                evidence=str(e),
            )
            self.add_finding(f)
            findings.append(f)

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _fetch_page(self, url: str) -> Optional[str]:
        try:
            if self.proxy:
                resp = await self.proxy.request("GET", url)
                if resp and hasattr(resp, "text"):
                    return resp.text
            if self.shell:
                result = await self.shell.execute(f"curl -sL '{url}'")
                if result and result.output:
                    return result.output
        except Exception as e:
            logger.debug(f"Fetch failed: {e}")
        return None

    async def _check_sqli(self, url: str) -> List[Finding]:
        results = []
        payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "1' UNION SELECT NULL--"]
        for payload in payloads:
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            try:
                content = await self._fetch_page(test_url)
                if content:
                    errors = [
                        "sql", "mysql", "syntax error", "unclosed quotation",
                        "odbc", "driver", "db2", "postgresql",
                    ]
                    for err in errors:
                        if err in content.lower():
                            f = Finding(
                                title="SQL Injection Detected",
                                description=f"SQLi vector found with payload: {payload}",
                                severity="high",
                                category="CTF",
                                evidence=f"URL: {test_url}\nError: {err} detected in response",
                                confidence=0.8,
                            )
                            self.add_finding(f)
                            results.append(f)
                            break
            except Exception:
                pass
        return results

    async def _check_ssti(self, url: str) -> List[Finding]:
        results = []
        payloads = [
            ("{{7*7}}", "49"),
            ("${{7*7}}", "49"),
            ("#{7*7}", "49"),
            ("{{config}}", "config"),
        ]
        for payload, indicator in payloads:
            test_url = f"{url}?name={urllib.parse.quote(payload)}"
            try:
                content = await self._fetch_page(test_url)
                if content and (indicator in content or payload in content):
                    f = Finding(
                        title="Server-Side Template Injection Detected",
                        description=f"SSTI vector found with payload: {payload}",
                        severity="high",
                        category="CTF",
                        evidence=f"URL: {test_url}\nPayload reflected/executed in response",
                        confidence=0.7,
                    )
                    self.add_finding(f)
                    results.append(f)
            except Exception:
                pass
        return results

    async def _check_lfi(self, url: str) -> List[Finding]:
        results = []
        payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "....//....//....//etc/passwd",
        ]
        indicators = ["root:", "boot loader", "Microsoft"]
        for payload in payloads:
            test_url = f"{url}?file={urllib.parse.quote(payload)}"
            try:
                content = await self._fetch_page(test_url)
                if content:
                    for indicator in indicators:
                        if indicator in content:
                            f = Finding(
                                title="Local File Inclusion Detected",
                                description=f"LFI vector found with payload: {payload}",
                                severity="high",
                                category="CTF",
                                evidence=f"URL: {test_url}\nIndicator: {indicator} found in response",
                                confidence=0.8,
                            )
                            self.add_finding(f)
                            results.append(f)
                            break
            except Exception:
                pass
        return results

    async def _check_command_injection(self, url: str) -> List[Finding]:
        results = []
        payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("`id`", "uid="),
            ("$(id)", "uid="),
        ]
        for payload, indicator in payloads:
            test_url = f"{url}?cmd={urllib.parse.quote(payload)}"
            try:
                content = await self._fetch_page(test_url)
                if content and indicator in content:
                    f = Finding(
                        title="Command Injection Detected",
                        description=f"Command injection vector with payload: {payload}",
                        severity="critical",
                        category="CTF",
                        evidence=f"URL: {test_url}\nIndicator: {indicator} found in response",
                        confidence=0.9,
                    )
                    self.add_finding(f)
                    results.append(f)
            except Exception:
                pass
        return results

    async def _check_source_comments(self, url: str) -> List[Finding]:
        results = []
        try:
            content = await self._fetch_page(url)
            if not content:
                return results
            comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)
            for comment in comments:
                stripped = comment.strip()
                if stripped and len(stripped) > 10:
                    f = Finding(
                        title="Interesting HTML Comment Found",
                        description=f"Comment content: {stripped[:300]}",
                        severity="low",
                        category="CTF",
                        evidence=stripped[:200],
                        confidence=0.5,
                    )
                    self.add_finding(f)
                    results.append(f)
            js_patterns = re.findall(r"(?:password|secret|key|token|flag)\s*[=:]\s*['\"]([^'\"]+)['\"]", content, re.IGNORECASE)
            for match in js_patterns:
                f = Finding(
                    title="Potential Secret in Source",
                    description=f"Potential credential or secret found in page source: {match}",
                    severity="medium",
                    category="CTF",
                    evidence=match,
                    confidence=0.6,
                )
                self.add_finding(f)
                results.append(f)
        except Exception:
            pass
        return results
