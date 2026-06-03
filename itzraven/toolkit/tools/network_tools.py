"""
Network security tool wrappers: RustScan, testssl.sh, Masscan, dnstwist
"""

from typing import Dict, Any, Optional
from itzraven.core.tool_runner import ToolRunner, ToolOutput
from itzraven.core.logger import get_logger

logger = get_logger()


class RustScanTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan(self, target: str, ports: str = "", timeout: int = 300) -> ToolOutput:
        args = f"-a {target}"
        if ports:
            args += f" -p {ports}"
        return await self.runner.execute(
            "information_gathering.RustScan",
            args=args,
            timeout=timeout,
            privileged=True,
        )

    async def scan_loop(self, target: str) -> Dict[str, Any]:
        result = await self.scan(target)
        open_ports = []
        if result.is_success():
            for line in result.stdout.splitlines():
                if "/tcp" in line:
                    open_ports.append(line.strip())
        return {
            "target": target,
            "open_ports": open_ports,
            "count": len(open_ports),
            "raw": result.to_dict(),
        }


class TestSSLTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def check(self, host: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "web_attack.TestSSL",
            args=host,
            timeout=timeout,
        )

    async def check_loop(self, host: str) -> Dict[str, Any]:
        result = await self.check(host)
        issues = []
        if result.is_success():
            for line in result.stdout.splitlines():
                for kw in ["CRITICAL", "HIGH", "MEDIUM", "failed", "vulnerable"]:
                    if kw in line:
                        issues.append(line.strip())
                        break
        return {
            "host": host,
            "issues_found": len(issues),
            "issues": issues[:30],
            "raw": result.to_dict(),
        }


class MasscanTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan(self, target: str, ports: str = "1-65535",
                   rate: str = "1000", timeout: int = 300) -> ToolOutput:
        args = f"{target} -p{ports} --rate={rate}"
        return await self.runner.execute(
            "information_gathering.Masscan",
            args=args,
            timeout=timeout,
            privileged=True,
        )


class DnstwistTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def check_domain(self, domain: str, timeout: int = 120) -> ToolOutput:
        return await self.runner.execute(
            "phishing_attack.Dnstwist",
            args=domain,
            timeout=timeout,
        )

    async def check_domain_loop(self, domain: str) -> Dict[str, Any]:
        result = await self.check_domain(domain)
        permutations = []
        if result.is_success():
            for line in result.stdout.splitlines():
                if domain.lower() not in line.lower():
                    permutations.append(line.strip())
        return {
            "domain": domain,
            "permutations_found": len(permutations),
            "permutations": permutations[:50],
            "raw": result.to_dict(),
        }
