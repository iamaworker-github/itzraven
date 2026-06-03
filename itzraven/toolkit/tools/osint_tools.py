"""
OSINT tool wrappers: Holehe, Maigret, Sherlock, SpiderFoot, TruffleHog, Gitleaks
"""

from typing import List, Dict, Any, Optional
from itzraven.core.tool_runner import ToolRunner, ToolOutput
from itzraven.core.logger import get_logger

logger = get_logger()


class HoleheTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def check_email(self, email: str, timeout: int = 120) -> ToolOutput:
        return await self.runner.execute(
            "information_gathering.Holehe",
            args=email,
            timeout=timeout,
        )

    async def check_email_loop(self, email: str) -> Dict[str, Any]:
        result = await self.check_email(email)
        registered = []
        if result.is_success():
            for line in result.stdout.splitlines():
                if "[+]" in line:
                    registered.append(line.strip())
        return {
            "email": email,
            "registered_sites": registered,
            "count": len(registered),
            "raw": result.to_dict(),
        }


class MaigretTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def check_username(self, username: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "information_gathering.Maigret",
            args=username,
            timeout=timeout,
        )

    async def check_username_loop(self, username: str) -> Dict[str, Any]:
        result = await self.check_username(username)
        sites = []
        if result.is_success():
            for line in result.stdout.splitlines():
                if ":" in line and not line.startswith(("#", "[")):
                    sites.append(line.strip())
        return {
            "username": username,
            "sites_found": len(sites),
            "profiles": sites[:50],
            "raw": result.to_dict(),
        }


class SherlockTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def search_username(self, username: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "information_gathering.Sherlock",
            args=username,
            timeout=timeout,
        )

    async def search_username_loop(self, username: str) -> Dict[str, Any]:
        result = await self.search_username(username)
        accounts = []
        if result.is_success():
            for line in result.stdout.splitlines():
                if "[+]" in line:
                    accounts.append(line.strip())
        return {
            "username": username,
            "accounts_found": len(accounts),
            "profiles": accounts[:50],
            "raw": result.to_dict(),
        }


class SpiderFootTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan(self, target: str, module: str = "", timeout: int = 600) -> ToolOutput:
        args = f"-s {target}"
        if module:
            args += f" -m {module}"
        return await self.runner.execute(
            "information_gathering.SpiderFoot",
            args=args,
            timeout=timeout,
        )


class TruffleHogTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan_git(self, repo_path: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "information_gathering.TruffleHog",
            args=f"filesystem {repo_path}",
            timeout=timeout,
        )

    async def scan_git_loop(self, repo_path: str) -> Dict[str, Any]:
        result = await self.scan_git(repo_path)
        secrets = []
        if result.is_success():
            for line in result.stdout.splitlines():
                try:
                    import json as _json
                    item = _json.loads(line)
                    secrets.append({
                        "source": item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                        "detector": item.get("DetectorName", ""),
                        "verified": item.get("Verified", False),
                    })
                except Exception:
                    pass
        return {
            "repo": repo_path,
            "secrets_found": len(secrets),
            "secrets": secrets[:50],
            "raw": result.to_dict(),
        }


class GitleaksTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan_git(self, repo_path: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "information_gathering.Gitleaks",
            args=f"detect --source {repo_path} -v",
            timeout=timeout,
        )

    async def scan_git_loop(self, repo_path: str) -> Dict[str, Any]:
        result = await self.scan_git(repo_path)
        leaks = []
        if result.is_success():
            for line in result.stdout.splitlines():
                try:
                    import json as _json
                    item = _json.loads(line)
                    leaks.append({
                        "file": item.get("File", ""),
                        "rule": item.get("RuleID", ""),
                        "match": item.get("Match", "")[:100],
                    })
                except Exception:
                    pass
        return {
            "repo": repo_path,
            "leaks_found": len(leaks),
            "leaks": leaks[:50],
            "raw": result.to_dict(),
        }
