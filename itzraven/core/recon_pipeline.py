"""
Parallel Recon Pipeline — RedAmon-inspired fan-out/fan-in.

Runs 5 concurrent recon tools, merges results, handles partial failures.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class ReconTask:
    name: str
    tool: str
    cmd: str
    timeout: int = 60
    priority: int = 0  # lower=higher priority


@dataclass
class ReconResult:
    task_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    duration: float = 0.0


class ReconPipeline:
    def __init__(self, max_concurrent: int = 5):
        self._max = max_concurrent

    async def run_batch(self, tasks: List[ReconTask], target: str) -> List[ReconResult]:
        sem = asyncio.Semaphore(self._max)
        async def run_one(task: ReconTask) -> ReconResult:
            async with sem:
                import time
                start = time.time()
                try:
                    proc = await asyncio.create_subprocess_shell(
                        task.cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=task.timeout)
                    dur = time.time() - start
                    if proc.returncode == 0:
                        return ReconResult(task_name=task.name, success=True, data={"stdout": stdout.decode(errors="replace")[:5000]}, duration=dur)
                    return ReconResult(task_name=task.name, success=False, error=stderr.decode(errors="replace")[:500], duration=dur)
                except asyncio.TimeoutError:
                    return ReconResult(task_name=task.name, success=False, error="timeout", duration=time.time() - start)
                except Exception as e:
                    return ReconResult(task_name=task.name, success=False, error=str(e), duration=time.time() - start)

        results = await asyncio.gather(*[run_one(t) for t in tasks], return_exceptions=True)
        final = []
        for r in results:
            if isinstance(r, ReconResult):
                final.append(r)
        successful = sum(1 for r in final if r.success)
        logger.info(f"Recon pipeline: {successful}/{len(tasks)} tasks completed")
        return final

    def merge_results(self, results: List[ReconResult]) -> Dict[str, Any]:
        merged: Dict[str, Any] = {
            "endpoints": [],
            "technologies": [],
            "ports": [],
            "subdomains": [],
            "ips": [],
        }
        for r in results:
            if not r.success:
                continue
            stdout = r.data.get("stdout", "")
            for line in stdout.split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("http://") or line.startswith("https://") or line.startswith("/"):
                    if line not in merged["endpoints"]:
                        merged["endpoints"].append(line)
                elif "open" in line and "port" in line.lower():
                    merged["ports"].append(line)
                elif "." in line and " " not in line and len(line) > 4:
                    merged["subdomains"].append(line)
            tech_keywords = ["php", "nginx", "apache", "node", "python", "wordpress", "laravel", "react", "angular", "django"]
            for kw in tech_keywords:
                if kw in stdout.lower() and kw not in merged["technologies"]:
                    merged["technologies"].append(kw)
        for k in merged:
            merged[k] = list(set(merged[k]))[:100]
        return merged

    def build_recon_tasks(self, target: str, depth: str = "quick") -> List[ReconTask]:
        tasks = []
        if depth in ("standard", "deep"):
            tasks.append(ReconTask("subdomain_scan", "subfinder", f"subfinder -d {target} -silent", timeout=60, priority=1))
        tasks.append(ReconTask("port_scan", "nmap", f"nmap -sS -sV -T4 --top-ports 1000 {target} -oG -", timeout=120, priority=2))
        tasks.append(ReconTask("tech_detect", "httpx", f"httpx -u https://{target} -td -silent -json 2>/dev/null || httpx -u http://{target} -td -silent -json 2>/dev/null", timeout=30, priority=0))
        tasks.append(ReconTask("endpoint_discovery", "gobuster", f"gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -q -n 2>/dev/null || echo 'gobuster unavailable'", timeout=60, priority=3))
        tasks.append(ReconTask("ssl_scan", "nmap", f"nmap --script ssl-enum-ciphers -p 443 {target} -oG - 2>/dev/null || echo 'nmap unavailable'", timeout=60, priority=4))
        return tasks
