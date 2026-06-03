"""
Kubescape Integration — Kubernetes security audit.
Scans K8s clusters for misconfigurations, RBAC issues, and CVEs.
"""

import json
import asyncio
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import Finding

logger = get_logger()


@dataclass
class KubescapeResult:
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    controls_passed: int = 0
    controls_failed: int = 0
    score: float = 0.0


class KubescapeTool:
    def __init__(self):
        self._available = None

    async def check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            proc = await asyncio.create_subprocess_exec(
                "kubescape", "--version",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            self._available = proc.returncode == 0
            return self._available
        except Exception:
            self._available = False
            return False

    async def run_kubescape_scan(self, target: str = "") -> KubescapeResult:
        if not await self.check_available():
            logger.debug("kubescape not installed, skipping K8s audit")
            return KubescapeResult()

        result = KubescapeResult()
        try:
            cmd = ["kubescape", "scan", "--format", "json", "--output", "/tmp/kubescape_results.json"]
            if target:
                cmd.extend(["--include-namespaces", target])

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            import json as js
            import os
            results_file = "/tmp/kubescape_results.json"
            if os.path.exists(results_file):
                with open(results_file) as f:
                    data = js.load(f)

                controls = data.get("results", []) or data.get("controls", [])
                for control in controls:
                    cid = control.get("controlID", control.get("id", "unknown"))
                    name = control.get("name", f"Control {cid}")
                    severity = control.get("severity", {}).get("value", "medium") if isinstance(control.get("severity"), dict) else control.get("severity", "medium")
                    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
                    sev = severity_map.get(severity.lower(), "medium")

                    status = control.get("status", {}).get("status") if isinstance(control.get("status"), dict) else control.get("status", "")
                    if status and "fail" in str(status).lower():
                        result.controls_failed += 1
                        desc = control.get("description", control.get("controlDescription", f"K8s misconfiguration: {name}"))
                        result.findings.append(Finding(
                            title=f"K8s: {name} ({cid})",
                            description=desc,
                            severity=sev, category="kubernetes",
                            evidence=f"Control: {cid}\nSeverity: {sev}\nDescription: {desc}",
                            confidence=0.8,
                            remediation=control.get("remediation", "Apply K8s security best practices"),
                        ))
                    else:
                        result.controls_passed += 1

                result.score = data.get("score", data.get("complianceScore", 0))
                try:
                    os.remove(results_file)
                except Exception:
                    pass

                logger.info(f"Kubescape: {result.controls_failed} failed, {result.controls_passed} passed (score: {result.score})")
            else:
                logger.debug("Kubescape: no results file generated")

        except asyncio.TimeoutError:
            result.error = "kubescape scan timed out"
        except Exception as e:
            result.error = str(e)
            logger.debug(f"kubescape scan error: {e}")

        return result
