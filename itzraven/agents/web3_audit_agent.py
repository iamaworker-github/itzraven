"""
Web3 / Smart Contract Audit Agent
DeFi security, reentrancy detection, Flash loan attack patterns, Solidity static analysis
"""

import asyncio
import json
from typing import List, Dict, Any
from pathlib import Path
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class Web3AuditAgent(BaseAgent):
    """Agent for Web3 and smart contract security auditing"""

    def __init__(self, target: str, event_bus=None, memory_manager=None, contract_path: str = ""):
        super().__init__("Web3 Audit Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.contract_path = contract_path
        self.reentrancy_patterns = [
            ".call{value:",
            ".call.value(",
            ".delegatecall(",
            "send(",
            "transfer(",
        ]
        self.checks_effects_interactions = [
            "require(balances",
            "require(balanceOf",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Auditing contract '{self.contract_path or self.target}'")
        if self.contract_path:
            await self._run_slither()
            await self._run_mythril()
            await self._check_reentrancy()
            await self._check_access_control()
            await self._check_oracle_usage()
            await self._check_arithmetic()
        await self._emit_thought("Web3 audit complete", "summary", "web3_audit")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _run_slither(self) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "slither", self.contract_path,
                "--detect", "all",
                "--json", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            try:
                data = json.loads(stdout.decode())
                for detector in data.get("detectors", []):
                    severity = detector.get("impact", "medium").lower()
                    sev_map = {"high": "critical", "medium": "high", "low": "medium"}
                    self.add_finding(Finding(
                        title=f"[Slither] {detector.get('check', 'Unknown')}",
                        description=detector.get("description", ""),
                        severity=sev_map.get(severity, "medium"),
                        category="blockchain",
                        evidence=detector.get("markdown", "") or detector.get("description", ""),
                        remediation=detector.get("recommendation", "Review and fix the identified issue."),
                        confidence=0.85,
                    ))
            except (json.JSONDecodeError, KeyError):
                pass
        except Exception as e:
            logger.debug(f"Slither analysis failed: {e}")

    async def _run_mythril(self) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "mythril", "analyze", self.contract_path,
                "--execution-timeout", "120",
                "--o", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            try:
                data = json.loads(stdout.decode())
                for issue in data.get("issues", []):
                    sev = issue.get("severity", "").lower()
                    sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
                    self.add_finding(Finding(
                        title=f"[Mythril] {issue.get('title', 'Unknown')}",
                        description=issue.get("description", ""),
                        severity=sev_map.get(sev, "medium"),
                        category="blockchain",
                        evidence=f"SWC ID: {issue.get('swc-id', 'N/A')}\n{issue.get('description', '')[:500]}",
                        remediation=f"SWC: https://swcregistry.io/docs/SWC-{issue.get('swc-id', '')}",
                        confidence=0.8,
                    ))
            except (json.JSONDecodeError, KeyError):
                pass
        except Exception as e:
            logger.debug(f"Mythril analysis failed: {e}")

    async def _check_reentrancy(self) -> None:
        if not self.contract_path:
            return
        src = Path(self.contract_path).read_text() if Path(self.contract_path).exists() else ""
        for pattern in self.reentrancy_patterns:
            if pattern in src:
                self.add_finding(Finding(
                    title="Potential Reentrancy Vulnerability",
                    description=f"External call pattern '{pattern}' detected — check for checks-effects-interactions pattern",
                    severity="critical",
                    category="blockchain",
                    evidence=f"Pattern found in {self.contract_path}: {pattern}",
                    remediation="Apply checks-effects-interactions pattern. Use ReentrancyGuard from OpenZeppelin.",
                    confidence=0.6,
                ))
                break

    async def _check_access_control(self) -> None:
        if not self.contract_path:
            return
        src = Path(self.contract_path).read_text() if Path(self.contract_path).exists() else ""
        if "tx.origin" in src and "msg.sender" not in src:
            self.add_finding(Finding(
                title="tx.origin Used for Authorization",
                description="tx.origin used without msg.sender check — vulnerable to phishing attacks",
                severity="high",
                category="blockchain",
                evidence=f"tx.origin found in {self.contract_path}",
                remediation="Use msg.sender instead of tx.origin for authorization checks.",
                confidence=0.8,
            ))
        if "selfdestruct" in src or "suicide" in src:
            self.add_finding(Finding(
                title="selfdestruct / suicide Detected",
                description="Contract can be self-destructed — ensure proper access control",
                severity="high",
                category="blockchain",
                evidence=f"selfdestruct found in {self.contract_path}",
                remediation="Ensure selfdestruct is protected by proper access control (onlyOwner, timelock).",
                confidence=0.7,
            ))

    async def _check_oracle_usage(self) -> None:
        if not self.contract_path:
            return
        src = Path(self.contract_path).read_text() if Path(self.contract_path).exists() else ""
        oracle_patterns = ["getReserves", "spotPrice", "getPrice", "oracle", "twap", "chainlink"]
        found = [p for p in oracle_patterns if p in src]
        if found:
            self.add_finding(Finding(
                title="Price Oracle Integration Detected",
                description=f"Oracle patterns found: {', '.join(found)} — check for manipulation vectors",
                severity="medium",
                category="blockchain",
                evidence=f"Oracle patterns detected in {self.contract_path}: {', '.join(found)}",
                remediation="Use TWAP oracles (e.g., Uniswap V3 TWAP) instead of spot price. Use multiple oracle sources.",
                confidence=0.6,
            ))

    async def _check_arithmetic(self) -> None:
        if not self.contract_path:
            return
        src = Path(self.contract_path).read_text() if Path(self.contract_path).exists() else ""
        if "pragma solidity <0.8" in src:
            if "SafeMath" not in src and "using SafeMath" not in src:
                self.add_finding(Finding(
                    title="Pre-0.8 Solidity Without SafeMath",
                    description="Contract uses Solidity <0.8.0 without SafeMath — integer overflow/underflow possible",
                    severity="high",
                    category="blockchain",
                    evidence=f"Contract {self.contract_path} uses pre-0.8 Solidity without SafeMath",
                    remediation="Upgrade to Solidity 0.8+ or import OpenZeppelin SafeMath library.",
                    confidence=0.9,
                ))
