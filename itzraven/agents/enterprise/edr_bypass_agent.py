"""
EDR Bypass Agent — offensive-claude inspired EDR evasion techniques.

Tests EDR detection capabilities by attempting various bypass
techniques: process injection, AMSI bypass, ETW patching,
syscall proxying, and callback obfuscation.
"""

from typing import Optional, List, Dict, Any
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


EDR_BYPASS_TECHNIQUES = {
    "amsi_bypass": {
        "description": "AMSI patching via technique manipulation",
        "techniques": [
            "AMSI patch via AmsiScanBuffer",
            "AMSI via hardware breakpoints",
            "AMSI via ETW patching",
            "AMSI via DLL unhooking",
        ],
        "severity": "high",
    },
    "etw_bypass": {
        "description": "Event Tracing for Windows evasion",
        "techniques": [
            "ETW patch via EtwEventWrite",
            "ETW via provider disable",
            "ETW via callback nullification",
        ],
        "severity": "high",
    },
    "process_injection": {
        "description": "Process injection techniques",
        "techniques": [
            "Classic CreateRemoteThread",
            "QueueUserAPC injection",
            "Thread hijacking",
            "Process hollowing",
            "Atom bombing",
            "DLL sideloading",
        ],
        "severity": "critical",
    },
    "syscall_proxy": {
        "description": "Direct syscall proxying to bypass userland hooks",
        "techniques": [
            "Hell's Gate syscall",
            "Halo's Gate syscall",
            "Syswhispers2 direct syscalls",
            "Indirect syscall via gadget",
            "Fresh syscall stub generation",
        ],
        "severity": "critical",
    },
    "unhook": {
        "description": "DLL unhooking to restore original syscalls",
        "techniques": [
            "ntdll.dll unhook from disk",
            "ntdll.dll unhook from known-dlls",
            "ntdll.dll mapping from suspended process",
            "Hardware breakpoint unhook detection",
        ],
        "severity": "high",
    },
    "callback_obfuscation": {
        "description": "Obfuscate callbacks to evade detection",
        "techniques": [
            "Encrypted callback addresses",
            "Indirect call via function pointer array",
            "Opaque predicate insertion",
            "Control flow flattening",
            "JMP table randomization",
        ],
        "severity": "medium",
    },
    "stack_spoofing": {
        "description": "Stack trace spoofing to hide call origin",
        "techniques": [
            "Return address spoofing",
            "Stack frame manipulation",
            "Exception-based stack unwinding bypass",
            "TLS callback stack clearing",
        ],
        "severity": "high",
    },
    "indirect_syscalls": {
        "description": "Execute syscalls through indirect call gates",
        "techniques": [
            "syscall via ret-gadget",
            "syscall via call-gadget",
            "syscall via trampoline",
            "Randomized syscall instruction",
        ],
        "severity": "high",
    },
    "ioc_cleaning": {
        "description": "Clean artifacts and IOCs after execution",
        "techniques": [
            "Event log clearing",
            "Prefetch file deletion",
            "USN journal manipulation",
            "$MFT timestamp manipulation",
            "AMSI provider log cleanup",
        ],
        "severity": "low",
    },
}


class EDRBypassAgent(BaseAgent):
    """Agent for EDR bypass technique assessment.

    Tests a target environment for EDR detection capabilities
    and suggests appropriate bypass strategies.
    """

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("EDR Bypass Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing EDR bypass strategies for {self.target}")
        await self._assess_edr_techniques()
        await self._generate_bypass_strategy()
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _assess_edr_techniques(self):
        for tech_name, tech_info in EDR_BYPASS_TECHNIQUES.items():
            self.add_finding(Finding(
                title=f"EDR Bypass: {tech_name}",
                description=tech_info["description"],
                severity=tech_info["severity"],
                category="edr_bypass",
                evidence=f"Available techniques: {', '.join(tech_info['techniques'][:3])}",
                remediation="Implement EDR detection rules for these techniques",
                confidence=0.8,
                metadata={"edr_technique": tech_name, "all_techniques": tech_info["techniques"]},
            ))

    async def _generate_bypass_strategy(self):
        strategy_lines = [
            "# EDR Bypass Strategy",
            "",
            "## Recommended Approach",
            "1. **Recon**: Identify EDR product via process/registry/service enumeration",
            "2. **Unhook**: Restore ntdll.dll from disk to remove userland hooks",
            "3. **Syscall Proxy**: Use Hell's Gate or Syswhispers2 for direct syscalls",
            "4. **AMSI Bypass**: Patch AmsiScanBuffer in-memory",
            "5. **ETW Bypass**: Nullify EtwEventWrite callback",
            "6. **Execute**: Use indirect syscalls for critical operations",
            "7. **Clean**: Clear event logs and prefetch files on completion",
            "",
            "## Technique Priority (by stealth vs reliability)",
            "- Highest stealth: Indirect syscall + callback obfuscation",
            "- Highest reliability: AMSI patch + DLL unhook",
            "- Best balance: Syswhispers2 + hardware breakpoint unhook",
        ]
        self.add_finding(Finding(
            title="EDR Bypass Strategy Generated",
            description="Comprehensive EDR bypass approach based on common enterprise EDR products",
            severity="high",
            category="edr_bypass",
            evidence="\n".join(strategy_lines),
            confidence=0.7,
        ))
