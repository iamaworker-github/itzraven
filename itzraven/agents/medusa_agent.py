"""
Medusa AI Security Scanner Agent

Wraps Medusa (github.com/Pantheon-Security/medusa) as an Itzraven agent,
bringing 9,600+ detection patterns for AI/ML, LLM, MCP, and SAST scanning.
"""

from typing import Optional, List

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.toolkit.medusa_integration import MedusaIntegration, MedusaScanResult, SEVERITY_MAP
from itzraven.core.logger import get_logger

logger = get_logger()


class MedusaAgent(BaseAgent):
    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope: Optional[List[str]] = None,
        workers: Optional[int] = None,
        scan_mode: str = "directory",
    ):
        super().__init__("Medusa Scanner", target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.workers = workers
        self.scan_mode = scan_mode

    async def execute(self) -> AgentResult:
        if not MedusaIntegration.check_available():
            logger.warning("medusa not installed. Run: pip install medusa-security")
            self.add_finding(Finding(
                title="Medusa scanner not available",
                description="medusa-security package is not installed. 9600+ AI security patterns unavailable.",
                severity="info",
                category="tooling",
                evidence="medusa command not found on PATH",
                confidence=1.0,
            ))
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                findings=self.findings,
                execution_time=0,
                metadata={"medusa_available": False},
            )

        logger.info(f"{self.name}: Running Medusa scan on {self.target} ({self.scan_mode})")

        exclude_dirs = [".git", "__pycache__", "node_modules", "venv", ".venv"]
        if self.scope:
            exclude_dirs.extend(self.scope)

        result: MedusaScanResult
        if self.scan_mode == "git":
            result = MedusaIntegration.scan_git_repo(self.target, workers=self.workers)
        else:
            result = MedusaIntegration.scan_path(
                self.target, workers=self.workers, exclude=exclude_dirs,
            )

        if result.error:
            logger.warning(f"Medusa scan error: {result.error}")
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                findings=self.findings,
                execution_time=0,
                metadata={"medusa_error": result.error},
            )

        for issue in result.findings:
            if issue.is_likely_fp:
                continue

            finding = Finding(
                title=issue.issue,
                description=f"Scanner: {issue.scanner} | File: {issue.file}:{issue.line}",
                severity=SEVERITY_MAP.get(issue.severity, "medium"),
                category=self._categorize_issue(issue),
                evidence=f"File: {issue.file}:{issue.line}\nScanner: {issue.scanner}",
                proof_of_concept=issue.code or None,
                confidence=self._confidence_to_float(issue.confidence),
            )
            if issue.cwe:
                finding.description += f"\nCWE: {issue.cwe}"
            self.add_finding(finding)

        logger.success(f"{self.name}: Medusa found {result.total_issues} issues "
                       f"(score: {result.security_score}/100, risk: {result.risk_level})")

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings,
            execution_time=0,
            metadata={
                "total_issues": result.total_issues,
                "files_scanned": result.files_scanned,
                "security_score": result.security_score,
                "risk_level": result.risk_level,
                "severity_breakdown": result.severity_breakdown,
                "medusa_available": True,
            },
        )

    def _categorize_issue(self, issue) -> str:
        scanner_lower = issue.scanner.lower()
        if "prompt" in scanner_lower or "injection" in scanner_lower:
            return "ai_prompt_injection"
        if "mcp" in scanner_lower:
            return "mcp_security"
        if "repo" in scanner_lower or "poison" in scanner_lower:
            return "supply_chain"
        if "secret" in scanner_lower or "leak" in scanner_lower:
            return "secret_leak"
        if "sast" in scanner_lower or "code" in scanner_lower:
            return "sast"
        if "cve" in scanner_lower or "vuln" in scanner_lower:
            return "vulnerability"
        return "general"

    @staticmethod
    def _confidence_to_float(confidence: str) -> float:
        mapping = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4, "UNDEFINED": 0.3}
        return mapping.get(confidence.upper(), 0.5)
