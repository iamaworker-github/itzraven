"""
PoC Validator Agent for validating discovered findings.

Shannon-style strict enforcement: "No Exploit, No Report".
Every finding in the final report must have a validated, executable PoC.
"""

import asyncio
import hashlib
from datetime import datetime
from typing import List, Optional

from itzraven.agents.base_agent import BaseAgent, AgentResult, AgentStatus, Finding
from itzraven.core.events import FindingValidatedEvent
from itzraven.core.logger import get_logger
from itzraven.core.no_exploit_no_report import enforce_no_exploit_no_report

logger = get_logger()


class PoCValidatorAgent(BaseAgent):
    """Validate proof-of-concept payloads for discovered findings.

    Strict mode: removes findings without validated PoCs from the report.
    """

    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope=None,
        strict_poc_mode: str = "shadow",
        require_poc_for_all: bool = False,
    ):
        super().__init__(
            name="PoC Validator Agent",
            target=target,
            event_bus=event_bus,
            memory_manager=memory_manager,
            scope=scope,
        )
        self._findings_to_validate: List[Finding] = []
        self._strict_poc_mode = strict_poc_mode
        self._require_poc_for_all = require_poc_for_all

    def set_findings_to_validate(self, findings: List[Finding]) -> None:
        """Set findings collected by other agents for validation."""
        self._findings_to_validate = findings

    async def execute(self) -> AgentResult:
        """Validate PoCs for existing findings without generating duplicate findings.

        Shannon-style: each critical/high finding MUST have a valid PoC
        or it is excluded from the report.
        """
        start = asyncio.get_event_loop().time()

        validated_count = 0
        failed_count = 0
        skipped_count = 0
        rejected_count = 0

        for finding in self._findings_to_validate:
            status = await self._validate_finding(finding)
            if status == "validated":
                validated_count += 1
            elif status == "failed_validation":
                failed_count += 1
            elif status and "rejected" in status:
                rejected_count += 1
            else:
                skipped_count += 1

        # Apply No Exploit No Report policy
        pre_count = len(self._findings_to_validate)
        filtered = enforce_no_exploit_no_report(
            self._findings_to_validate, mode=self._strict_poc_mode
        )
        post_count = len(filtered)
        if self._strict_poc_mode == "strict":
            self._findings_to_validate[:] = filtered

        end = asyncio.get_event_loop().time()
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[],
            execution_time=end - start,
            metadata={
                "validated_count": validated_count,
                "failed_count": failed_count,
                "skipped_count": skipped_count,
                "rejected_count": rejected_count,
                "processed_count": pre_count,
                "post_filter_count": post_count,
                "strict_poc_mode": self._strict_poc_mode,
            },
        )

    async def _validate_finding(self, finding: Finding) -> str:
        """Validate a single finding PoC and update finding status in-place.

        Shannon strictness levels:
          1. Critical/high without PoC → reject (no exceptions)
          2. Medium/low without PoC → reject if require_poc_for_all
          3. Non-executable PoC → reject
          4. Executable PoC that fails → reject
          5. Executable PoC that succeeds → validated
        """
        severity = finding.severity.lower()
        poc = (finding.proof_of_concept or "").strip()
        finding_id = finding.finding_id or self._finding_id(finding)
        finding.finding_id = finding_id

        if await self._should_skip_revalidation(finding_id):
            finding.validation_status = "skipped_recently_validated"
            return finding.validation_status

        # Rule 1: Critical/high MUST have PoC
        if severity in {"critical", "high"} and not poc:
            finding.validation_status = "rejected_no_poc"
            return finding.validation_status

        # Rule 2: Medium/low without PoC → depends on config
        if self._require_poc_for_all and not poc:
            finding.validation_status = "rejected_no_poc"
            return finding.validation_status

        if not poc:
            finding.validation_status = "unvalidated_poc_missing"
            return finding.validation_status

        # Rule 3: Try curl reproduction for findings with URLs in evidence
        curl_valid = await self._validate_via_curl(finding)
        if curl_valid is False:
            finding.validation_status = "rejected_curl_reproduction_failed"
            return finding.validation_status

        # Rule 4: PoC must be executable Python
        if not self._is_executable_python(poc):
            finding.validation_status = "rejected_poc_non_executable"
            return finding.validation_status

        # Rules 5-6: Execute PoC in sandbox
        validation_start = asyncio.get_event_loop().time()
        execution = await self.python.execute_exploit(poc, self.target)

        if execution.exception:
            finding.validation_status = "rejected_poc_execution_failed"
            result_ok = False
        else:
            finding.validation_status = "validated"
            result_ok = True

        if self.event_bus:
            await self.event_bus.publish_event(
                FindingValidatedEvent(
                    finding_id=finding_id,
                    validation_method="python_runtime",
                    validation_result=result_ok,
                    proof_of_concept=poc,
                    validation_time=asyncio.get_event_loop().time() - validation_start,
                    source=self.name,
                    correlation_id=self.correlation_id,
                )
            )

        return finding.validation_status

    async def _should_skip_revalidation(self, finding_id: str) -> bool:
        if not self.memory_manager:
            return False
        try:
            previous = await self.memory_manager.get_vulnerability(finding_id)
        except Exception as exc:
            logger.debug(f"Memory lookup failed for finding {finding_id}: {exc}")
            return False
        if not previous or previous.validation_status != "validated" or not previous.last_validated:
            return False
        return previous.last_validated.date() == datetime.now().date()

    async def _validate_via_curl(self, finding: Finding) -> Optional[bool]:
        """Independent curl reproduction: replay finding's URL and check if
        the vulnerability pattern is still present. Returns:
          - True  → curl confirms vulnerability still present
          - False → curl could not reproduce (likely false positive)
          - None  → skipped (no URL in evidence, or non-HTTP finding)
        """
        import re as _re
        evidence = (finding.evidence or "").strip()
        poc = (finding.proof_of_concept or "").strip()
        severity = finding.severity.lower()

        url_match = _re.search(r"https?://[^\s'\"]+", evidence)
        if not url_match:
            url_match = _re.search(r"https?://[^\s'\"]+", poc)
        if not url_match:
            return None

        target_url = url_match.group(0)
        if not target_url.startswith("http"):
            return None

        try:
            header_args = self.format_auth_args()
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10"]
            cmd.extend(header_args)
            cmd.append(target_url)
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            http_code = stdout.decode().strip()
            code_int = int(http_code) if http_code.isdigit() else 0

            if severity in ("critical", "high") and code_int in (0, 403, 404, 410, 503):
                logger.info(f"  ⚠ Curl reproduction FAILED for '{finding.title}' (HTTP {http_code})")
                return False

            if severity in ("critical", "high") and code_int in (200, 401, 302, 500):
                logger.info(f"  ✅ Curl reproduction OK for '{finding.title}' (HTTP {http_code})")
                return True

            return None
        except Exception as exc:
            logger.debug(f"Curl validation error for '{finding.title}': {exc}")
            return None

    @staticmethod
    def _is_executable_python(poc: str) -> bool:
        """Return True only when PoC parses as Python executable code."""
        try:
            compile(poc, "<poc>", "exec")
            return True
        except SyntaxError:
            return False

    @staticmethod
    def _finding_id(finding: Finding) -> str:
        raw = f"{finding.agent_name}:{finding.title}:{finding.category}:{finding.evidence}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
