"""
Remediation Agent for generating autofix-style patch suggestions from findings.
"""

import asyncio
import json
from typing import Any, Dict, List

from itzraven.agents.base_agent import BaseAgent, AgentResult, AgentStatus, Finding
from itzraven.agents.llm_client import LLMClient
from itzraven.core.logger import get_logger

logger = get_logger()


class RemediationAgent(BaseAgent):
    """Generate remediation suggestions for high-signal findings."""

    def __init__(self, target: str, event_bus=None, memory_manager=None, scope=None):
        super().__init__(
            name="Remediation Agent",
            target=target,
            event_bus=event_bus,
            memory_manager=memory_manager,
            scope=scope,
        )
        self._findings_to_remediate: List[Finding] = []
        self.llm_client = LLMClient()

    def set_findings_to_remediate(self, findings: List[Finding]) -> None:
        """Set findings collected by other agents for remediation suggestions."""
        self._findings_to_remediate = findings

    async def execute(self) -> AgentResult:
        """Generate remediation suggestions without applying code changes."""
        start = asyncio.get_event_loop().time()

        candidates = self._select_candidates(self._findings_to_remediate)
        if not candidates:
            end = asyncio.get_event_loop().time()
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                findings=[],
                execution_time=end - start,
                metadata={
                    "remediation_processed_count": 0,
                    "remediation_suggested_count": 0,
                    "remediation_skipped_count": 0,
                    "remediation_suggestions": [],
                },
            )

        if not self.llm_client.config.has_ai_enabled:
            logger.info(f"{self.name}: AI unavailable, skipping remediation generation")
            end = asyncio.get_event_loop().time()
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                findings=[],
                execution_time=end - start,
                metadata={
                    "remediation_processed_count": len(candidates),
                    "remediation_suggested_count": 0,
                    "remediation_skipped_count": len(candidates),
                    "remediation_suggestions": [],
                    "remediation_skipped_reason": "ai_unavailable",
                },
            )

        suggestions: List[Dict[str, Any]] = []
        skipped = 0
        for finding in candidates:
            suggestion = await self._generate_remediation(finding)
            if suggestion:
                suggestions.append(
                    {
                        "finding_id": finding.finding_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        **suggestion,
                    }
                )
            else:
                skipped += 1

        end = asyncio.get_event_loop().time()
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[],
            execution_time=end - start,
            metadata={
                "remediation_processed_count": len(candidates),
                "remediation_suggested_count": len(suggestions),
                "remediation_skipped_count": skipped,
                "remediation_suggestions": suggestions,
            },
        )

    def _select_candidates(self, findings: List[Finding]) -> List[Finding]:
        """Select high-signal findings for remediation generation."""
        selected: List[Finding] = []
        seen: set[str] = set()

        for finding in findings:
            finding_id = finding.finding_id or f"{finding.agent_name}:{finding.title}"
            if finding_id in seen:
                continue

            severity = (finding.severity or "").lower()
            validation_status = (finding.validation_status or "").lower()
            is_high_signal = severity in {"critical", "high"} or validation_status == "validated"
            if not is_high_signal:
                continue

            seen.add(finding_id)
            selected.append(finding)
            if len(selected) >= 10:
                break

        return selected

    async def _generate_remediation(self, finding: Finding) -> Dict[str, Any]:
        """Generate structured remediation suggestion for a finding."""
        system = (
            "You are a secure code remediation assistant. "
            "Return ONLY valid JSON object with keys: "
            "suggested_fix, patch_suggestion, verification_steps, risk_notes, confidence. "
            "Do not suggest disabling authentication, authorization, input validation, or logging."
        )
        prompt = (
            f"Target: {self.target}\n"
            f"Scope: {self.scope or []}\n"
            f"Baton context: {self.context}\n\n"
            f"Finding title: {finding.title}\n"
            f"Severity: {finding.severity}\n"
            f"Category: {finding.category}\n"
            f"Evidence: {finding.evidence}\n"
            f"Description: {finding.description}\n"
            f"PoC: {finding.proof_of_concept or 'N/A'}\n\n"
            "Provide an autofix-style patch suggestion for developers. "
            "Suggestions must be reviewable and safe by default. "
            "Explicitly include manual review considerations."
        )

        try:
            response = await self.llm_client.generate(prompt=prompt, system=system, max_tokens=900)
        except Exception as exc:
            logger.debug(f"{self.name}: remediation generation failed for '{finding.title}': {exc}")
            return {}

        parsed = self._normalize_remediation_payload(self._extract_json(response.content))
        if not parsed:
            return {}

        verification_steps = parsed.get("verification_steps", [])
        risk_notes = parsed.get("risk_notes", [])
        confidence_raw = parsed.get("confidence", 0.6)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.6

        return {
            "suggested_fix": str(parsed.get("suggested_fix", "")).strip(),
            "patch_suggestion": str(parsed.get("patch_suggestion", "")).strip(),
            "verification_steps": [str(step) for step in verification_steps if str(step).strip()],
            "risk_notes": "; ".join(str(note).strip() for note in risk_notes if str(note).strip()) or "Manual review required before applying any patch.",
            "confidence": confidence,
            "manual_review_required": True,
        }

    def _extract_json(self, content: str) -> Any:
        text = (content or "").strip()
        if not text:
            return None

        try:
            return json.loads(text)
        except Exception:
            pass

        for block in self._extract_fenced_blocks(text):
            try:
                return json.loads(block)
            except Exception:
                continue

        for candidate in self._extract_balanced_json_candidates(text):
            try:
                return json.loads(candidate)
            except Exception:
                continue

        return None

    def _extract_fenced_blocks(self, text: str) -> List[str]:
        blocks: List[str] = []
        parts = text.split("```")
        if len(parts) < 3:
            return blocks

        for idx in range(1, len(parts), 2):
            block = parts[idx].strip()
            if not block:
                continue
            if block.lower().startswith("json"):
                block = block[4:].strip()
            if block:
                blocks.append(block)
        return blocks

    def _extract_balanced_json_candidates(self, text: str) -> List[str]:
        candidates: List[str] = []
        start_index = -1
        depth = 0

        for index, char in enumerate(text):
            if char == "{":
                if depth == 0:
                    start_index = index
                depth += 1
            elif char == "}":
                if depth == 0:
                    continue
                depth -= 1
                if depth == 0 and start_index != -1:
                    candidates.append(text[start_index:index + 1])
                    start_index = -1
        return candidates

    def _normalize_remediation_payload(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}

        verification_steps = payload.get("verification_steps", [])
        if isinstance(verification_steps, list):
            normalized_steps = [str(step).strip() for step in verification_steps if str(step).strip()]
        elif verification_steps:
            normalized_steps = [str(verification_steps).strip()]
        else:
            normalized_steps = []

        risk_notes = payload.get("risk_notes", [])
        if isinstance(risk_notes, list):
            normalized_risk = [str(note).strip() for note in risk_notes if str(note).strip()]
        elif risk_notes:
            normalized_risk = [str(risk_notes).strip()]
        else:
            normalized_risk = []

        return {
            **payload,
            "suggested_fix": str(payload.get("suggested_fix", "")).strip(),
            "patch_suggestion": str(payload.get("patch_suggestion", "")).strip(),
            "verification_steps": normalized_steps,
            "risk_notes": normalized_risk,
            "confidence": payload.get("confidence", 0.6),
        }
