"""
BugBountyOrchestrator — Methodology-driven bug bounty hunting workflow.

5-Phase Non-Linear Workflow:
Phase 1: Understand Target (scope, policy, disclosed reports)
Phase 2: Map Surface (recon, subdomains, tech stack, JS analysis)
Phase 3: Hunt (targeted vuln testing with depth matrices)
Phase 4: Validate & Chain (PoC validation, exploit chain building)
Phase 5: Report (platform-specific drafting, quality scoring, duplicate check)

Integrates: ScopeAnalyzer, DuplicateChecker, ChainBuilder, ReportDrafter,
QualityChecker, H1 skills, cross-session memory, skill learning, alerts.
"""
import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from itzraven.agents.modes.base import ModeOrchestrator
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.recon_agent import ReconAgent
from itzraven.agents.sql_injection_agent import SQLInjectionAgent
from itzraven.agents.xss_agent import XSSAgent
from itzraven.agents.ssrf_agent import SSRFAgent
from itzraven.agents.command_injection_agent import CommandInjectionAgent
from itzraven.agents.authentication_agent import AuthenticationAgent
from itzraven.agents.idor_agent import IDORAgent
from itzraven.agents.medusa_agent import MedusaAgent
from itzraven.agents.poc_validator_agent import PoCValidatorAgent
from itzraven.agents.bugbounty import (
    ScopeAnalyzer,
    DuplicateChecker,
    ReportDrafter,
    ChainBuilder,
    QualityChecker,
)
from itzraven.toolkit.backmeup_agent import BackMeUpAgent
from itzraven.toolkit.takeover_agent import SubdomainTakeoverAgent
from itzraven.toolkit.advanced_recon_agent import AdvancedReconAgent
from itzraven.agents.category import CATEGORY_MAP
from itzraven.core.memory import get_memory
from itzraven.core.skill_learner import get_skill_learner
from itzraven.core.alerter import get_alerter
from itzraven.core.logger import get_logger
from itzraven.core.event_bus import EventBus
from itzraven.core import MEMORY_SYSTEM_AVAILABLE
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core.memory_manager import MemoryManager

logger = get_logger()


class BugBountyOrchestrator(ModeOrchestrator):
    mode_name = "bugbounty"

    def __init__(
        self,
        target: str,
        event_bus: Optional[EventBus] = None,
        memory_manager: Optional['MemoryManager'] = None,
        scope: Optional[List[str]] = None,
        scan_depth: str = "deep",
        instruction: Optional[str] = None,
        scope_file: Optional[str] = None,
    ):
        super().__init__(target, event_bus, memory_manager, scope, scan_depth=scan_depth, instruction=instruction)
        self._session_id: str = str(uuid.uuid4())[:8]
        self._memory = get_memory()
        self._skill_learner = get_skill_learner()
        self._alerter = get_alerter()
        self._scope_analyzer = ScopeAnalyzer(scope_file=scope_file) if scope_file else ScopeAnalyzer()
        self._duplicate_checker = DuplicateChecker()
        self._report_drafter = ReportDrafter()
        self._chain_builder = ChainBuilder()
        self._quality_checker = QualityChecker()
        self._bb_known_findings: List[Finding] = []
        self._phase_results: Dict[str, Any] = {}

    def load_agents(self) -> None:
        self._memory.record_target(self.target, "bugbounty")

        # Phase 1: Recon agents (surface mapping)
        self.add_agent(ReconAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, mode="bugbounty"))
        self.add_agent(SQLInjectionAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(XSSAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(SSRFAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(CommandInjectionAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(AuthenticationAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(IDORAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(MedusaAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))
        self.add_agent(PoCValidatorAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))

        # BackMeUp: URL collection + sensitive data leak detection (sub-agent)
        self.add_agent(BackMeUpAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager))

        # Advanced Recon: Next.js manifest, qsreplace fuzzing, DOM sinks, backup files, CDN bypass
        self.add_agent(AdvancedReconAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, scan_depth=self.scan_depth))

        # Category agents for targeted hunting
        for cat in ["web", "api", "identity", "recon"]:
            agent_class = CATEGORY_MAP.get(cat)
            if agent_class:
                self.add_agent(agent_class(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, scan_depth=self.scan_depth))

        logger.info(f"Loaded {len(self.agents)} bug bounty agents for {self.target}")

    def _collect_subdomains_from_results(self) -> List[str]:
        subdomains: set = set()
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        for result in self.results:
            meta = result.metadata or {}
            if isinstance(meta, dict) and meta.get("subdomains"):
                for s in meta["subdomains"]:
                    subdomains.add(s)
            for finding in result.findings:
                if finding.category == "recon" and "subdomain" in finding.title.lower():
                    subdomains.add(finding.evidence.strip())
                if hasattr(finding, 'evidence') and finding.evidence:
                    import re
                    found = re.findall(rf'([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+{re.escape(domain)}', finding.evidence, re.I)
                    for match in found:
                        subdomains.add(match[0] + domain)
        return sorted(subdomains)[:50]

    def _is_in_scope(self, target: str) -> bool:
        return self._scope_analyzer.is_in_scope(target)

    def _deduplicate(self, finding: Finding) -> bool:
        result = self._duplicate_checker.check(finding, self._bb_known_findings)
        if result["is_duplicate"]:
            logger.info(f"  ⏭ Duplicate: {finding.title} (score: {result['similarity_score']:.2f})")
            return True
        self._bb_known_findings.append(finding)
        return False

    def _run_quality_gate(self, finding: Finding) -> bool:
        score = self._quality_checker.score(finding)
        if score < 4.0:
            logger.warning(f"  ⚠ Low quality ({score}/10): {finding.title} — skipping")
            return False
        if score < 7.0:
            logger.info(f"  📝 Quality: {score}/10 — needs improvement: {finding.title}")
        else:
            logger.info(f"  ✅ Quality: {score}/10 — {finding.title}")
        return True

    def _process_findings_post_scan(self) -> Dict[str, Any]:
        findings_dicts = []
        for f in self.all_findings:
            fd = f.to_dict() if hasattr(f, 'to_dict') else {}
            fd["target"] = self.target

            is_dup = self._deduplicate(f)
            if is_dup:
                continue

            passes_quality = self._run_quality_gate(f)
            if not passes_quality:
                continue

            self._memory.record_finding(fd)
            learned = self._skill_learner.learn_from_finding(fd)
            if learned:
                logger.info(f"  🧠 Learned skill: {learned}")
            findings_dicts.append(fd)

        if self._alerter.is_configured():
            self._alerter.send_alert(findings_dicts, self.target)

        return {"total": len(findings_dicts), "findings": findings_dicts}

    def _run_chain_analysis(self) -> Dict[str, Any]:
        validated = [f for f in self.all_findings if f.validation_status == "validated"]
        chains = self._chain_builder.build_chains(validated)
        suggestions = self._chain_builder.get_chain_suggestions(validated)
        return {"chains": chains, "suggestions": suggestions, "count": len(chains)}

    def _generate_reports(self) -> Dict[str, str]:
        reports = {}
        for platform in ["hackerone", "bugcrowd", "intigriti"]:
            platform_findings = [
                f for f in self.all_findings
                if f.severity.lower() in ("critical", "high") and f.validation_status == "validated"
            ]
            if platform_findings:
                report = self._report_drafter.draft_bugbounty_report(platform_findings)
                reports[platform] = report
        return reports

    async def run_sequential(self):
        self._memory.record_session(self._session_id, self.target, self.scan_depth, "bugbounty")

        memory_ctx = self._memory.build_memory_context(self.target)
        if "<memory-context>" in memory_ctx:
            logger.info(f"🧠 Memory: previous findings exist for {self.target}")

        logger.info(f"🎯 Bug Bounty Hunt started — {self.target}")
        logger.info(f"  Phase 1-2: Recon & Surface Mapping")
        logger.info(f"  Phase 3:   Targeted Hunting")
        logger.info(f"  Phase 4:   Validation & Chain Analysis")
        logger.info(f"  Phase 5:   Report Generation")

        result = await super().run_sequential()

        # Phase 2b: Subdomain takeover check from collected subdomains
        takeover_subdomains = self._collect_subdomains_from_results()
        if takeover_subdomains:
            logger.info(f"  🔍 Checking {len(takeover_subdomains)} subdomains for takeover...")
            to_agent = SubdomainTakeoverAgent(
                self.target, event_bus=self.event_bus,
                memory_manager=self.memory_manager, subdomains=takeover_subdomains,
            )
            takeover_result = await to_agent.run()
            for f in takeover_result.findings:
                self.all_findings.append(f)

        processed = self._process_findings_post_scan()
        logger.info(f"  📊 After dedup+quality: {processed['total']} valid findings")

        chain_result = self._run_chain_analysis()
        if chain_result["count"] > 0:
            logger.success(f"  🔗 {chain_result['count']} exploit chains discovered")

        reports = self._generate_reports()
        if reports:
            output_dir = Path("./itzraven_results/bugbounty")
            output_dir.mkdir(parents=True, exist_ok=True)
            for platform, report_text in reports.items():
                path = output_dir / f"report_{platform}_{self._session_id}.md"
                path.write_text(report_text)
                logger.info(f"  📄 {platform} report: {path}")
            self._phase_results["reports"] = list(reports.keys())

        self._memory.complete_session(self._session_id, result.total_findings,
                                       f"Bug bounty: {processed['total']} valid findings, {chain_result['count']} chains")

        result.metadata["bugbounty"] = {
            "processed_findings": processed["total"],
            "chains": chain_result["count"],
            "reports": list(reports.keys()),
            "takeover_checked": len(takeover_subdomains),
        }
        return result

    async def run_parallel(self):
        self._memory.record_session(self._session_id, self.target, self.scan_depth, "bugbounty")
        result = await super().run_parallel()

        processed = self._process_findings_post_scan()
        chain_result = self._run_chain_analysis()
        reports = self._generate_reports()

        self._memory.complete_session(self._session_id, result.total_findings,
                                       f"Bug bounty parallel: {processed['total']} valid findings, {chain_result['count']} chains")
        result.metadata["bugbounty"] = {
            "processed_findings": processed["total"],
            "chains": chain_result["count"],
        }
        return result

    def get_report_template(self) -> str:
        return "bugbounty_report"

    def get_output_subdir(self) -> str:
        return "bugbounty"
