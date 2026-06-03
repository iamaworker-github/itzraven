"""
RavenGraph — LangGraph-based orchestrator for Itzraven.
Replaces sequential baton-passing with a formal state graph.
Adds durable execution (crash recovery) + human-in-the-loop + conditional routing.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Annotated, Literal
from urllib.parse import urlparse

from contextlib import asynccontextmanager
from langgraph.graph import StateGraph, END, START
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.types import Command

from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.orchestrator import ScanResult
from itzraven.core.logger import get_logger
from itzraven.core.event_bus import EventBus, get_event_bus
from itzraven.core.events import ScanStartedEvent, ScanCompletedEvent, AgentProgressEvent, FindingDiscoveredEvent
from itzraven.core.blackboard import Blackboard, FindingCategory, get_blackboard
from itzraven.core.config import get_config
from itzraven.core import MEMORY_SYSTEM_AVAILABLE

logger = get_logger()
config = get_config()


class RavenGraphState(TypedDict):
    """Formal state that flows through the LangGraph."""
    scan_id: str
    target: str
    mode: str
    scan_depth: str
    sub_mode: Optional[str]
    scope: List[str]
    instruction: Optional[str]
    start_time: Optional[str]
    all_findings: Annotated[List[Dict], "append_findings"]
    agent_results: Annotated[List[Dict], "append_results"]
    shared_technologies: List[str]
    shared_endpoints: List[str]
    shared_subdomains: List[str]
    open_ports: List[Dict]
    detected_wafs: List[str]
    target_ip: Optional[str]
    plan_categories: List[str]
    completed_agents: List[str]
    current_phase: str
    error: Optional[str]


def _findings_reducer(a: List[Dict], b: List[Dict]) -> List[Dict]:
    return a + b


def _results_reducer(a: List[Dict], b: List[Dict]) -> List[Dict]:
    return a + b


def _dedup_findings(findings: List[Dict]) -> List[Dict]:
    seen = set()
    result = []
    for f in findings:
        key = f"{f.get('title', '')}|{f.get('agent_name', '')}|{f.get('evidence', '')[:50]}"
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _make_finding_dict(finding: Finding) -> Dict:
    return {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "category": finding.category,
        "evidence": finding.evidence,
        "proof_of_concept": finding.proof_of_concept,
        "remediation": finding.remediation,
        "confidence": finding.confidence,
        "reproducibility_steps": finding.reproducibility_steps,
        "fix_hint": finding.fix_hint,
        "validation_status": finding.validation_status,
        "timestamp": finding.timestamp.isoformat() if hasattr(finding.timestamp, 'isoformat') else str(finding.timestamp),
        "agent_name": finding.agent_name,
        "finding_id": finding.finding_id,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "cwe_id": finding.cwe_id,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "code_snippet": finding.code_snippet,
        "metadata": finding.metadata,
    }


def _make_result_dict(result: AgentResult) -> Dict:
    return {
        "agent_name": result.agent_name,
        "status": result.status.value if hasattr(result.status, 'value') else str(result.status),
        "findings": [_make_finding_dict(f) for f in result.findings],
        "execution_time": result.execution_time,
        "error": result.error,
        "metadata": result.metadata,
    }


def _finding_from_dict(d: Dict) -> Finding:
    return Finding(
        title=d.get("title", ""),
        description=d.get("description", ""),
        severity=d.get("severity", "info"),
        category=d.get("category", ""),
        evidence=d.get("evidence", ""),
        proof_of_concept=d.get("proof_of_concept"),
        remediation=d.get("remediation"),
        confidence=d.get("confidence", 1.0),
        reproducibility_steps=d.get("reproducibility_steps"),
        fix_hint=d.get("fix_hint"),
        validation_status=d.get("validation_status", "validated"),
        agent_name=d.get("agent_name", ""),
        finding_id=d.get("finding_id", ""),
        cvss_score=d.get("cvss_score"),
        cvss_vector=d.get("cvss_vector"),
        cwe_id=d.get("cwe_id"),
        file_path=d.get("file_path"),
        line_number=d.get("line_number"),
        code_snippet=d.get("code_snippet"),
        metadata=d.get("metadata", {}),
    )


def _findings_to_objects(state: RavenGraphState) -> List[Finding]:
    return [_finding_from_dict(f) for f in state.get("all_findings", [])]


class RavenGraph:
    """LangGraph-powered orchestrator for Raven security scans."""

    def __init__(
        self,
        target: str,
        mode: str = "pentest",
        scan_depth: str = "deep",
        scope: Optional[List[str]] = None,
        instruction: Optional[str] = None,
        sub_mode: Optional[str] = None,
        event_bus: Optional[EventBus] = None,
        memory_manager=None,
        checkpoint_path: Optional[str] = None,
    ):
        self.target = target
        self.mode = mode
        self.scan_depth = scan_depth
        self.scope = scope or []
        self.instruction = instruction
        self.sub_mode = sub_mode
        self.event_bus = event_bus
        self.memory_manager = memory_manager
        self.scan_id = f"lg_{uuid.uuid4().hex[:8]}"

        cp_dir = checkpoint_path or str(Path.home() / ".itzraven" / "langgraph_checkpoints")
        Path(cp_dir).mkdir(parents=True, exist_ok=True)
        cp_file = os.path.join(cp_dir, f"{self.scan_id}.db")
        self._cp_file = cp_file
        self.checkpointer = None

        self._agents: List[BaseAgent] = []
        self._agent_factories: List[tuple] = []
        self._auth_headers: Dict[str, str] = {}
        self._auth_cookies: Dict[str, str] = {}

        auth_headers_raw = os.environ.get("ITZRAVEN_AUTH_HEADERS", "")
        auth_cookies_raw = os.environ.get("ITZRAVEN_AUTH_COOKIES", "")
        if auth_headers_raw:
            try:
                self._auth_headers = json.loads(auth_headers_raw)
            except Exception:
                pass
        if auth_cookies_raw:
            try:
                self._auth_cookies = json.loads(auth_cookies_raw)
            except Exception:
                pass

        self.graph = None  # built lazily in run()

    def _apply_auth(self, agent: BaseAgent) -> None:
        if hasattr(agent, 'auth_headers') and self._auth_headers:
            agent.auth_headers = dict(self._auth_headers)
        if hasattr(agent, 'auth_cookies') and self._auth_cookies:
            agent.auth_cookies = dict(self._auth_cookies)

    async def _emit_phase(self, phase: str, progress: float, message: str):
        if self.event_bus:
            try:
                await self.event_bus.publish_event(AgentProgressEvent(
                    agent_name="RavenGraph",
                    progress=progress,
                    current_phase=phase,
                    message=message,
                    correlation_id=self.scan_id,
                ))
            except Exception:
                pass

    # ─── NODE: PLANNING ─────────────────────────────────
    async def _node_planning(self, state: RavenGraphState) -> RavenGraphState:
        logger.info("🧠 [Graph] Planning phase")
        await self._emit_phase("planning", 5.0, "🧠 AI Planning — analyzing target...")

        from itzraven.agents.plan_agent import PlanAgent
        from itzraven.agents.waf_detection_agent import WafDetectionAgent
        from itzraven.core.agent_handoff import get_handoff_manager

        hm = get_handoff_manager()
        agent_results = state.get("agent_results", [])

        pa = PlanAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, scope=self.scope)
        self._apply_auth(pa)
        pa_result = await pa.run()
        agent_results.append(_make_result_dict(pa_result))

        plan = (pa_result.metadata or {}).get("plan", {}) if hasattr(pa_result, "metadata") else {}
        plan_categories = ["web", "api", "recon"]
        if isinstance(plan, dict):
            plan_categories = plan.get("categories", plan_categories)

        wa = WafDetectionAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager)
        self._apply_auth(wa)
        wa_result = await wa.run()
        agent_results.append(_make_result_dict(wa_result))

        waf_meta = wa_result.metadata if hasattr(wa_result, "metadata") else {}
        detected_wafs = waf_meta.get("waf_detected", []) if isinstance(waf_meta, dict) else []

        return {
            **state,
            "plan_categories": plan_categories,
            "detected_wafs": detected_wafs,
            "agent_results": agent_results,
            "current_phase": "planning",
        }

    # ─── NODE: RECONNAISSANCE ────────────────────────────
    async def _node_recon(self, state: RavenGraphState) -> RavenGraphState:
        logger.info("🔍 [Graph] Reconnaissance phase")
        await self._emit_phase("reconnaissance", 15.0, f"🔍 Reconnaissance — resolving {self.target}")

        agent_results = state.get("agent_results", [])
        shared_techs = state.get("shared_technologies", [])
        shared_ends = state.get("shared_endpoints", [])
        open_ports = state.get("open_ports", [])
        target_ip = state.get("target_ip")
        detected_wafs = state.get("detected_wafs", [])

        target_domain = urlparse(self.target).hostname or self.target.split('/')[0].split(':')[0]

        # IP resolve
        if not target_ip:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', self.target):
                target_ip = self.target
            else:
                try:
                    import socket
                    target_ip = socket.gethostbyname(target_domain)
                except Exception:
                    pass

        # Tech detect (httpx -td)
        try:
            import shutil
            httpx_bin = "httpx" if shutil.which("httpx") else "pd-httpx"
            proc = await asyncio.create_subprocess_exec(
                httpx_bin, "-u", target_domain, "-ip", "-td", "-json", "-sc", "-silent",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            for line in stdout.decode().strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("ip") and not target_ip:
                        target_ip = data["ip"]
                    techs = data.get("tech", []) or []
                    for t in techs:
                        if t not in shared_techs:
                            shared_techs.append(t)
                except Exception:
                    pass
        except Exception:
            pass

        # Port scan
        if not open_ports:
            try:
                nmap_flags = "-sS -p- -T4 --max-retries 2"
                if detected_wafs:
                    nmap_flags = "-sS -p- -T4 --max-retries 2"
                host = target_ip or target_domain
                proc = await asyncio.create_subprocess_exec(
                    "nmap", *(nmap_flags.split()), "-oX", "-", host,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
                if stdout:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(stdout.decode("utf-8", errors="replace"))
                    for host_elem in root.findall(".//host"):
                        for port_elem in host_elem.findall(".//port"):
                            port_num = port_elem.get("portid")
                            state_elem = port_elem.find("state")
                            if state_elem is not None and state_elem.get("state") == "open":
                                open_ports.append({"port": int(port_num) if port_num else 0, "protocol": port_elem.get("protocol", "tcp"), "state": "open"})
            except Exception:
                pass

        # ReconAgent
        from itzraven.agents.recon_agent import ReconAgent
        ra = ReconAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, mode="pentest")
        self._apply_auth(ra)
        ra.context["target_ip"] = target_ip or ""
        ra_result = await ra.run()
        agent_results.append(_make_result_dict(ra_result))

        recon_meta = ra_result.metadata if hasattr(ra_result, "metadata") else {}
        if isinstance(recon_meta, dict):
            for t in recon_meta.get("technologies", []):
                if t not in shared_techs:
                    shared_techs.append(t)
            for e in recon_meta.get("endpoints", []):
                if e not in shared_ends:
                    shared_ends.append(e)

        # NucleiAgent
        from itzraven.agents.nuclei_agent import NucleiAgent
        nuclei = NucleiAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager,
                             urls=list(set(shared_ends)) if shared_ends else [self.target],
                             technologies=shared_techs)
        self._apply_auth(nuclei)
        nuclei.context = {"scan_id": self.scan_id, "target": self.target, "mode": self.mode}
        nuclei_result = await nuclei.run()
        agent_results.append(_make_result_dict(nuclei_result))

        return {
            **state,
            "target_ip": target_ip,
            "shared_technologies": shared_techs,
            "shared_endpoints": shared_ends,
            "open_ports": open_ports,
            "agent_results": agent_results,
            "current_phase": "reconnaissance",
        }

    # ─── NODE: ENUMERATION ──────────────────────────────
    async def _node_enumeration(self, state: RavenGraphState) -> RavenGraphState:
        logger.info("📂 [Graph] Enumeration phase")
        await self._emit_phase("enumeration", 50.0, "📂 Enumeration — collecting URLs and hidden paths...")

        agent_results = state.get("agent_results", [])
        shared_ends = state.get("shared_endpoints", [])
        shared_techs = state.get("shared_technologies", [])
        open_ports = state.get("open_ports", [])
        target_ip = state.get("target_ip")
        target_domain = urlparse(self.target).hostname or self.target.split('/')[0].split(':')[0]

        from itzraven.agents.smart_bruteforce_agent import SmartBruteforceAgent
        from itzraven.toolkit.backmeup_agent import BackMeUpAgent

        backmeup = BackMeUpAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, exclude_subs=True)
        self._apply_auth(backmeup)
        backmeup.context = {"scan_id": self.scan_id, "target": self.target, "mode": self.mode}
        bm_result = await backmeup.run()
        agent_results.append(_make_result_dict(bm_result))
        bm_meta = bm_result.metadata if hasattr(bm_result, "metadata") else {}
        bm_urls = bm_meta.get("collected_urls", []) if isinstance(bm_meta, dict) else []
        for u in bm_urls:
            if u not in shared_ends:
                shared_ends.append(u)

        smart_bf = SmartBruteforceAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, collected_urls=bm_urls, custom_ports=[])
        self._apply_auth(smart_bf)
        smart_bf.context = {"scan_id": self.scan_id, "target": self.target, "mode": self.mode}
        bf_result = await smart_bf.run()
        agent_results.append(_make_result_dict(bf_result))
        bf_meta = bf_result.metadata if hasattr(bf_result, "metadata") else {}
        bf_ends = bf_meta.get("discovered_endpoints", []) if isinstance(bf_meta, dict) else []
        for e in bf_ends:
            if e not in shared_ends:
                shared_ends.append(e)

        return {
            **state,
            "shared_endpoints": shared_ends,
            "shared_technologies": shared_techs,
            "agent_results": agent_results,
            "current_phase": "enumeration",
        }

    # ─── NODE: VULNERABILITY ────────────────────────────
    async def _node_vulnerability(self, state: RavenGraphState) -> RavenGraphState:
        logger.info("🛡️ [Graph] Vulnerability phase")
        await self._emit_phase("vulnerability", 60.0, "🛡️ Vulnerability testing — AI-selected agents...")

        agent_results = state.get("agent_results", [])
        shared_techs = state.get("shared_technologies", [])
        shared_ends = state.get("shared_endpoints", [])
        plan_categories = state.get("plan_categories", ["web", "api", "recon"])

        self._register_agent_factories()
        tech_lower = " ".join(t.lower() for t in shared_techs)

        AGENT_TECH_REQUIREMENTS = {
            "NoSQLInjectionAgent": ["mongodb", "couchdb", "firebase", "nosql", "node"],
            "XXEAgent": ["xml", "soap", "dtd", "xerces"],
            "SSTIAgent": ["jinja", "twig", "freemarker", "velocity", "smarty", "handlebars"],
            "JWTTAttackAgent": ["jwt", "oauth", "oidc", "keycloak"],
        }

        from itzraven.agents.medusa_agent import MedusaAgent
        selected = []
        for cat, agent_cls, extra_kw in self._agent_factories:
            if cat not in plan_categories:
                continue
            agent_name = agent_cls.__name__
            req = AGENT_TECH_REQUIREMENTS.get(agent_name, [])
            if req and not any(t in tech_lower for t in req):
                continue
            kwargs = {"event_bus": self.event_bus, "memory_manager": self.memory_manager}
            kwargs.update(extra_kw)
            agent = agent_cls(self.target, **kwargs)
            self._apply_auth(agent)
            agent.context = {
                "scan_id": self.scan_id, "target": self.target, "scope": self.scope,
                "mode": self.mode, "shared_endpoints": shared_ends,
                "shared_technologies": shared_techs,
            }
            selected.append(agent)

        for agent in selected:
            result = await agent.run()
            agent_results.append(_make_result_dict(result))

        return {
            **state,
            "agent_results": agent_results,
            "current_phase": "vulnerability",
        }

    # ─── NODE: AI_ANALYSIS ──────────────────────────────
    async def _node_ai_analysis(self, state: RavenGraphState) -> RavenGraphState:
        logger.info("🧠 [Graph] AI Analysis phase")
        await self._emit_phase("ai_analysis", 80.0, "🧠 AI Analysis — PoC validation + remediation...")

        agent_results = state.get("agent_results", [])
        findings_objs = _findings_to_objects(state)

        from itzraven.agents.poc_validator_agent import PoCValidatorAgent
        from itzraven.agents.remediation_agent import RemediationAgent

        poc = PoCValidatorAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager)
        poc.set_findings_to_validate(findings_objs)
        self._apply_auth(poc)
        poc_result = await poc.run()
        agent_results.append(_make_result_dict(poc_result))

        rem = RemediationAgent(self.target, event_bus=self.event_bus, memory_manager=self.memory_manager)
        rem.set_findings_to_remediate(findings_objs)
        self._apply_auth(rem)
        rem_result = await rem.run()
        agent_results.append(_make_result_dict(rem_result))

        # Collect all finding dicts from results
        all_finding_dicts = []
        for ar in agent_results:
            all_finding_dicts.extend(ar.get("findings", []))

        return {
            **state,
            "agent_results": agent_results,
            "all_findings": all_finding_dicts,
            "current_phase": "ai_analysis",
        }

    # ─── NODE: REPORTING ────────────────────────────────
    async def _node_reporting(self, state: RavenGraphState) -> RavenGraphState:
        logger.info("📊 [Graph] Reporting phase")
        await self._emit_phase("reporting", 95.0, "📊 Reporting — generating findings report...")

        findings_objs = _findings_to_objects(state)

        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_objs:
            s = f.severity.lower()
            if s in findings_by_severity:
                findings_by_severity[s] += 1

        logger.info(f"✓ Scan completed — {len(findings_objs)} total findings")
        logger.info(f"   Critical: {findings_by_severity['critical']}")
        logger.info(f"   High: {findings_by_severity['high']}")
        logger.info(f"   Medium: {findings_by_severity['medium']}")
        logger.info(f"   Low: {findings_by_severity['low']}")

        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanCompletedEvent(
                    scan_id=self.scan_id, target=self.target, mode=self.mode,
                    total_findings=len(findings_objs), duration=0, success=True,
                ))
            except Exception:
                pass

        return {
            **state,
            "current_phase": "completed",
        }

    # ─── CONDITIONAL EDGE ROUTERS ───────────────────────
    def _route_from_planning(self, state: RavenGraphState) -> str:
        return "reconnaissance"

    def _route_from_recon(self, state: RavenGraphState) -> str:
        has_web_tech = any(t.lower() in ("http", "nginx", "apache", "iis", "tomcat", "caddy", "cloudflare", "wordpress", "php", "python", "node.js", "express", "django", "flask", "react", "vue", "angular", "next.js", "nuxt") for t in state.get("shared_technologies", []))
        if has_web_tech:
            return "enumeration"
        return "reporting"

    def _route_from_enumeration(self, state: RavenGraphState) -> str:
        if len(state.get("shared_endpoints", [])) > 0:
            return "vulnerability"
        return "reporting"

    def _route_from_vulnerability(self, state: RavenGraphState) -> str:
        findings = _findings_to_objects(state)
        has_findings = len(findings) > 0
        if has_findings:
            return "ai_analysis"
        return "reporting"

    def _route_from_ai_analysis(self, state: RavenGraphState) -> str:
        return "reporting"

    # ─── AGENT FACTORIES ────────────────────────────────
    def _register_agent_factories(self):
        from itzraven.agents.sql_injection_agent import SQLInjectionAgent
        from itzraven.agents.xss_agent import XSSAgent
        from itzraven.agents.ssrf_agent import SSRFAgent
        from itzraven.agents.command_injection_agent import CommandInjectionAgent
        from itzraven.agents.authentication_agent import AuthenticationAgent
        from itzraven.agents.idor_agent import IDORAgent
        from itzraven.agents.xxe_agent import XXEAgent
        from itzraven.agents.ssti_agent import SSTIAgent
        from itzraven.agents.open_redirect_agent import OpenRedirectAgent
        from itzraven.agents.cors_agent import CORSAgent
        from itzraven.agents.clickjacking_agent import ClickjackingAgent
        from itzraven.agents.nosql_injection_agent import NoSQLInjectionAgent
        from itzraven.agents.host_header_injection_agent import HostHeaderInjectionAgent
        from itzraven.agents.jwt_attack_agent import JWTTAttackAgent
        from itzraven.agents.rate_limit_agent import RateLimitAgent
        from itzraven.agents.strix_pentest_agent import StrixPentestAgent

        if not self._agent_factories:
            self._agent_factories = [
                ("web", SQLInjectionAgent, {}),
                ("web", XSSAgent, {}),
                ("web", SSRFAgent, {}),
                ("web", CommandInjectionAgent, {}),
                ("web", AuthenticationAgent, {}),
                ("web", IDORAgent, {}),
                ("web", XXEAgent, {}),
                ("web", SSTIAgent, {}),
                ("web", OpenRedirectAgent, {}),
                ("web", CORSAgent, {}),
                ("web", ClickjackingAgent, {}),
                ("web", NoSQLInjectionAgent, {}),
                ("web", HostHeaderInjectionAgent, {}),
                ("web", JWTTAttackAgent, {}),
                ("web", RateLimitAgent, {}),
                ("web", StrixPentestAgent, {"scope": self.scope, "scan_depth": self.scan_depth, "scan_mode": self.mode, "instruction": self.instruction}),
            ]

    # ─── BUILD GRAPH ────────────────────────────────────
    def _build_graph(self, checkpointer=None) -> StateGraph:
        builder = StateGraph(RavenGraphState)

        builder.add_node("planning", self._node_planning)
        builder.add_node("reconnaissance", self._node_recon)
        builder.add_node("enumeration", self._node_enumeration)
        builder.add_node("vulnerability", self._node_vulnerability)
        builder.add_node("ai_analysis", self._node_ai_analysis)
        builder.add_node("reporting", self._node_reporting)

        builder.add_conditional_edges("planning", self._route_from_planning)
        builder.add_conditional_edges("reconnaissance", self._route_from_recon, {
            "enumeration": "enumeration",
            "reporting": "reporting",
        })
        builder.add_conditional_edges("enumeration", self._route_from_enumeration, {
            "vulnerability": "vulnerability",
            "reporting": "reporting",
        })
        builder.add_conditional_edges("vulnerability", self._route_from_vulnerability, {
            "ai_analysis": "ai_analysis",
            "reporting": "reporting",
        })
        builder.add_conditional_edges("ai_analysis", self._route_from_ai_analysis)
        builder.add_edge("reporting", END)

        builder.set_entry_point("planning")

        cp = checkpointer or self.checkpointer or True
        return builder.compile(checkpointer=cp, interrupt_before=["ai_analysis", "reporting"])

    # ─── RUN ────────────────────────────────────────────
    async def run(self) -> ScanResult:
        start_time = datetime.now()

        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanStartedEvent(
                    scan_id=self.scan_id, target=self.target, mode=self.mode, agent_count=6,
                ))
            except Exception:
                pass

        initial_state: RavenGraphState = {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "scan_depth": self.scan_depth,
            "sub_mode": self.sub_mode,
            "scope": self.scope,
            "instruction": self.instruction,
            "start_time": start_time.isoformat(),
            "all_findings": [],
            "agent_results": [],
            "shared_technologies": [],
            "shared_endpoints": [],
            "shared_subdomains": [],
            "open_ports": [],
            "detected_wafs": [],
            "target_ip": None,
            "plan_categories": [],
            "completed_agents": [],
            "current_phase": "init",
            "error": None,
        }

        thread_id = self.scan_id
        config_lg = {"configurable": {"thread_id": thread_id}}

        async with AsyncSqliteSaver.from_conn_string(self._cp_file) as saver:
            self.graph = self._build_graph(checkpointer=saver)
            try:
                async for output in self.graph.astream(initial_state, config_lg):
                    if isinstance(output, dict):
                        for node_name, node_output in output.items():
                            logger.debug(f"[Graph] Node completed: {node_name}")

                final_state = await self.graph.aget_state(config_lg)
                state_values = final_state.values if final_state else initial_state
            except Exception as e:
                logger.error(f"[Graph] Runtime error: {e}")
                state_values = initial_state

        end_time = datetime.now()

        all_finding_dicts = state_values.get("all_findings", [])
        all_finding_objs = [_finding_from_dict(f) for f in all_finding_dicts]

        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_finding_objs:
            s = f.severity.lower()
            if s in findings_by_severity:
                findings_by_severity[s] += 1

        agent_result_objs = []
        agent_results_list = state_values.get("agent_results", [])
        for ar in agent_results_list:
            findings_objs = [_finding_from_dict(f) for f in ar.get("findings", [])]
            agent_result_objs.append(AgentResult(
                agent_name=ar.get("agent_name", "unknown"),
                status=AgentStatus.COMPLETED,
                findings=findings_objs,
                execution_time=ar.get("execution_time", 0),
                error=ar.get("error"),
                metadata=ar.get("metadata", {}),
            ))

        scan_result = ScanResult(
            target=self.target,
            start_time=start_time,
            end_time=end_time,
            total_findings=len(all_finding_objs),
            findings_by_severity=findings_by_severity,
            agent_results=agent_result_objs,
            all_findings=all_finding_objs,
            metadata={"mode": self.mode, "scan_depth": self.scan_depth, "graph": True, "thread_id": thread_id},
        )

        logger.info(f"✓ [Graph] Scan completed in {scan_result.duration:.2f}s — {scan_result.total_findings} findings")
        return scan_result

    # ─── HUMAN-IN-THE-LOOP ──────────────────────────────
    async def resume_with_feedback(self, thread_id: str, feedback: Optional[Dict] = None) -> ScanResult:
        config_lg = {"configurable": {"thread_id": thread_id}}

        if feedback:
            Command(resume=feedback)

        async for event in self.graph.astream_events(None, config_lg, version="v2"):
            pass

        final_state = await self.graph.aget_state(config_lg)
        # convert to ScanResult...
        return await self._state_to_result(final_state.values if final_state else {})

    def get_checkpoint_path(self) -> str:
        return self._cp_file

    async def has_checkpoint(self, thread_id: str) -> bool:
        if not os.path.exists(self._cp_file):
            return False
        async with AsyncSqliteSaver.from_conn_string(self._cp_file) as saver:
            try:
                state = await saver.aget_tuple({"configurable": {"thread_id": thread_id}})
                return state is not None and len(state.values.get("agent_results", [])) > 0
            except Exception:
                return False
