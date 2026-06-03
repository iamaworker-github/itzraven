"""
Reaction Engine — Blackboard event-driven agent collaboration.

When an agent posts a finding to the blackboard, the reaction engine
checks predefined rules and triggers dependent agents automatically.

Example chaining:
  SQLi found → trigger WAFBypassAgent + DataExfiltrationAgent
  SSRF found → trigger InternalPortScanAgent + CloudMetadataAgent
  IDOR found → trigger EscalationAgent + LateralMovementAgent
"""

import asyncio
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Dict, Any, Awaitable
from itzraven.core.blackboard import BlackboardEntry, get_blackboard, FindingCategory
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class ReactionRule:
    """A reaction rule: trigger when a finding matches conditions."""
    name: str
    trigger_techniques: List[str]
    trigger_severity: str = "high"
    min_confidence: float = 0.7
    target_agent_name: str = ""
    target_agent_factory: Optional[Callable[..., Any]] = None
    context_enricher: Optional[Callable[[BlackboardEntry], Dict[str, Any]]] = None
    description: str = ""


class ReactionEngine:
    """Listens to Blackboard events and triggers agent reactions.

    Integrates with pentest orchestrator to auto-launch dependent agents
    when specific finding types are discovered.
    """

    def __init__(self, orchestrator=None):
        self.orchestrator = orchestrator
        self.blackboard = get_blackboard()
        self.rules: List[ReactionRule] = []
        self._running = False
        self._pending_launches: List[Dict[str, Any]] = []
        self._triggered: set = set()

    def add_rule(self, rule: ReactionRule):
        """Register a reaction rule."""
        self.rules.append(rule)
        logger.debug(f"ReactionRule added: {rule.name}")

    def start(self):
        """Start listening to blackboard events."""
        if self._running:
            return
        self.blackboard.subscribe("new", self._on_new_finding)
        self._running = True
        logger.info(f"ReactionEngine started: {len(self.rules)} rules active")

    def stop(self):
        self._running = False

    def get_pending_launches(self) -> List[Dict[str, Any]]:
        """Get accumulated reactions and clear the queue."""
        launches = list(self._pending_launches)
        self._pending_launches.clear()
        return launches

    def _on_new_finding(self, entry: BlackboardEntry):
        """Handle new blackboard entry — check reaction rules."""
        if not self._running:
            return
        if not entry or not entry.data:
            return

        finding = entry.data if isinstance(entry.data, dict) else {}
        title = str(finding.get("title", "") or "")
        evidence = str(finding.get("evidence", "") or "")
        category = str(finding.get("category", "") or "")
        technique = str(finding.get("technique", "") or category)
        severity = str(finding.get("severity", "") or "")
        confidence = float(finding.get("confidence", 0.5) or 0.5)
        agent_name = entry.source_agent or ""

        search_text = f"{title} {evidence} {category}".lower()

        for rule in self.rules:
            trigger_key = f"{rule.name}:{entry.key}"
            if trigger_key in self._triggered:
                continue

            match = False
            for trigger_tech in rule.trigger_techniques:
                if trigger_tech.lower() in technique.lower():
                    match = True
                    break
                if trigger_tech.lower() in search_text:
                    match = True
                    break

            if not match:
                continue

            severity_ok = (
                not rule.trigger_severity
                or severity.lower() in rule.trigger_severity.lower()
                or severity.lower() == rule.trigger_severity.lower()
            )
            if not severity_ok:
                if severity not in ("", "info"):
                    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    trig_sev = sev_order.get(rule.trigger_severity, 99)
                    actual_sev = sev_order.get(severity, 99)
                    if actual_sev > trig_sev:
                        continue

            if confidence < rule.min_confidence:
                continue

            self._triggered.add(trigger_key)
            context = None
            if rule.context_enricher:
                try:
                    context = rule.context_enricher(entry)
                except Exception as e:
                    logger.debug(f"Context enricher failed for {rule.name}: {e}")

            launch = {
                "rule_name": rule.name,
                "target_agent_name": rule.target_agent_name,
                "target_agent_factory": rule.target_agent_factory,
                "trigger_entry": entry,
                "context": context or {},
                "description": rule.description,
            }
            self._pending_launches.append(launch)
            logger.info(f"⚡ Reaction triggered: {rule.name} (from {agent_name})")

    def add_default_rules(self):
        """Add production-grade reaction rules."""
        self.rules = [
            ReactionRule(
                name="sqli_exploit",
                trigger_techniques=["sqli", "sql injection"],
                trigger_severity="high",
                target_agent_name="WAFBypassEngine",
                description="SQLi found — deploy WAF bypass + data exfiltration",
            ),
            ReactionRule(
                name="xss_escalation",
                trigger_techniques=["xss", "cross site scripting"],
                trigger_severity="medium",
                target_agent_name="SessionHijackAgent",
                description="XSS found — attempt session hijacking",
            ),
            ReactionRule(
                name="ssrf_pivot",
                trigger_techniques=["ssrf", "server side request forgery"],
                trigger_severity="high",
                target_agent_name="InternalPortScanner",
                description="SSRF found — probe internal network via gopher/file",
            ),
            ReactionRule(
                name="idor_escalation",
                trigger_techniques=["idor", "insecure direct object"],
                trigger_severity="high",
                min_confidence=0.8,
                target_agent_name="PrivilegeEscalationAgent",
                description="IDOR found — escalate to account takeover",
            ),
            ReactionRule(
                name="rce_chain",
                trigger_techniques=["rce", "remote code execution", "command injection"],
                trigger_severity="critical",
                min_confidence=0.9,
                target_agent_name="PostExploitationAgent",
                description="RCE found — deploy post-exploitation chain",
            ),
            ReactionRule(
                name="waf_detected",
                trigger_techniques=["waf", "firewall", "cloudflare", "modsecurity"],
                trigger_severity="low",
                target_agent_name="WAFBypassAgent",
                description="WAF detected — auto-deploy bypass payloads",
            ),
        ]


_reaction_engine: Optional[ReactionEngine] = None


def get_reaction_engine(orchestrator=None) -> ReactionEngine:
    global _reaction_engine
    if _reaction_engine is None:
        _reaction_engine = ReactionEngine(orchestrator=orchestrator)
        _reaction_engine.add_default_rules()
    return _reaction_engine
