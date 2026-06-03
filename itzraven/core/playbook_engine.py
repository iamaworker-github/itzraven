"""
Playbook Engine — YAML-based named pipelines for different scenarios.
Pentest-Swarm-AI inspired: bug-bounty, external-asm, ci-cd, internal-network, ctf-solver.
"""
import json
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime

from itzraven.core.swarm.scheduler import SwarmScheduler, SwarmAgent, SwarmContext
from itzraven.core.swarm.blackboard import get_blackboard, BlackboardQuery
from itzraven.core.swarm.trigger import TriggerPredicate
from itzraven.core.logger import get_logger

logger = get_logger()

_PLAYBOOK_DIR = Path(__file__).parent.parent.parent / "playbooks"


@dataclass
class PlaybookStep:
    name: str
    agent: str
    trigger_types: List[str]
    min_pheromone: float = 0.2
    max_concurrency: int = 3
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    name: str
    description: str
    version: str = "1.0"
    steps: List[PlaybookStep] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: Path) -> "Playbook":
        with open(path) as f:
            data = yaml.safe_load(f)
        steps = [PlaybookStep(**s) for s in data.get("steps", [])]
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            steps=steps,
            config=data.get("config", {}),
        )


# Built-in playbooks
BUG_BOUNTY_PLAYBOOK = Playbook(
    name="bug-bounty",
    description="Optimized for bug bounty programs: fast recon → high-value vulns",
    steps=[
        PlaybookStep("recon", "recon_agent", ["TARGET_REGISTERED"], 0.8),
        PlaybookStep("tech_detect", "tech_detect_agent", ["PORT_OPEN", "HTTP_ENDPOINT"], 0.3),
        PlaybookStep("cve_check", "nuclei_agent", ["TECHNOLOGY"], 0.4),
        PlaybookStep("web_scan", "web_agent", ["HTTP_ENDPOINT", "CVE_MATCH"], 0.5),
        PlaybookStep("exploit", "exploit_agent", ["VULNERABILITY"], 0.6),
        PlaybookStep("report", "report_agent", ["CAMPAIGN_COMPLETE"], 0.9),
    ],
    config={"max_depth": "fast", "budget_minutes": 30},
)

EXTERNAL_ASM_PLAYBOOK = Playbook(
    name="external-asm",
    description="External attack surface management: subdomain takeover, exposed assets",
    steps=[
        PlaybookStep("recon", "recon_agent", ["TARGET_REGISTERED"], 0.9, max_concurrency=5),
        PlaybookStep("subdomain", "subdomain_agent", ["SUBDOMAIN"], 0.3, max_concurrency=10),
        PlaybookStep("port_scan", "port_scan_agent", ["SUBDOMAIN"], 0.4),
        PlaybookStep("tech_detect", "tech_detect_agent", ["PORT_OPEN"], 0.3),
        PlaybookStep("vuln_check", "nuclei_agent", ["TECHNOLOGY", "HTTP_ENDPOINT"], 0.4),
        PlaybookStep("report", "report_agent", ["CAMPAIGN_COMPLETE"], 0.9),
    ],
    config={"max_depth": "full", "budget_minutes": 60},
)

CI_CD_PLAYBOOK = Playbook(
    name="ci-cd",
    description="CI/CD pipeline security: fast feedback for dev teams",
    steps=[
        PlaybookStep("fast_recon", "recon_agent", ["TARGET_REGISTERED"], 0.9, max_concurrency=2),
        PlaybookStep("critical_vulns", "web_agent", ["HTTP_ENDPOINT"], 0.5),
        PlaybookStep("report", "report_agent", ["CAMPAIGN_COMPLETE"], 0.9),
    ],
    config={"max_depth": "quick", "budget_minutes": 10},
)

CTF_SOLVER_PLAYBOOK = Playbook(
    name="ctf-solver",
    description="CTF mode: aggressive scanning with custom wordlists",
    steps=[
        PlaybookStep("recon", "recon_agent", ["TARGET_REGISTERED"], 0.8),
        PlaybookStep("full_port", "port_scan_agent", ["TARGET_REGISTERED"], 0.7),
        PlaybookStep("tech_detect", "tech_detect_agent", ["PORT_OPEN"], 0.3),
        PlaybookStep("aggressive_scan", "exploit_agent", ["TECHNOLOGY", "HTTP_ENDPOINT"], 0.3, max_concurrency=5),
        PlaybookStep("report", "report_agent", ["CAMPAIGN_COMPLETE"], 0.9),
    ],
    config={"max_depth": "deep", "budget_minutes": 120},
)


class PlaybookEngine:
    def __init__(self):
        self._playbooks: Dict[str, Playbook] = {}
        self._register_builtins()

    def _register_builtins(self):
        for pb in [BUG_BOUNTY_PLAYBOOK, EXTERNAL_ASM_PLAYBOOK, CI_CD_PLAYBOOK, CTF_SOLVER_PLAYBOOK]:
            self._playbooks[pb.name] = pb

        # Load from disk
        if _PLAYBOOK_DIR.exists():
            for f in _PLAYBOOK_DIR.glob("*.yaml"):
                try:
                    pb = Playbook.from_yaml(f)
                    self._playbooks[pb.name] = pb
                except Exception as e:
                    logger.debug(f"Failed to load playbook {f.name}: {e}")

    def get_playbook(self, name: str) -> Optional[Playbook]:
        return self._playbooks.get(name)

    def list_playbooks(self) -> List[dict]:
        return [
            {"name": p.name, "description": p.description, "version": p.version, "steps": len(p.steps)}
            for p in self._playbooks.values()
        ]

    async def run(self, name: str, target: str, **kwargs) -> dict:
        pb = self.get_playbook(name)
        if not pb:
            return {"success": False, "error": f"Playbook '{name}' not found"}

        board = get_blackboard()
        scheduler = SwarmScheduler(board)

        for step in pb.steps:
            agent = SwarmAgent(
                name=step.agent,
                trigger=TriggerPredicate(
                    finding_types=step.trigger_types,
                    min_pheromone=step.min_pheromone,
                ),
                handler=self._make_handler(step),
                max_concurrency=step.max_concurrency,
            )
            scheduler.register_agent(agent)

        context = SwarmContext(
            target=target,
            scan_id=f"pb_{name}_{datetime.now().strftime('%H%M%S')}",
            mode=f"playbook:{name}",
            scan_depth=pb.config.get("max_depth", "medium"),
            blackboard=board,
            budget_seconds=pb.config.get("budget_minutes", 30) * 60,
            max_decisions=pb.config.get("max_decisions", 15),
        )
        context.params = kwargs

        results = await scheduler.run(context)
        return {
            "success": True,
            "playbook": name,
            "target": target,
            "iterations": len(results),
            "findings_count": len(board.query(BlackboardQuery(target=target, min_weight=0.0))),
            "elapsed": f"{(datetime.now() - datetime.fromtimestamp(context.start_time)).total_seconds():.0f}s",
        }

    def _make_handler(self, step: PlaybookStep):
        async def handler(entry, ctx):
            logger.info(f"  📋 Playbook step: {step.name} (triggered by {entry.finding_type})")
            return [{
                "step": step.name,
                "agent": step.agent,
                "trigger": entry.finding_type,
                "target": ctx["target"],
                "status": "executed",
                "config": step.config,
            }]
        return handler


_instance_playbook: Optional[PlaybookEngine] = None


def get_playbook_engine() -> PlaybookEngine:
    global _instance_playbook
    if _instance_playbook is None:
        _instance_playbook = PlaybookEngine()
    return _instance_playbook
