"""
Autonomous Hunt Loop — continuous bug bounty/pentest mode.

Inspired by pentest-agents /autopilot: runs agents in waves,
reports findings, deep-dives on interesting endpoints, and
maintains session state across runs.

Features:
- Wave-based execution with circuit breaker
- Endpoint depth scoring (prioritizes promising paths)
- State persistence across sessions
- Self-tuning scan parameters
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

from itzraven.core.logger import get_logger
from itzraven.core.config import ITZRAVEN_HOME
from itzraven.core.circuit_breaker import get_circuit_breaker_registry

logger = get_logger()


@dataclass
class EndpointState:
    """State tracking for a single endpoint."""
    url: str
    depth_score: float = 0.0
    waves_tested: int = 0
    findings_count: int = 0
    last_tested: Optional[str] = None
    interesting: bool = False
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url, "depth_score": self.depth_score,
            "waves_tested": self.waves_tested, "findings_count": self.findings_count,
            "last_tested": self.last_tested, "interesting": self.interesting,
            "tags": list(self.tags),
        }


@dataclass
class HuntSession:
    """Persistent hunt session state."""
    target: str
    session_id: str
    start_time: str = ""
    waves_completed: int = 0
    total_findings: int = 0
    total_endpoints: int = 0
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "session_id": self.session_id,
            "start_time": self.start_time, "waves_completed": self.waves_completed,
            "total_findings": self.total_findings,
            "total_endpoints": self.total_endpoints, "active": self.active,
        }


class Autopilot:
    """Autonomous hunting loop with wave-based execution."""

    MAX_WAVES = 10
    WAVE_TIMEOUT = 600  # 10 min per wave
    MIN_INTERESTING_SCORE = 2.0
    WAVE_AGENTS = ["recon", "web", "api", "enterprise"]

    def __init__(self, target: str):
        self.target = target
        self.session_id = f"hunt-{int(time.time())}"
        self.state_dir = ITZRAVEN_HOME / "autopilot"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.endpoints: Dict[str, EndpointState] = {}
        self.session = HuntSession(
            target=target,
            session_id=self.session_id,
            start_time=datetime.now().isoformat(),
        )
        self.circuit_breaker = get_circuit_breaker_registry()
        self._load_state()

    def _state_path(self) -> Path:
        safe = self.target.replace("/", "_").replace(":", "_")
        return self.state_dir / f"{safe}.json"

    def _save_state(self):
        data = {
            "session": self.session.to_dict(),
            "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
        }
        self._state_path().write_text(json.dumps(data, indent=2))
        logger.debug(f"Autopilot state saved ({len(self.endpoints)} endpoints)")

    def _load_state(self):
        path = self._state_path()
        if path.exists():
            try:
                data = json.loads(path.read_text())
                self.session = HuntSession(**data.get("session", {}))
                self.session.active = True
                for url, ed in data.get("endpoints", {}).items():
                    ed["tags"] = set(ed.get("tags", []))
                    self.endpoints[url] = EndpointState(**ed)
                logger.info(f"Autopilot state loaded: {self.session.waves_completed} waves, {len(self.endpoints)} endpoints")
            except Exception as e:
                logger.warning(f"Failed to load autopilot state: {e}")

    def record_endpoint(self, url: str, tags: Optional[List[str]] = None):
        """Record or update an endpoint."""
        if url not in self.endpoints:
            self.endpoints[url] = EndpointState(url=url)
        ep = self.endpoints[url]
        ep.waves_tested += 1
        ep.last_tested = datetime.now().isoformat()
        if tags:
            ep.tags.update(tags)
        self._save_state()

    def score_endpoint(self, url: str, finding_severity: str = "info"):
        """Score endpoint based on finding quality."""
        if url not in self.endpoints:
            self.endpoints[url] = EndpointState(url=url)
        ep = self.endpoints[url]
        severity_scores = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0.5}
        ep.depth_score += severity_scores.get(finding_severity, 0.5)
        ep.findings_count += 1
        if ep.depth_score >= self.MIN_INTERESTING_SCORE:
            ep.interesting = True
        self._save_state()

    def get_interesting_endpoints(self, min_score: float = 1.0) -> List[EndpointState]:
        """Get endpoints worth deeper investigation."""
        return sorted(
            [ep for ep in self.endpoints.values() if ep.depth_score >= min_score],
            key=lambda x: x.depth_score, reverse=True,
        )

    def should_continue(self) -> bool:
        """Check if hunt should continue to next wave."""
        if self.session.waves_completed >= self.MAX_WAVES:
            return False
        interesting = self.get_interesting_endpoints()
        if not interesting and self.session.waves_completed >= 3:
            return False  # no promising leads
        return True

    def wave_plan(self) -> Dict[str, Any]:
        """Generate next wave plan based on accumulated state.

        Returns:
            Dict with categories and endpoints for next wave.
        """
        self.session.waves_completed += 1
        wave = self.session.waves_completed

        interesting = self.get_interesting_endpoints()
        cat_weights = defaultdict(float)
        agent_priority = []

        # Prioritize agents based on findings so far
        for ep in self.endpoints.values():
            for tag in ep.tags:
                if tag in self.WAVE_AGENTS:
                    cat_weights[tag] += ep.depth_score

        # First wave: full coverage
        if wave == 1:
            agent_priority = ["recon", "web", "api", "enterprise"]
        else:
            # Subsequent waves: focus on interesting categories
            sorted_cats = sorted(cat_weights.items(), key=lambda x: -x[1])
            agent_priority = [c[0] for c in sorted_cats if c[1] > 0] or self.WAVE_AGENTS

        plan = {
            "wave": wave,
            "agents": agent_priority,
            "endpoints": [ep.url for ep in interesting[:5]],
            "depth": "deep" if interesting else "standard",
        }

        logger.info(f"Wave {wave} plan: {agent_priority} agents, {len(interesting)} interesting endpoints")
        self._save_state()
        return plan

    def summary(self) -> Dict[str, Any]:
        """Return hunt summary."""
        interesting = self.get_interesting_endpoints()
        return {
            "target": self.target,
            "session_id": self.session_id,
            "waves": self.session.waves_completed,
            "total_endpoints": len(self.endpoints),
            "interesting_endpoints": len(interesting),
            "total_findings": self.session.total_findings,
            "active": self.session.active,
            "circuit_breaker_states": self.circuit_breaker.get_all_states() if hasattr(self.circuit_breaker, 'get_all_states') else {},
        }


_autopilot_instances: Dict[str, Autopilot] = {}


def get_autopilot(target: str) -> Autopilot:
    """Get or create Autopilot for a target."""
    if target not in _autopilot_instances:
        _autopilot_instances[target] = Autopilot(target)
    return _autopilot_instances[target]
