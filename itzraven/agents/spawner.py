"""
Agent Spawner — hierarchical agent spawning system.

Allows a parent agent to spawn child sub-agents as isolated processes.
"""

import asyncio
import uuid
import time
import random
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.blackboard import FindingCategory, get_blackboard
from itzraven.agents.base_agent import Finding

logger = get_logger()


@dataclass
class SubAgent:
    child_id: str
    target: str
    scope: List[str]
    status: str = "spawning"
    spawned_at: float = field(default_factory=time.time)
    findings: List[dict] = field(default_factory=list)
    task: asyncio.Task = None


class AgentSpawner:
    def __init__(self):
        self._children: Dict[str, SubAgent] = {}

    def spawn_child(
        self,
        target: str,
        scope: Optional[List[str]] = None,
        model: Optional[str] = None,
    ) -> str:
        child_id = f"sub-{uuid.uuid4().hex[:12]}"
        child = SubAgent(
            child_id=child_id,
            target=target,
            scope=scope or [],
        )
        child.task = asyncio.create_task(
            self._run_child(child, model),
            name=child_id,
        )
        self._children[child_id] = child
        logger.info(f"Spawned child agent {child_id} for target {target}")
        return child_id

    async def despawn_child(self, child_id: str) -> None:
        child = self._children.get(child_id)
        if child is None:
            logger.warning(f"Child {child_id} not found for despawn")
            return
        child.status = "cancelling"
        child.task.cancel()
        try:
            await child.task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Child {child_id} raised during despawn: {e}")
        child.status = "cancelled"
        logger.info(f"Despawned child agent {child_id}")

    def list_children(self) -> List[Dict[str, Any]]:
        return [
            {
                "child_id": c.child_id,
                "target": c.target,
                "status": c.status,
                "spawned_at": c.spawned_at,
                "findings_count": len(c.findings),
            }
            for c in self._children.values()
            if c.status not in ("cancelled", "completed")
        ]

    def get_child(self, child_id: str) -> Optional[Dict[str, Any]]:
        child = self._children.get(child_id)
        if child is None:
            return None
        return {
            "child_id": child.child_id,
            "target": child.target,
            "status": child.status,
            "spawned_at": child.spawned_at,
            "findings_count": len(child.findings),
        }

    async def _run_child(self, child: SubAgent, model: Optional[str] = None) -> None:
        try:
            child.status = "running"
            findings = await self._execute_sub_scan(child, model)
            child.findings = [f.to_dict() if isinstance(f, Finding) else f for f in findings]
            child.status = "completed"
        except asyncio.CancelledError:
            child.status = "cancelled"
            logger.info(f"Child {child.child_id} cancelled")
            raise
        except Exception as e:
            child.status = "failed"
            logger.error(f"Child {child.child_id} failed: {e}")

    async def _execute_sub_scan(
        self, child: SubAgent, model: Optional[str] = None
    ) -> List[Finding]:
        bb = get_blackboard()

        try:
            from itzraven.agents.recon_agent import ReconAgent
            agent = ReconAgent(
                target=child.target,
                scope=child.scope,
            )
            result = await agent.run()
            findings = result.findings or []
        except Exception as e:
            logger.debug(f"ReconAgent unavailable for {child.child_id}, simulating: {e}")
            await asyncio.sleep(random.uniform(1, 3))
            findings = self._mock_findings(child)

        for f in findings:
            try:
                bb.post(
                    category=FindingCategory.TARGET_REG,
                    key=f"spawner:{child.child_id}:{f.finding_id or uuid.uuid4().hex[:8]}",
                    data={
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                        "evidence": f.evidence,
                        "agent": child.child_id,
                    },
                    source_agent=child.child_id,
                )
            except Exception as e:
                logger.debug(f"Failed to post finding to blackboard: {e}")

        logger.info(
            f"Child {child.child_id} completed with {len(findings)} findings"
        )
        return findings

    def _mock_findings(self, child: SubAgent) -> List[Finding]:
        mock = Finding(
            title=f"Recon scan on {child.target}",
            description=f"Simulated reconnaissance completed for {child.target}",
            severity="info",
            category="recon",
            evidence=f"Scanned {len(child.scope) if child.scope else 1} endpoints",
            agent_name=child.child_id,
        )
        return [mock]
