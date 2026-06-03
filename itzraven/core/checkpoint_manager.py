"""
Git-commit checkpointing for workspace resume.
Shannon-inspired: interrupted scans resume seamlessly from the last checkpoint.

Architecture:
  - After each agent completes, a checkpoint JSON + optional git commit is created
  - Checkpoint stores: scan_id, target, mode, completed_agents, all_findings (serialised), agent_results
  - On resume: read checkpoint, skip completed agents, restore findings
  - Git mode: auto-commit checkpoint changes for full audit trail
"""

import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import Finding, AgentResult

logger = get_logger()


class CheckpointManager:
    """Manages scan checkpoints for workspace resume."""

    CHECKPOINT_DIR = Path.home() / ".itzraven" / "checkpoints"

    def __init__(
        self,
        scan_id: str,
        target: str,
        mode: str = "pentest",
        checkpoint_dir: Optional[Path] = None,
        use_git: bool = False,
        git_repo_path: Optional[str] = None,
    ):
        self.scan_id = scan_id
        self.target = target
        self.mode = mode
        self._dir = Path(checkpoint_dir or self.CHECKPOINT_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._use_git = use_git
        self._repo_path = git_repo_path or self._detect_git_repo()
        self._completed_agents: Set[str] = set()
        self._all_findings: List[dict] = []
        self._agent_results: List[dict] = []

    @staticmethod
    def _detect_git_repo() -> Optional[str]:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    def _checkpoint_path(self) -> Path:
        return self._dir / f"{self.scan_id[:16]}.json"

    def save(
        self,
        agent_name: str,
        findings: List[Finding],
        result: AgentResult,
        completed_pct: float = 0.0,
    ) -> Path:
        self._completed_agents.add(agent_name)
        self._all_findings.extend(f.to_dict() for f in findings)
        self._agent_results.append(result.to_dict())

        data = {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "timestamp": datetime.now().isoformat(),
            "completed_agents": sorted(list(self._completed_agents)),
            "completed_pct": completed_pct,
            "all_findings": self._all_findings,
            "agent_results": self._agent_results,
            "last_agent": agent_name,
        }

        path = self._checkpoint_path()
        path.write_text(json.dumps(data, indent=2, default=str))
        logger.debug(f"Checkpoint saved: {path} (agent={agent_name})")

        if self._use_git and self._repo_path:
            self._git_commit(agent_name)

        return path

    def resume(self) -> Optional[Dict[str, Any]]:
        path = self._checkpoint_path()
        if not path.exists():
            logger.info(f"No checkpoint found at {path}")
            return None
        try:
            data = json.loads(path.read_text())
            self._completed_agents = set(data.get("completed_agents", []))
            self._all_findings = data.get("all_findings", [])
            self._agent_results = data.get("agent_results", [])
            logger.info(
                f"Resumed from checkpoint: {len(self._completed_agents)} agents done, "
                f"{len(self._all_findings)} findings"
            )
            return data
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
            return None

    def is_agent_completed(self, agent_name: str) -> bool:
        return agent_name in self._completed_agents

    def get_completed_agents(self) -> Set[str]:
        return self._completed_agents.copy()

    def get_restored_findings(self) -> List[dict]:
        return list(self._all_findings)

    def clear(self) -> None:
        path = self._checkpoint_path()
        if path.exists():
            path.unlink()
        self._completed_agents.clear()
        self._all_findings.clear()
        self._agent_results.clear()

    @classmethod
    def list_checkpoints(cls, checkpoint_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        cdir = Path(checkpoint_dir or cls.CHECKPOINT_DIR)
        if not cdir.exists():
            return []
        checkpoints = []
        for f in sorted(cdir.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text())
                checkpoints.append({
                    "path": str(f),
                    "scan_id": data.get("scan_id"),
                    "target": data.get("target"),
                    "mode": data.get("mode"),
                    "timestamp": data.get("timestamp"),
                    "completed_agents": len(data.get("completed_agents", [])),
                    "findings": len(data.get("all_findings", [])),
                    "last_agent": data.get("last_agent"),
                })
            except Exception:
                continue
        return checkpoints

    def _git_commit(self, agent_name: str) -> None:
        if not self._repo_path:
            return
        try:
            checkpoint_rel = os.path.relpath(
                str(self._checkpoint_path()), self._repo_path
            )
            subprocess.run(
                ["git", "add", checkpoint_rel],
                cwd=self._repo_path, capture_output=True, timeout=10,
            )
            subprocess.run(
                [
                    "git", "commit",
                    "--allow-empty",
                    "-m", f"itzraven-checkpoint: {agent_name} on {self.target} [{self.scan_id[:8]}]",
                ],
                cwd=self._repo_path, capture_output=True, timeout=10,
            )
            logger.debug(f"Git checkpoint committed for {agent_name}")
        except Exception as e:
            logger.debug(f"Git commit failed: {e}")


_checkpoint_managers: Dict[str, CheckpointManager] = {}


def get_checkpoint_manager(
    scan_id: str,
    target: str,
    mode: str = "pentest",
    use_git: bool = False,
) -> CheckpointManager:
    key = scan_id
    if key not in _checkpoint_managers:
        _checkpoint_managers[key] = CheckpointManager(
            scan_id=scan_id, target=target, mode=mode, use_git=use_git,
        )
    return _checkpoint_managers[key]
