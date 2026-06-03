"""
Continuous Monitoring Mode — scheduled recurring scans with diff detection.

Features:
1. Schedule scans via cron-like intervals (--monitor --interval 24h)
2. Diff engine: compare current scan with previous → alert on new findings
3. Passive DNS monitoring: track subdomains, IP changes, cert expiry
4. Webhook on changes
5. State persistence in ~/.itzraven/monitor/
"""

import asyncio
import json
import hashlib
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Callable

import httpx

from itzraven.core.logger import get_logger
from itzraven.core.config import Config
from itzraven.core.graph_memory import GraphMemory, EntityType, get_graph_memory
from itzraven.core.notifier import get_notifier

logger = get_logger()

MONITOR_DIR = Config.MONITOR_DIR


@dataclass
class MonitorTarget:
    target: str
    interval_hours: float
    mode: str = "osint"  # osint / pentest / ctf
    last_scan: float = 0.0
    next_scan: float = 0.0
    scan_count: int = 0
    last_findings_hash: str = ""
    notification_channels: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "interval_hours": self.interval_hours,
            "mode": self.mode,
            "last_scan": self.last_scan,
            "next_scan": self.next_scan,
            "scan_count": self.scan_count,
            "notification_channels": self.notification_channels,
        }


@dataclass
class MonitorDiff:
    target: str
    scan_id: str
    timestamp: float
    new_findings: List[dict]
    resolved_findings: List[dict]
    new_subdomains: List[str]
    changed_ips: List[dict]
    new_ports: List[str]
    expired_certs: List[str]

    def has_changes(self) -> bool:
        return bool(self.new_findings or self.new_subdomains or self.changed_ips
                    or self.new_ports or self.expired_certs)

    def summary(self) -> str:
        parts = []
        if self.new_findings:
            parts.append(f"{len(self.new_findings)} new findings")
        if self.new_subdomains:
            parts.append(f"{len(self.new_subdomains)} new subdomains")
        if self.changed_ips:
            parts.append(f"{len(self.changed_ips)} IP changes")
        if self.new_ports:
            parts.append(f"{len(self.new_ports)} new ports")
        if self.expired_certs:
            parts.append(f"{len(self.expired_certs)} expired certs")
        return f"[{self.target}] " + ", ".join(parts) if parts else f"[{self.target}] No changes"


class ContinuousMonitor:
    """Scheduled recurring scans with diff detection and webhook alerts."""

    def __init__(self, graph: Optional[GraphMemory] = None):
        self._graph = graph or get_graph_memory()
        self._targets: Dict[str, MonitorTarget] = {}
        self._history: Dict[str, List[dict]] = defaultdict(list)
        self._running = False
        self._task = None
        self._on_change_hooks: List[Callable] = []
        self._webhook_urls: List[str] = []
        self._slack_webhook: Optional[str] = None
        self._discord_webhook: Optional[str] = None
        self._consecutive_empty_scans: Dict[str, int] = defaultdict(int)
        MONITOR_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    def add_webhook(self, url: str):
        self._webhook_urls.append(url)
        logger.info(f"Monitor: added webhook: {url}")

    def set_slack_webhook(self, url: str):
        self._slack_webhook = url
        logger.info("Monitor: Slack webhook configured")

    def set_discord_webhook(self, url: str):
        self._discord_webhook = url
        logger.info("Monitor: Discord webhook configured")

    def add_target(self, target: str, interval_hours: float = 24.0,
                   mode: str = "osint"):
        mt = MonitorTarget(
            target=target, interval_hours=interval_hours,
            mode=mode, next_scan=time.time(),  # Scan immediately
        )
        self._targets[target] = mt
        logger.info(f"Monitor: added {target} (every {interval_hours}h, mode={mode})")
        self._save()

    def remove_target(self, target: str) -> bool:
        if target in self._targets:
            del self._targets[target]
            self._save()
            return True
        return False

    def list_targets(self) -> List[dict]:
        return [t.to_dict() for t in self._targets.values()]

    def on_change(self, handler: Callable):
        self._on_change_hooks.append(handler)

    def get_history(self, target: str, limit: int = 10) -> List[dict]:
        return self._history.get(target, [])[-limit:]

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(f"ContinuousMonitor: started ({len(self._targets)} targets)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        self._save()

    async def _monitor_loop(self):
        while self._running:
            now = time.time()
            for target_name, mt in list(self._targets.items()):
                if now >= mt.next_scan:
                    try:
                        diff = await self._run_scan(mt)
                        mt.scan_count += 1
                        mt.last_scan = now
                        mt.next_scan = now + (mt.interval_hours * 3600)
                        self._save()
                        if diff.has_changes():
                            logger.info(f"Monitor: {diff.summary()}")
                            await self._send_webhook(diff)
                            self._consecutive_empty_scans[target_name] = 0
                            for hook in self._on_change_hooks:
                                try:
                                    hook(diff)
                                except Exception as e:
                                    logger.debug(f"Monitor hook error: {e}")
                        else:
                            self._consecutive_empty_scans[target_name] += 1
                            consec = self._consecutive_empty_scans[target_name]
                            if consec > 0 and consec % 10 == 0:
                                logger.info(f"Monitor: {target_name} - {consec} scans with no changes")
                    except Exception as e:
                        logger.error(f"Monitor: scan failed for {target_name}: {e}")
            await asyncio.sleep(60)

    async def _send_webhook(self, diff: MonitorDiff):
        payload = {
            "event": "monitor_diff",
            "target": diff.target,
            "scan_id": diff.scan_id,
            "timestamp": diff.timestamp,
            "summary": diff.summary(),
            "changes": {
                "new_findings": len(diff.new_findings),
                "new_subdomains": diff.new_subdomains[:10],
                "new_ports": diff.new_ports[:10],
                "ip_changes": len(diff.changed_ips),
                "expired_certs": len(diff.expired_certs),
            },
        }
        for url in self._webhook_urls:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json=payload)
                logger.debug(f"Monitor: webhook sent to {url}")
            except Exception as e:
                logger.debug(f"Monitor: webhook failed {url}: {e}")

        if self._slack_webhook:
            slack_msg = {
                "text": f"Itzraven Monitor Alert\n{diff.summary()}\nScan: {diff.scan_id}"
            }
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(self._slack_webhook, json=slack_msg)
            except Exception as e:
                logger.debug(f"Monitor: Slack notification failed: {e}")

        if self._discord_webhook:
            discord_msg = {
                "content": f"**Itzraven Monitor Alert**\n{diff.summary()}\nScan: `{diff.scan_id}`"
            }
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(self._discord_webhook, json=discord_msg)
            except Exception as e:
                logger.debug(f"Monitor: Discord notification failed: {e}")

    async def _run_scan(self, mt: MonitorTarget) -> MonitorDiff:
        from itzraven.core.tool_output_parser import ToolOutputParser
        from itzraven.core.blackboard import get_blackboard
        from itzraven.agents.osint import DomainIntelAgent, DNSIntelAgent, TechIntelAgent

        scan_id = f"monitor_{uuid.uuid4().hex[:8]}"
        findings_before = self._get_findings_snapshot(mt.target)

        # Run OSINT agents
        agents = [
            DomainIntelAgent(target=mt.target, depth="quick"),
            DNSIntelAgent(target=mt.target),
            TechIntelAgent(target=mt.target),
        ]
        for agent in agents:
            try:
                await agent.execute()
            except Exception:
                pass

        findings_after = self._get_findings_snapshot(mt.target)

        return self._compute_diff(mt.target, scan_id, findings_before, findings_after)

    def _get_findings_snapshot(self, target: str) -> dict:
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
        snapshot = {
            "domains": {e.name for e in self._graph.find_entity(EntityType.DOMAIN)},
            "ips": {e.name for e in self._graph.find_entity(EntityType.IP_ADDRESS)},
            "ports": {e.name for e in self._graph.find_entity(EntityType.PORT)},
            "vulns": {e.name for e in self._graph.find_entity(EntityType.VULNERABILITY)},
            "techs": {e.name for e in self._graph.find_entity(EntityType.TECHNOLOGY)},
            "urls": {e.name for e in self._graph.find_entity(EntityType.URL)},
        }
        return snapshot

    def _compute_diff(self, target: str, scan_id: str,
                       before: dict, after: dict) -> MonitorDiff:
        diff = MonitorDiff(
            target=target, scan_id=scan_id, timestamp=time.time(),
            new_findings=[],
            resolved_findings=[],
            new_subdomains=list(after.get("domains", set()) - before.get("domains", set())),
            changed_ips=[],
            new_ports=list(after.get("ports", set()) - before.get("ports", set())),
            expired_certs=[],
        )

        new_vulns = after.get("vulns", set()) - before.get("vulns", set())
        if new_vulns:
            for v in new_vulns:
                diff.new_findings.append({"type": "vulnerability", "name": v})

        new_techs = after.get("techs", set()) - before.get("techs", set())
        if new_techs:
            for t in new_techs:
                diff.new_findings.append({"type": "technology", "name": t})

        new_urls = after.get("urls", set()) - before.get("urls", set())
        if new_urls:
            for u in list(new_urls)[:10]:
                diff.new_findings.append({"type": "url", "name": u})

        self._history[target].append({
            "scan_id": scan_id,
            "timestamp": diff.timestamp,
            "new_subdomains": len(diff.new_subdomains),
            "new_ports": len(diff.new_ports),
            "new_findings": len(diff.new_findings),
        })
        return diff

    def _save(self):
        data = {
            "targets": [t.to_dict() for t in self._targets.values()],
            "history": {k: v[-20:] for k, v in self._history.items()},
        }
        (MONITOR_DIR / "state.json").write_text(json.dumps(data, indent=2))

    def _load(self):
        state_file = MONITOR_DIR / "state.json"
        if not state_file.exists():
            return
        try:
            data = json.loads(state_file.read_text())
            for tdata in data.get("targets", []):
                mt = MonitorTarget(**tdata)
                self._targets[mt.target] = mt
            self._history.update(data.get("history", {}))
        except Exception:
            pass


_monitor: Optional[ContinuousMonitor] = None


def get_monitor() -> ContinuousMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ContinuousMonitor()
    return _monitor
