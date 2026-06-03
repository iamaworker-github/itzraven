"""
Itzraven Web Dashboard Server — FastAPI + WebSocket backend.
Serves the React dashboard and bridges itzraven scan events to the browser.
"""

from __future__ import annotations

import asyncio
import json
import uuid
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from itzraven.core.logger import get_logger
from itzraven.core.event_bus import get_event_bus
from itzraven.core.di_container import get_container

from itzraven.agents.orchestrator import AgentOrchestrator

logger = get_logger()


def _append_log(logs: list, entry: dict) -> list:
    """Append log entry only if different from last, to avoid duplicates."""
    if logs and logs[-1].get("text") == entry.get("text") and logs[-1].get("agent_name") == entry.get("agent_name"):
        return logs
    logs.append(entry)
    return logs


# Current orchestrator reference for pause/kill
_current_orchestrator: Optional['AgentOrchestrator'] = None
_current_scan_task: Optional[asyncio.Task] = None

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "web-dashboard" / "dist"


class ScanRequest(BaseModel):
    target: str
    mode: str = "pentest"
    depth: str = "standard"
    incremental: bool = False
    dry_run: bool = False
    scope: Optional[List[str]] = None
    exclude: Optional[List[str]] = None


class ScopeConfig(BaseModel):
    allow: List[str] = []
    exclude: List[str] = []


class NotificationConfig(BaseModel):
    name: str
    type: str  # slack, discord, webhook
    webhook_url: str
    min_severity: str = "medium"


class ScheduleConfig(BaseModel):
    target: str
    mode: str = "pentest"
    interval_hours: float = 24
    depth: str = "standard"
    incremental: bool = True


class CICDConfig(BaseModel):
    provider: str = "github"  # github, gitlab
    repo: str = ""
    pr_number: int = 0
    token: str = ""
    event: str = "scan_completed"


# ---- State manager ----
class DashboardState:
    """Tracks current scan state for WebSocket clients with disk persistence."""

    def __init__(self):
        self.state: Dict[str, Any] = {
            "cpu": 0,
            "mem": 0,
            "net": 0,
            "tokens": 0,
            "maxTokens": 2000000,
            "credits": 5000,
            "uptime": "00:00:00",
            "llmModel": "",
            "sessionId": "",
            "time": "00:00:00",
            "target": "",
            "mode": "PENTEST",
            "agentStatus": "IDLE",
            "riskProfile": "Balanced",
            "maxParallel": "4 agents",
            "safeMode": True,
            "activeAgentName": "",
            "activeAgentTime": "00:00:00",
            "tokensUsed": "0k",
            "memoryPercent": 0,
            "knowledgeBase": "Idle",
            "agents": [],
            "pipeline": [
                {"name": "AI Planning", "completed": 0, "total": 1, "active": False},
                {"name": "Reconnaissance", "completed": 0, "total": 5, "active": False},
                {"name": "Enumeration", "completed": 0, "total": 3, "active": False},
                {"name": "Vulnerability", "completed": 0, "total": 4, "active": False},
                {"name": "AI Analysis", "completed": 0, "total": 2, "active": False},
                {"name": "Exploitation", "completed": 0, "total": 2, "active": False},
                {"name": "Reporting", "completed": 0, "total": 2, "active": False},
            ],
            "logs": [],
            "thinkingLines": [],
            "activities": [],
            "findings": [],
            "technologies": [],
            "discoveries": [],
            "nodes": [],
            "edges": [],
            "riskScore": 0,
            "riskLabel": "Unknown",
            "targetIP": "",
            "openPorts": 0,
            "subdomains": 0,
            "technologies_count": 0,
            "attackSurface": "Unknown",
            "commandsExecuted": 0,
            "dataCollected": "0 MB",
            "findingsCount": 0,
            "vulnerabilities": 0,
        }
        self.clients: Set[WebSocket] = set()
        self._start_time = time.time()

    def update(self, data: Dict[str, Any]):
        self.state.update(data)
        # Auto-add root node when target is set
        if data.get("target") and not self.state.get("nodes"):
            self.state["nodes"] = [{"id": "root", "label": data["target"], "x": 50, "y": 10, "type": "host", "color": "#00ff88"}]

    def reset(self):
        self.state.update({
            "target": "",
            "mode": "PENTEST",
            "agentStatus": "IDLE",
            "activeAgentName": "",
            "agents": [],
            "logs": [],
            "thinkingLines": [],
            "activities": [],
            "findings": [],
            "findingsCount": 0,
            "technologies": [],
            "discoveries": [],
            "nodes": [],
            "edges": [],
            "riskScore": 0,
            "riskLabel": "Unknown",
            "targetIP": "",
            "openPorts": 0,
            "subdomains": 0,
            "technologies_count": 0,
            "attackSurface": "Unknown",
            "commandsExecuted": 0,
            "dataCollected": "0 MB",
            "vulnerabilities": 0,
            "pipeline": [
                {"name": "AI Planning", "completed": 0, "total": 1, "active": False},
                {"name": "Reconnaissance", "completed": 0, "total": 5, "active": False},
                {"name": "Enumeration", "completed": 0, "total": 3, "active": False},
                {"name": "Vulnerability", "completed": 0, "total": 4, "active": False},
                {"name": "AI Analysis", "completed": 0, "total": 2, "active": False},
                {"name": "Exploitation", "completed": 0, "total": 2, "active": False},
                {"name": "Reporting", "completed": 0, "total": 2, "active": False},
            ],
        })
        self._start_time = time.time()

    def get_state(self) -> Dict[str, Any]:
        elapsed = int(time.time() - self._start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        return {
            **self.state,
            "uptime": f"{h:02d}:{m:02d}:{s:02d}",
            "time": f"{h:02d}:{m:02d}:{s:02d}",
        }


dashboard_state = DashboardState()

# Pending scan from CLI (set by itzraven web -t before server starts)
_pending_scan: Optional[Dict[str, str]] = None


# ---- Event bus bridge ----
def setup_event_subscriptions():
    """Subscribe to itzraven EventBus and bridge to dashboard state."""
    bus = get_event_bus()

    @bus.subscribe("agent.started")
    async def on_agent_started(event):
        agents = dashboard_state.state.get("agents", [])
        now = datetime.now().strftime("%H:%M:%S")
        _structured_log.append({"event": "agent.started", "agent": event.agent_name, "timestamp": now})
        if not any(a.get("name") == event.agent_name for a in agents):
            agents.append({
                "name": event.agent_name,
                "id": event.agent_name.lower().replace(" ", "_"),
                "status": "running",
                "progress": 0,
                "findings": 0,
            })
        logs = dashboard_state.state.get("logs", [])
        logs = _append_log(logs, {"text": f"Agent started: {event.agent_name}", "type": "info", "timestamp": now, "agent_name": event.agent_name})
        activities = dashboard_state.state.get("activities", [])
        activities.append({"time": now, "agent": event.agent_name, "message": "Agent started"})
        dashboard_state.update({
            "activeAgentName": event.agent_name.upper(),
            "activeAgentTime": "00:00:00",
            "agentStatus": "EXECUTING",
            "agents": agents[-20:],
            "logs": logs[-50:],
            "activities": activities[-30:],
        })
        await broadcast_state()

    @bus.subscribe("agent.completed")
    async def on_agent_completed(event):
        agents = dashboard_state.state.get("agents", [])
        now = datetime.now().strftime("%H:%M:%S")
        _structured_log.append({"event": "agent.completed", "agent": event.agent_name, "findings": event.findings_count, "timestamp": now})
        for a in agents:
            if a["name"] == event.agent_name:
                a["status"] = "completed"
                a["progress"] = 100
        logs = dashboard_state.state.get("logs", [])
        logs = _append_log(logs, {"text": f"Agent completed: {event.agent_name} ({event.findings_count} findings)", "type": "success", "timestamp": now, "agent_name": event.agent_name})
        activities = dashboard_state.state.get("activities", [])
        activities.append({"time": now, "agent": event.agent_name, "message": f"Agent completed — {event.findings_count} findings"})
        dashboard_state.update({
            "agentStatus": "IDLE",
            "agents": agents,
            "logs": logs[-50:],
            "activities": activities[-30:],
        })
        await broadcast_state()

    @bus.subscribe("agent.failed")
    async def on_agent_failed(event):
        agents = dashboard_state.state.get("agents", [])
        now = datetime.now().strftime("%H:%M:%S")
        for a in agents:
            if a["name"] == event.agent_name:
                a["status"] = "error"
        logs = dashboard_state.state.get("logs", [])
        logs = _append_log(logs, {"text": f"Agent failed: {event.agent_name} — {event.error_message}", "type": "error", "timestamp": now, "agent_name": event.agent_name})
        activities = dashboard_state.state.get("activities", [])
        activities.append({"time": now, "agent": event.agent_name, "message": f"Agent failed: {event.error_message}"})
        dashboard_state.update({
            "agentStatus": "ERROR",
            "agents": agents,
            "logs": logs[-50:],
            "activities": activities[-30:],
        })
        await broadcast_state()

    @bus.subscribe("agent.thinking")
    async def on_agent_thinking(event):
        lines = dashboard_state.state.get("thinkingLines", [])
        lines = lines[-9:] + [f"> {event.thought}"]
        now = datetime.now().strftime("%H:%M:%S")
        logs = dashboard_state.state.get("logs", [])
        logs = _append_log(logs, {"text": f"[{event.agent_name}] {event.thought}", "type": "thinking", "timestamp": now, "agent_name": event.agent_name})
        dashboard_state.update({
            "thinkingLines": lines,
            "logs": logs[-50:],
        })
        await broadcast_state()

    @bus.subscribe("finding.discovered")
    async def on_finding(event):
        findings = dashboard_state.state.get("findings", [])
        now = datetime.now().strftime("%H:%M:%S")
        _structured_log.append({"event": "finding.discovered", "title": event.title, "severity": event.severity, "agent": event.agent_name, "timestamp": now})
        findings = findings[-19:] + [{
            "text": event.title,
            "title": event.title,
            "description": event.description,
            "severity": event.severity,
            "category": event.category,
            "evidence": event.evidence,
            "confidence": event.confidence,
            "cvss_score": event.cvss_score,
            "cwe_id": event.cwe_id,
            "remediation": event.remediation,
            "agent_name": event.agent_name,
        }]
        findings_count = dashboard_state.state.get("findingsCount", 0) + 1
        agents = dashboard_state.state.get("agents", [])
        for a in agents:
            if a["name"] == event.agent_name:
                a["findings"] = a.get("findings", 0) + 1
        logs = dashboard_state.state.get("logs", [])
        logs = _append_log(logs, {"text": f"Finding: {event.title} [{event.severity.upper()}]", "type": "warning", "timestamp": now, "agent_name": event.agent_name})

        # Extract technologies from findings (Recon Agent batch, httpx inline, or any tech finding)
        tech_update = {}
        existing_techs = dashboard_state.state.get("technologies", [])
        existing_names = {t.get("name") if isinstance(t, dict) else t for t in existing_techs}
        new_techs = []
        if event.agent_name == "Recon Agent" and "technologies" in event.title.lower():
            if event.evidence and event.evidence.startswith("Technologies:"):
                raw = event.evidence.replace("Technologies:", "").strip()
                tech_list = [t.strip() for t in raw.split(",") if t.strip()]
                for t in tech_list:
                    if t not in existing_names:
                        new_techs.append({"name": t, "icon": "", "percent": 100})
                        existing_names.add(t)
        elif event.agent_name == "httpx" and event.title.startswith("Technology: "):
            tech_name = event.title.replace("Technology: ", "").strip()
            if tech_name and tech_name not in existing_names:
                new_techs.append({"name": tech_name, "icon": "", "percent": 100})
                existing_names.add(tech_name)
        elif event.severity == "info" and event.category == "osint_tech" and "Technology" in event.title:
            tech_name = event.title.replace("Technology: ", "").strip() if "Technology:" in event.title else event.title.strip()
            if tech_name and tech_name not in existing_names:
                new_techs.append({"name": tech_name, "icon": "", "percent": 100})
                existing_names.add(tech_name)
        if new_techs:
            tech_update = {
                "technologies": existing_techs + new_techs,
                "technologies_count": len(existing_techs) + len(new_techs),
            }

        dashboard_state.update({
            "findings": findings,
            "findingsCount": findings_count,
            "agents": agents,
            "logs": logs[-50:],
            **tech_update,
        })
        await broadcast_state()

    @bus.subscribe("agent.progress")
    async def on_agent_progress(event):
        agents = dashboard_state.state.get("agents", [])
        now = datetime.now().strftime("%H:%M:%S")
        for a in agents:
            if a["name"] == event.agent_name:
                a["progress"] = max(a.get("progress", 0), int(event.progress))
        logs = dashboard_state.state.get("logs", [])
        if event.message:
            logs = _append_log(logs, {"text": f"[{event.agent_name}] {event.message}", "type": "info", "timestamp": now, "agent_name": event.agent_name})
        # Extract target IP from recon messages
        if event.message and "Target IP:" in event.message:
            import re as _re
            m = _re.search(r'Target IP:\s*([\d.]+)', event.message)
            if m:
                dashboard_state.update({"targetIP": m.group(1)})
        # Extract open ports from messages
        if event.message and "open ports:" in event.message.lower():
            import re as _re
            m = _re.search(r'open ports:\s*(\d+)', event.message, _re.I)
            if m:
                dashboard_state.update({"openPorts": int(m.group(1))})
        # Update pipeline stage from current_phase
        pipeline = list(dashboard_state.state.get("pipeline", []))
        phase_to_stage = {
            "planning": 0, "reconnaissance": 1, "enumeration": 2,
            "vulnerability": 3, "ai_analysis": 4, "exploitation": 5, "reporting": 6,
        }
        phase_agent_names = {
            "planning": "Plan Agent", "reconnaissance": "Recon Agent",
            "enumeration": "BackMeUp Agent", "vulnerability": "Vuln Scanner",
            "ai_analysis": "Analysis Agent", "exploitation": "Exploitation Agent",
            "reporting": "Report Agent",
        }
        if event.current_phase == "completed":
            for s in pipeline:
                s["active"] = False
                s["completed"] = s["total"]
        elif event.current_phase in phase_to_stage:
            ix = phase_to_stage[event.current_phase]
            for i, s in enumerate(pipeline):
                was_active = s.get("active", False)
                is_current = i == ix
                if is_current and not was_active:
                    pipeline[i]["active"] = True
                elif not is_current and was_active and i < ix:
                    pipeline[i]["active"] = False
                    pipeline[i]["completed"] = pipeline[i]["total"]
            # Add phase agent to agents list if not already there
            agent_name = phase_agent_names.get(event.current_phase)
            if agent_name and not any(a.get("name") == agent_name for a in agents):
                agents.append({
                    "name": agent_name,
                    "id": agent_name.lower().replace(" ", "_"),
                    "status": "running" if pipeline[ix].get("active") else "idle",
                    "progress": int(event.progress),
                    "findings": 0,
                })
        # Update agent status based on pipeline
        for a in agents:
            a_name = a.get("name", "")
            a_phase = None
            for p_name, p_agent in phase_agent_names.items():
                if p_agent == a_name:
                    a_phase = p_name
                    break
            if a_phase and a_phase in phase_to_stage:
                ix = phase_to_stage[a_phase]
                s = pipeline[ix] if ix < len(pipeline) else None
                if s:
                    if s.get("completed") == s.get("total") and s.get("total", 0) > 0:
                        a["status"] = "completed"
                    elif s.get("active"):
                        a["status"] = "running"
                    else:
                        a["status"] = "idle"
        dashboard_state.update({
            "commandsExecuted": dashboard_state.state.get("commandsExecuted", 0) + 1,
            "dataCollected": f"{float(dashboard_state.state.get('dataCollected', '0').split()[0]) + 0.1:.1f} MB",
            "agents": agents,
            "logs": logs[-50:],
            "pipeline": pipeline,
        })
        await broadcast_state()


async def broadcast_state():
    """Broadcast current state to all connected WebSocket clients."""
    state = dashboard_state.get_state()
    msg = json.dumps({"type": "state", "payload": state})
    dead: List[WebSocket] = []
    for client in dashboard_state.clients:
        try:
            await client.send_text(msg)
        except Exception:
            dead.append(client)
    for d in dead:
        dashboard_state.clients.discard(d)


async def _health_tick():
    """Periodically update system health metrics — live data."""
    import psutil
    from itzraven.agents.llm_client import get_cost_tracker, LLMClient
    from itzraven.core.config import get_config

    _prev_net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    _prev_time = time.monotonic()

    while True:
        await asyncio.sleep(2)
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
        except Exception:
            cpu = 0
            mem = 0

        # Real network I/O rate
        try:
            now = time.monotonic()
            cur = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
            elapsed = now - _prev_time
            net_rate = int((cur - _prev_net) / elapsed) if elapsed > 0 else 0
            _prev_net = cur
            _prev_time = now
        except Exception:
            net_rate = 0

        # Real token usage from CostTracker
        try:
            tokens = get_cost_tracker().total_tokens
        except Exception:
            tokens = dashboard_state.state.get("tokens", 0)

        # LLM status
        try:
            cfg = get_config()
            if cfg.has_ai_enabled:
                llm_model = LLMClient().model
            else:
                llm_model = "AI OFF"
        except Exception:
            llm_model = "AI OFF"

        dashboard_state.update({
            "cpu": round(cpu, 1),
            "mem": round(mem, 1),
            "net": net_rate,
            "tokens": tokens,
            "llmModel": llm_model,
        })
        if dashboard_state.clients:
            await broadcast_state()


# ---- FastAPI app ----
app = FastAPI(title="Itzraven Web Dashboard")


@app.on_event("startup")
async def startup():
    global _pending_scan
    bus = get_event_bus()
    await bus.start()
    setup_event_subscriptions()
    asyncio.create_task(_health_tick())

    # Start pending scan if set via CLI itzraven web -t
    if _pending_scan:
        ps = _pending_scan
        _pending_scan = None
        import re as _re
        target_ip = ps["target"] if _re.match(r'^\d+\.\d+\.\d+\.\d+$', ps["target"]) else ""
        dashboard_state.update({"targetIP": target_ip})
        await asyncio.sleep(1)
        await broadcast_state()
        asyncio.create_task(_run_scan_task(ps["target"], ps["mode"], ps["session_id"]))


@app.get("/api/state")
async def get_state():
    return dashboard_state.get_state()


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    session_id = uuid.uuid4().hex[:8]
    import re as _re
    target_ip = req.target if _re.match(r'^\d+\.\d+\.\d+\.\d+$', req.target) else ""
    dashboard_state.update({
        "target": req.target,
        "mode": req.mode.upper(),
        "depth": req.depth,
        "incremental": req.incremental,
        "sessionId": session_id,
        "agentStatus": "PLANNING",
        "targetIP": target_ip,
        "commandsExecuted": 0,
        "dataCollected": "0 MB",
        "findingsCount": 0,
        "findings": [],
        "logs": [],
        "thinkingLines": [],
        "activities": [],
        "discoveries": [],
        "technologies": [],
        "technologies_count": 0,
    })
    if req.dry_run:
        return {"status": "dry_run", "message": "Dry-run mode — no scan started"}
    if req.scope:
        dashboard_state.state["scope_allow"] = req.scope
    if req.exclude:
        dashboard_state.state["scope_exclude"] = req.exclude
    await broadcast_state()

    asyncio.create_task(_run_scan_task(req.target, req.mode, session_id, depth=req.depth, incremental=req.incremental))

    return {"status": "started", "session_id": session_id}


async def _run_scan_task(target: str, mode: str, session_id: str, depth: str = "standard", incremental: bool = False):
    global _current_orchestrator, _current_scan_task
    _current_scan_task = asyncio.current_task()
    _current_orchestrator = None
    try:
        from itzraven.core.config import set_config
        from itzraven.cli import run_scan as _run_scan
        set_config(verbose=False, output_dir=Path("./itzraven_results"))

        def _store_orchestrator(orch):
            global _current_orchestrator
            _current_orchestrator = orch

        result = await _run_scan(
            target=target,
            parallel=False,
            scan_depth=depth,
            non_interactive=True,
            mode=mode,
            event_bus=get_event_bus(),
            _from_web=True,
            _orchestrator_hook=_store_orchestrator,
        )

        findings_count = getattr(result, 'total_findings', 0)
        all_findings = getattr(result, 'all_findings', [])

        # Extract findings from result
        findings_list = []
        for f in all_findings:
            findings_list.append({
                "text": f.title,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "category": f.category,
                "evidence": f.evidence,
                "confidence": f.confidence,
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id,
                "remediation": f.remediation,
                "agent_name": f.agent_name,
            })

        # Extract agent results for nodes/edges
        agent_results = getattr(result, 'agent_results', [])
        nodes = dashboard_state.state.get("nodes", [])
        edges = dashboard_state.state.get("edges", [])
        if not nodes or (len(nodes) == 1 and nodes[0].get("id") == "root" and nodes[0].get("label") == "target.domain"):
            nodes = [{"id": "root", "label": target, "x": 50, "y": 10, "type": "host", "color": "#00ff88"}]

        logs = []
        activities = []
        for ar in agent_results:
            agent_name = getattr(ar, "agent_name", "unknown")
            logs = _append_log(logs, {"text": f"Agent {agent_name} completed — {len(getattr(ar, 'findings', []))} findings", "type": "info", "agent_name": agent_name})
            activities.append({"time": datetime.now().strftime("%H:%M:%S"), "agent": agent_name, "message": f"Agent completed with {len(getattr(ar, 'findings', []))} findings"})

            for f in getattr(ar, "findings", []):
                nid = f"f_{f.finding_id[:8] if hasattr(f, 'finding_id') and f.finding_id else 'unknown'}"
                if nid not in [n.get("id") for n in nodes]:
                    nodes.append({"id": nid, "label": f.title[:30], "sublabel": f.severity.upper(), "x": 30 + len(nodes) * 20, "y": 54, "type": "application", "color": "#a855f7"})
                    edges.append({"from": "root", "to": nid})

        dashboard_state.update({
            "findings": findings_list[-20:],
            "findingsCount": findings_count,
            "logs": (dashboard_state.state.get("logs", []) + logs)[-50:],
            "activities": (dashboard_state.state.get("activities", []) + activities)[-20:],
            "nodes": nodes,
            "edges": edges,
            "agentStatus": "IDLE",
        })
        await broadcast_state()
        logger.info(f"Scan completed: {target} — {findings_count} findings")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        import traceback
        traceback.print_exc()
        dashboard_state.update({"agentStatus": "IDLE"})
        await broadcast_state()
    finally:
        _current_orchestrator = None
        _current_scan_task = None


@app.post("/api/scan/stop")
async def stop_scan():
    global _current_orchestrator, _current_scan_task
    if _current_orchestrator:
        _current_orchestrator.cancel_all()
        _current_orchestrator = None
    if _current_scan_task and not _current_scan_task.done():
        _current_scan_task.cancel()
        _current_scan_task = None
    dashboard_state.update({
        "agentStatus": "CANCELLED",
        "agents": [{"id": "all", "name": "Scan", "status": "Killed", "findings": 0}],
        "pipeline": [
            {"name": s["name"], "completed": s["completed"], "total": s["total"], "active": False, "cancelled": True}
            if s.get("active") else s
            for s in dashboard_state.state.get("pipeline", [])
        ],
    })
    await broadcast_state()
    return {"status": "stopped"}


@app.post("/api/scan/new")
async def new_scan():
    global _current_orchestrator, _current_scan_task
    if _current_orchestrator:
        _current_orchestrator.cancel_all()
        _current_orchestrator = None
    if _current_scan_task and not _current_scan_task.done():
        _current_scan_task.cancel()
        _current_scan_task = None
    dashboard_state.reset()
    chat_history_store.clear()
    await broadcast_state()
    return {"status": "new_scan_ready"}


# ---- Scope API ----
@app.get("/api/scope")
async def get_scope():
    return {
        "allow": dashboard_state.state.get("scope_allow", []),
        "exclude": dashboard_state.state.get("scope_exclude", []),
    }


@app.post("/api/scope")
async def set_scope(cfg: ScopeConfig):
    dashboard_state.state["scope_allow"] = cfg.allow
    dashboard_state.state["scope_exclude"] = cfg.exclude
    await broadcast_state()
    return {"status": "ok"}


# ---- Notifications API ----
_app_notifier = None


def _get_notifier():
    global _app_notifier
    if _app_notifier is None:
        from itzraven.core.notifier import get_notifier
        _app_notifier = get_notifier()
        _app_notifier.subscribe_to_events()
    return _app_notifier


@app.get("/api/notifications")
async def list_notifications():
    return {"channels": _get_notifier().list_channels()}


@app.post("/api/notifications")
async def add_notification(cfg: NotificationConfig):
    from itzraven.core.notifier import NotificationChannel
    channel = NotificationChannel(
        name=cfg.name,
        type=cfg.type,
        config={"webhook_url": cfg.webhook_url},
        min_severity=cfg.min_severity,
    )
    _get_notifier().add_channel(channel)
    return {"status": "added", "name": cfg.name}


@app.delete("/api/notifications/{name}")
async def delete_notification(name: str):
    ok = _get_notifier().remove_channel(name)
    return {"status": "removed" if ok else "not_found"}


# ---- Checkpoint / Resume API ----
@app.get("/api/checkpoint")
async def get_checkpoint():
    from itzraven.core.checkpoint_manager import get_checkpoint_manager
    scan_id = dashboard_state.state.get("sessionId", "")
    if not scan_id:
        return {"status": "no_active_scan"}
    mgr = get_checkpoint_manager(scan_id=scan_id, target="", mode="")
    cp = mgr.resume()
    if cp:
        return {"status": "found", "checkpoint": cp}
    return {"status": "no_checkpoint"}


# ---- Health Check / Dry-Run ----
@app.get("/api/health")
async def health_check():
    import platform, psutil
    return {
        "status": "ok",
        "version": "2.0.0",
        "uptime": f"{int(time.time() - dashboard_state._start_time)}s",
        "python": platform.python_version(),
        "cpu_percent": psutil.cpu_percent(interval=0),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_free_gb": round(psutil.disk_usage("/").free / (1024**3), 1),
        "active_scan": dashboard_state.state.get("agentStatus") not in ("IDLE", "CANCELLED"),
        "orchestrator_active": _current_orchestrator is not None,
    }


@app.post("/api/scan/dry-run")
async def dry_run_scan(req: ScanRequest):
    """Preview scan commands without executing."""
    commands = [
        f"[DRY-RUN] Target: {req.target}",
        f"[DRY-RUN] Mode: {req.mode}",
        f"[DRY-RUN] Depth: {req.depth}",
        f"[DRY-RUN] Tools: nmap, nuclei, httpx, subfinder, sqlmap, ffuf",
        f"[DRY-RUN] Agents: Recon → DomainIntel → TechIntel → Nuclei → SQLi",
        f"[DRY-RUN] Estimated time: 15-30 min",
        f"[DRY-RUN] Estimated findings: 5-20",
    ]
    if req.incremental:
        commands.append("[DRY-RUN] Mode: incremental (diff against last scan)")
    if req.dry_run:
        commands.append("[DRY-RUN] Dry-run: true (no commands executed)")
    return {"status": "dry_run", "commands": commands, "target": req.target, "mode": req.mode}


# ---- Scan Scheduling ----
_scheduler_task: Optional[asyncio.Task] = None
_scheduled_jobs: List[Dict[str, Any]] = []


@app.get("/api/schedule")
async def list_schedules():
    return {"schedules": _scheduled_jobs}


@app.post("/api/schedule")
async def add_schedule(cfg: ScheduleConfig):
    job = {
        "id": uuid.uuid4().hex[:8],
        "target": cfg.target,
        "mode": cfg.mode,
        "interval_hours": cfg.interval_hours,
        "depth": cfg.depth,
        "incremental": cfg.incremental,
        "next_run": time.time() + cfg.interval_hours * 3600,
        "last_run": None,
        "active": True,
    }
    _scheduled_jobs.append(job)
    _ensure_scheduler()
    return {"status": "scheduled", "job": job}


@app.delete("/api/schedule/{job_id}")
async def delete_schedule(job_id: str):
    global _scheduled_jobs
    _scheduled_jobs = [j for j in _scheduled_jobs if j["id"] != job_id]
    return {"status": "removed"}


def _ensure_scheduler():
    global _scheduler_task
    if _scheduler_task is None or _scheduler_task.done():
        _scheduler_task = asyncio.create_task(_scheduler_loop())


async def _scheduler_loop():
    while True:
        now = time.time()
        for job in _scheduled_jobs:
            if job.get("active") and now >= job.get("next_run", now):
                job["last_run"] = now
                job["next_run"] = now + job["interval_hours"] * 3600
                asyncio.create_task(_run_scan_task(job["target"], job["mode"], uuid.uuid4().hex[:8], depth=job["depth"], incremental=job["incremental"]))
        await asyncio.sleep(30)


# ---- CI/CD Integration ----
@app.post("/api/cicd/comment")
async def cicd_comment(cfg: CICDConfig):
    if cfg.provider == "github" and cfg.token and cfg.repo and cfg.pr_number:
        try:
            import httpx
            findings = dashboard_state.state.get("findings", [])
            summary = f"## Itzraven Scan Report\n\n**Target:** {dashboard_state.state.get('target', 'N/A')}\n**Mode:** {dashboard_state.state.get('mode', 'N/A')}\n**Findings:** {len(findings)}\n\n"
            for f in findings[-10:]:
                summary += f"- **[{f.get('severity','info').upper()}]** {f.get('title', 'N/A')}\n"
            summary += "\n---\n*Generated by Itzraven Security Agent*"
            r = await httpx.AsyncClient().post(
                f"https://api.github.com/repos/{cfg.repo}/issues/{cfg.pr_number}/comments",
                json={"body": summary},
                headers={"Authorization": f"Bearer {cfg.token}", "Accept": "application/vnd.github.v3+json"},
            )
            return {"status": "commented" if r.status_code == 201 else "failed", "code": r.status_code}
        except Exception as e:
            return {"status": "error", "detail": str(e)}
    return {"status": "skipped", "detail": "missing required fields"}


# ---- Report Generation ----
@app.get("/api/report/json")
async def report_json():
    return dashboard_state.get_state()


@app.get("/api/report/html")
async def report_html():
    findings = dashboard_state.state.get("findings", [])
    target = dashboard_state.state.get("target", "N/A")
    mode = dashboard_state.state.get("mode", "N/A")
    session = dashboard_state.state.get("sessionId", "N/A")

    rows = ""
    for f in findings:
        sev = f.get("severity", "info").upper()
        color = {"CRITICAL": "dc2626", "HIGH": "ea580c", "MEDIUM": "ca8a04", "LOW": "2563eb", "INFO": "6b7280"}.get(sev, "6b7280")
        rows += f"<tr><td style='padding:6px 10px;border-bottom:1px solid #333;color:#{color};font-weight:bold'>{sev}</td><td style='padding:6px 10px;border-bottom:1px solid #333'>{f.get('title','')}</td><td style='padding:6px 10px;border-bottom:1px solid #333'>{f.get('category','')}</td><td style='padding:6px 10px;border-bottom:1px solid #333'>{f.get('agent_name','')}</td></tr>"

    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>Itzraven Report — {target}</title>
<style>body{{background:#09090b;color:#e4e4e7;font-family:monospace;padding:20px}}h1{{color:#facc15}}h2{{color:#a78bfa}}table{{width:100%;border-collapse:collapse}}th{{text-align:left;padding:8px 10px;border-bottom:2px solid #52525b;color:#a1a1aa}}</style></head>
<body><h1>🔍 Itzraven Security Report</h1>
<p><strong>Target:</strong> {target} | <strong>Mode:</strong> {mode} | <strong>Session:</strong> {session}</p>
<h2>Findings ({len(findings)})</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Agent</th></tr></thead><tbody>{rows}</tbody></table>
<p style='color:#52525b;margin-top:30px;font-size:12px'>Generated by Itzraven v2.0.0</p></body></html>"""
    from fastapi.responses import HTMLResponse as HTMLResp
    return HTMLResp(content=html)


# ---- Structured Logging ----
_structured_log: List[Dict[str, Any]] = []


@app.post("/api/log")
async def write_log(entry: dict):
    entry["timestamp"] = datetime.now().isoformat()
    _structured_log.append(entry)
    return {"status": "logged"}


@app.get("/api/log")
async def read_log(limit: int = 100):
    return {"logs": _structured_log[-limit:]}


chat_history_store: List[Dict[str, Any]] = []


class ChatRequest(BaseModel):
    message: str


@app.get("/api/chat")
async def get_chat():
    return {"messages": chat_history_store[-50:]}


@app.post("/api/chat")
async def post_chat(req: ChatRequest):
    user_entry = {"role": "user", "text": req.message, "timestamp": datetime.now().isoformat(), "id": uuid.uuid4().hex[:8]}
    chat_history_store.append(user_entry)
    dashboard_state.state.setdefault("chat_history", []).append(user_entry)
    try:
        from itzraven.agents.llm_client import LLMClient
        client = LLMClient()
        system_prompt = "You are Itzraven AI, a cybersecurity assistant. Be concise in Hinglish."
        response = await asyncio.wait_for(
            client.generate(req.message, system=system_prompt, max_tokens=300, task="chat"),
            timeout=15,
        )
        reply_text = response.content if hasattr(response, 'content') else str(response)
        if not reply_text or reply_text.strip() == req.message:
            reply_text = None
    except asyncio.TimeoutError:
        reply_text = None
    except Exception:
        reply_text = None

    if not reply_text:
        target = dashboard_state.state.get("target", "")
        status = dashboard_state.state.get("agentStatus", "IDLE")
        findings = dashboard_state.state.get("findingsCount", 0)
        elapsed = dashboard_state.state.get("time", "00:00:00")
        reply_text = f"Scan status: {status} | Target: {target or '—'} | Findings: {findings} | Time: {elapsed}"

    reply_entry = {"role": "assistant", "text": str(reply_text)[:1000], "timestamp": datetime.now().isoformat(), "id": uuid.uuid4().hex[:8]}
    chat_history_store.append(reply_entry)
    dashboard_state.state.setdefault("chat_history", []).append(reply_entry)
    return {"reply": reply_entry["text"]}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    dashboard_state.clients.add(websocket)
    logger.info("WebSocket client connected")

    try:
        # Send initial state
        await websocket.send_text(json.dumps({
            "type": "state",
            "payload": dashboard_state.get_state(),
        }))

        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif msg.get("type") == "agent_pause":
                    agent_id = msg.get("payload", {}).get("agent_id", "")
                    agents = dashboard_state.state.get("agents", [])
                    matched_name = None
                    for a in agents:
                        if a.get("id") == agent_id or a.get("name", "").lower().replace(" ", "_") == agent_id:
                            a["status"] = "paused"
                            matched_name = a.get("name", "")
                            logger.info(f"Agent paused: {matched_name}")
                    dashboard_state.update({"agents": agents})
                    if matched_name and _current_orchestrator:
                        _current_orchestrator.pause_agent(matched_name)
                    await broadcast_state()
                elif msg.get("type") == "agent_resume":
                    agent_id = msg.get("payload", {}).get("agent_id", "")
                    agents = dashboard_state.state.get("agents", [])
                    matched_name = None
                    for a in agents:
                        if a.get("id") == agent_id or a.get("name", "").lower().replace(" ", "_") == agent_id:
                            a["status"] = "running"
                            matched_name = a.get("name", "")
                            logger.info(f"Agent resumed: {matched_name}")
                    dashboard_state.update({"agents": agents})
                    if matched_name and _current_orchestrator:
                        _current_orchestrator.resume_agent(matched_name)
                    await broadcast_state()
                elif msg.get("type") == "agent_kill":
                    agent_id = msg.get("payload", {}).get("agent_id", "")
                    agents = dashboard_state.state.get("agents", [])
                    matched_name = None
                    for a in agents:
                        if a.get("id") == agent_id or a.get("name", "").lower().replace(" ", "_") == agent_id:
                            a["status"] = "killed"
                            matched_name = a.get("name", "")
                            logger.info(f"Agent killed: {matched_name}")
                    dashboard_state.update({"agents": agents})
                    if matched_name and _current_orchestrator:
                        _current_orchestrator.cancel_agent(matched_name)
                    await broadcast_state()
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
    finally:
        dashboard_state.clients.discard(websocket)


@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Serve index.html for all non-API routes (SPA fallback)."""
    index_path = DASHBOARD_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text())
    return JSONResponse({"error": "Dashboard not built"}, status_code=404)


# ---- Standalone runner ----
def run_server(host: str = "0.0.0.0", port: int = 8484):
    """Start the web dashboard server."""
    import uvicorn
    logger.info(f"Itzraven Web Dashboard: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
