"""
Event schemas for Itzraven event-driven architecture

All events inherit from BaseEvent and provide strongly-typed schemas
for different event categories.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum


class EventPriority(Enum):
    """Event priority levels"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class BaseEvent:
    """Base class for all events in the system

    All events must inherit from this class and provide additional
    fields specific to their event type.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = ""  # Component that generated the event
    correlation_id: str = ""  # For tracing related events
    priority: EventPriority = EventPriority.NORMAL
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "correlation_id": self.correlation_id,
            "priority": self.priority.value,
            "metadata": self.metadata,
        }


# ============================================================================
# AGENT EVENTS
# ============================================================================

@dataclass
class AgentStartedEvent(BaseEvent):
    """Published when an agent starts execution"""
    agent_name: str = ""
    agent_type: str = ""  # "recon", "sql_injection", etc.
    target: str = ""
    mode: str = ""  # "pentest", "ctf", "osint", "bugbounty"
    config: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "agent.started"
        if not self.source:
            self.source = self.agent_name

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "target": self.target,
            "mode": self.mode,
            "config": self.config,
        })
        return base


@dataclass
class AgentThinkingEvent(BaseEvent):
    """Published when an agent is thinking/reasoning - shows LLM chain-of-thought"""
    agent_name: str = ""
    thought: str = ""
    thought_type: str = "reasoning"  # analyzing, planning, evaluating, deciding, searching
    phase: str = ""

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "agent.thinking"
        if not self.source:
            self.source = self.agent_name

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "agent_name": self.agent_name,
            "thought": self.thought,
            "thought_type": self.thought_type,
            "phase": self.phase,
        })
        return base


@dataclass
class AgentProgressEvent(BaseEvent):
    """Published when an agent reports progress"""
    agent_name: str = ""
    progress: float = 0.0  # 0.0 to 100.0
    current_phase: str = ""
    message: str = ""
    estimated_completion: Optional[datetime] = None

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "agent.progress"
        if not self.source:
            self.source = self.agent_name

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "agent_name": self.agent_name,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "message": self.message,
            "estimated_completion": self.estimated_completion.isoformat() if self.estimated_completion else None,
        })
        return base


@dataclass
class AgentCompletedEvent(BaseEvent):
    """Published when an agent completes successfully"""
    agent_name: str = ""
    agent_type: str = ""
    target: str = ""
    execution_time: float = 0.0  # Seconds
    findings_count: int = 0
    success: bool = True

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "agent.completed"
        if not self.source:
            self.source = self.agent_name

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "target": self.target,
            "execution_time": self.execution_time,
            "findings_count": self.findings_count,
            "success": self.success,
        })
        return base


@dataclass
class AgentFailedEvent(BaseEvent):
    """Published when an agent fails"""
    agent_name: str = ""
    agent_type: str = ""
    target: str = ""
    error_message: str = ""
    error_type: str = ""
    stack_trace: Optional[str] = None

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "agent.failed"
        if not self.source:
            self.source = self.agent_name
        self.priority = EventPriority.HIGH

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "target": self.target,
            "error_message": self.error_message,
            "error_type": self.error_type,
            "stack_trace": self.stack_trace,
        })
        return base


# ============================================================================
# FINDING EVENTS
# ============================================================================

@dataclass
class FindingDiscoveredEvent(BaseEvent):
    """Published when a vulnerability is discovered"""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""  # "critical", "high", "medium", "low", "info"
    category: str = ""  # "sql_injection", "xss", etc.
    evidence: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    target: str = ""
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "finding.discovered"
        if not self.source:
            self.source = self.agent_name
        # Set priority based on severity
        if self.severity.lower() in ["critical", "high"]:
            self.priority = EventPriority.HIGH

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "finding_id": self.finding_id,
            "agent_name": self.agent_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "target": self.target,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
        })
        return base


@dataclass
class FindingValidatedEvent(BaseEvent):
    """Published when a finding is validated with PoC"""
    finding_id: str = ""
    validation_method: str = ""
    validation_result: bool = False
    proof_of_concept: str = ""
    screenshot_path: Optional[str] = None
    validation_time: float = 0.0

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "finding.validated"
        if not self.source:
            self.source = "validation_engine"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "finding_id": self.finding_id,
            "validation_method": self.validation_method,
            "validation_result": self.validation_result,
            "proof_of_concept": self.proof_of_concept,
            "screenshot_path": self.screenshot_path,
            "validation_time": self.validation_time,
        })
        return base


# ============================================================================
# SCAN EVENTS
# ============================================================================

@dataclass
class ScanStartedEvent(BaseEvent):
    """Published when a scan starts"""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    mode: str = ""  # "pentest", "ctf", "osint", "bugbounty"
    agent_count: int = 0
    config: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "scan.started"
        if not self.source:
            self.source = "orchestrator"
        if not self.correlation_id:
            self.correlation_id = self.scan_id

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "agent_count": self.agent_count,
            "config": self.config,
        })
        return base


@dataclass
class ScanProgressEvent(BaseEvent):
    """Published to report overall scan progress"""
    scan_id: str = ""
    target: str = ""
    progress: float = 0.0  # 0.0 to 100.0
    agents_completed: int = 0
    agents_total: int = 0
    findings_count: int = 0
    elapsed_time: float = 0.0

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "scan.progress"
        if not self.source:
            self.source = "orchestrator"
        if not self.correlation_id:
            self.correlation_id = self.scan_id

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "scan_id": self.scan_id,
            "target": self.target,
            "progress": self.progress,
            "agents_completed": self.agents_completed,
            "agents_total": self.agents_total,
            "findings_count": self.findings_count,
            "elapsed_time": self.elapsed_time,
        })
        return base


@dataclass
class ScanCompletedEvent(BaseEvent):
    """Published when a scan completes"""
    scan_id: str = ""
    target: str = ""
    mode: str = ""
    duration: float = 0.0  # Seconds
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    agents_executed: List[str] = field(default_factory=list)
    success: bool = True

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "scan.completed"
        if not self.source:
            self.source = "orchestrator"
        if not self.correlation_id:
            self.correlation_id = self.scan_id

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "duration": self.duration,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "agents_executed": self.agents_executed,
            "success": self.success,
        })
        return base


# ============================================================================
# TOOLKIT EVENTS
# ============================================================================

@dataclass
class BrowserPageLoadedEvent(BaseEvent):
    """Published when browser loads a page"""
    url: str = ""
    status_code: int = 0
    load_time: float = 0.0
    page_title: str = ""

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "toolkit.browser.page_loaded"
        if not self.source:
            self.source = "browser_automation"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "url": self.url,
            "status_code": self.status_code,
            "load_time": self.load_time,
            "page_title": self.page_title,
        })
        return base


@dataclass
class ShellCommandExecutedEvent(BaseEvent):
    """Published when a shell command is executed"""
    command: str = ""
    return_code: int = 0
    execution_time: float = 0.0
    stdout_length: int = 0
    stderr_length: int = 0

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "toolkit.shell.command_executed"
        if not self.source:
            self.source = "shell_executor"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "command": self.command,
            "return_code": self.return_code,
            "execution_time": self.execution_time,
            "stdout_length": self.stdout_length,
            "stderr_length": self.stderr_length,
        })
        return base


# ============================================================================
# SYSTEM EVENTS
# ============================================================================

@dataclass
class SystemErrorEvent(BaseEvent):
    """Published when a system error occurs"""
    error_message: str = ""
    error_type: str = ""
    component: str = ""
    stack_trace: Optional[str] = None
    recoverable: bool = True

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "system.error"
        if not self.source:
            self.source = self.component
        self.priority = EventPriority.CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "error_message": self.error_message,
            "error_type": self.error_type,
            "component": self.component,
            "stack_trace": self.stack_trace,
            "recoverable": self.recoverable,
        })
        return base


@dataclass
class SystemMetricEvent(BaseEvent):
    """Published for system metrics"""
    metric_name: str = ""
    metric_value: float = 0.0
    metric_unit: str = ""
    tags: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.event_type:
            self.event_type = "system.metric"
        if not self.source:
            self.source = "metrics_collector"
        self.priority = EventPriority.LOW

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "metric_unit": self.metric_unit,
            "tags": self.tags,
        })
        return base


# ============================================================================
# EVENT TYPE REGISTRY
# ============================================================================

EVENT_TYPE_REGISTRY: Dict[str, type] = {
    "agent.started": AgentStartedEvent,
    "agent.thinking": AgentThinkingEvent,
    "agent.progress": AgentProgressEvent,
    "agent.completed": AgentCompletedEvent,
    "agent.failed": AgentFailedEvent,
    "finding.discovered": FindingDiscoveredEvent,
    "finding.validated": FindingValidatedEvent,
    "scan.started": ScanStartedEvent,
    "scan.progress": ScanProgressEvent,
    "scan.completed": ScanCompletedEvent,
    "toolkit.browser.page_loaded": BrowserPageLoadedEvent,
    "toolkit.shell.command_executed": ShellCommandExecutedEvent,
    "system.error": SystemErrorEvent,
    "system.metric": SystemMetricEvent,
}


def create_event_from_dict(event_type: str, data: Dict[str, Any]) -> BaseEvent:
    """Create an event object from event type and data dictionary

    Args:
        event_type: The event type (e.g., "agent.started")
        data: Dictionary containing event data

    Returns:
        Event object of the appropriate type

    Raises:
        ValueError: If event_type is not registered
    """
    event_class = EVENT_TYPE_REGISTRY.get(event_type)
    if not event_class:
        # Return generic BaseEvent for unknown types
        return BaseEvent(event_type=event_type, **data)

    return event_class(**data)
