import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from contextlib import contextmanager

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_id: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    error: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {},
        })

    def finish(self, status: str = "ok", error: Optional[str] = None):
        self.end_time = time.time()
        self.status = status
        self.error = error

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "duration_ms": round(self.duration_ms, 2),
            "status": self.status,
            "error": self.error,
            "attributes": self.attributes,
            "events": self.events[-10:],
        }


class Tracer:
    _instance: Optional["Tracer"] = None

    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._spans: Dict[str, Span] = {}
        self._trace_stack: Dict[str, List[str]] = {}
        self._current_trace: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Span:
        if not self._enabled:
            return Span(name="disabled", trace_id="", span_id="")
        trace = trace_id or self._current_trace or str(uuid.uuid4())
        self._current_trace = trace
        span = Span(
            name=name,
            trace_id=trace,
            span_id=str(uuid.uuid4()),
            parent_id=parent_id,
            attributes=attributes or {},
        )
        self._spans[span.span_id] = span
        if trace not in self._trace_stack:
            self._trace_stack[trace] = []
        self._trace_stack[trace].append(span.span_id)
        return span

    def end_span(self, span: Span, status: str = "ok", error: Optional[str] = None):
        if not self._enabled:
            return
        span.finish(status, error)
        trace = span.trace_id
        if trace in self._trace_stack:
            stack = self._trace_stack[trace]
            if span.span_id in stack:
                stack.remove(span.span_id)
            if not stack:
                del self._trace_stack[trace]

    def get_trace_spans(self, trace_id: str) -> List[Span]:
        return [s for s in self._spans.values() if s.trace_id == trace_id]

    def get_span(self, span_id: str) -> Optional[Span]:
        return self._spans.get(span_id)

    def get_all_spans(self, limit: int = 100) -> List[dict]:
        spans = sorted(self._spans.values(), key=lambda s: s.start_time, reverse=True)
        return [s.to_dict() for s in spans[:limit]]

    def clear(self):
        self._spans.clear()
        self._trace_stack.clear()
        self._current_trace = None

    def get_stats(self) -> dict:
        return {
            "total_spans": len(self._spans),
            "active_traces": len(self._trace_stack),
            "enabled": self._enabled,
        }

    @classmethod
    def get_instance(cls) -> "Tracer":
        if cls._instance is None:
            cls._instance = Tracer()
        return cls._instance


class TraceContext:
    def __init__(self, tracer: Tracer, name: str, attributes: Optional[Dict[str, Any]] = None):
        self._tracer = tracer
        self._name = name
        self._attributes = attributes or {}
        self._span: Optional[Span] = None

    def __enter__(self):
        if self._tracer.enabled:
            self._span = self._tracer.start_span(self._name, attributes=self._attributes)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._span:
            status = "error" if exc_type else "ok"
            error = str(exc_val) if exc_val else None
            self._tracer.end_span(self._span, status=status, error=error)

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        if self._span:
            self._span.add_event(name, attributes)

    @property
    def span(self) -> Optional[Span]:
        return self._span


def trace(name: str, **attributes: Any):
    return TraceContext(Tracer.get_instance(), name, attributes)


_tracer: Optional[Tracer] = None


def get_tracer() -> Tracer:
    global _tracer
    if _tracer is None:
        _tracer = Tracer()
    return _tracer
