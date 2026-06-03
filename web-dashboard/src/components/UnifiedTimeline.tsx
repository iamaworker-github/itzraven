import { useRef, useEffect, useState } from 'react';
import type { TimelineEvent, Severity, AgentStatus } from '../types';

interface Props {
  events: TimelineEvent[];
  agentName: string;
  agentStatus: AgentStatus;
  elapsed: string;
  filterAgent: string;
  filterSeverity: string;
  onFilterAgentChange: (v: string) => void;
  onFilterSeverityChange: (v: string) => void;
  agents: { name: string }[];
}

const eventTypeColors: Record<string, string> = {
  started: 'text-green-400',
  completed: 'text-cyan-400',
  finding: 'text-yellow-300',
  error: 'text-red-400',
  info: 'text-zinc-400',
};

const eventTypeBadge: Record<string, string> = {
  started: 'bg-green-900 text-green-300 border-green-700',
  completed: 'bg-cyan-900 text-cyan-300 border-cyan-700',
  finding: 'bg-yellow-900 text-yellow-300 border-yellow-700',
  error: 'bg-red-900 text-red-300 border-red-700',
  info: 'bg-zinc-800 text-zinc-400 border-zinc-700',
};

const severityColors: Record<Severity, string> = {
  CRITICAL: 'text-red-400 bg-red-900/40 border-red-600',
  HIGH: 'text-orange-400 bg-orange-900/40 border-orange-600',
  MEDIUM: 'text-yellow-400 bg-yellow-900/40 border-yellow-600',
  LOW: 'text-blue-400 bg-blue-900/40 border-blue-600',
  INFO: 'text-zinc-400 bg-zinc-800 border-zinc-600',
};

export default function UnifiedTimeline({
  events,
  agentName,
  agentStatus,
  elapsed,
  filterAgent,
  filterSeverity,
  onFilterAgentChange,
  onFilterSeverityChange,
  agents,
}: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  const handleScroll = () => {
    if (!scrollRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 40);
  };

  const filtered = events.filter((e) => {
    const agentMatch = filterAgent === 'all' || e.agentName === filterAgent || e.agentName.includes(filterAgent) || filterAgent.includes(e.agentName);
    const sevMatch = filterSeverity === 'all' || !e.severity || e.severity === filterSeverity || (filterSeverity === 'events' && !e.severity);
    return agentMatch && sevMatch;
  });

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Header with FIX: merged log+activity + filter controls */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-700 bg-zinc-900 shrink-0">
        <div className="flex items-center gap-2">
          <div
            className={`w-2 h-2 rounded-full ${agentStatus === 'Running' ? 'bg-green-400 animate-pulse' : agentStatus === 'Paused' ? 'bg-yellow-400' : 'bg-zinc-500'}`}
          />
          <span className="text-zinc-300 font-mono text-xs font-bold uppercase tracking-wider">
            {agentName}
          </span>
          <span
            className={`font-mono text-xs font-bold ${agentStatus === 'Running' ? 'text-green-400' : agentStatus === 'Paused' ? 'text-yellow-400' : 'text-zinc-500'}`}
          >
            ● {agentStatus.toUpperCase()}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* FIX: Agent filter */}
          <select
            value={filterAgent}
            onChange={(e) => onFilterAgentChange(e.target.value)}
            className="bg-zinc-800 text-zinc-300 text-[12px] font-mono border border-zinc-700 rounded px-1 py-0.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Agents</option>
            {agents.map((a) => (
              <option key={a.name} value={a.name}>{a.name}</option>
            ))}
          </select>
          {/* FIX: Severity filter */}
          <select
            value={filterSeverity}
            onChange={(e) => onFilterSeverityChange(e.target.value)}
            className="bg-zinc-800 text-zinc-300 text-[12px] font-mono border border-zinc-700 rounded px-1 py-0.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Types</option>
            <option value="events">Events Only</option>
            <option value="INFO">INFO</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <span className="text-zinc-500 font-mono text-xs">{elapsed}</span>
        </div>
      </div>

      {/* Unified scrollable timeline — FIX: merged log + activity feed */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto bg-zinc-950 px-3 py-2 font-mono text-xs"
        style={{ scrollBehavior: 'smooth' }}
      >
        {filtered.map((event) => (
          <div
            key={event.id}
            className="flex items-start gap-2 py-0.5 hover:bg-zinc-900/50 rounded px-1 group"
          >
            {/* Timestamp */}
            <span className="text-zinc-600 shrink-0 text-[12px] mt-0.5">{event.timestamp}</span>
            {/* Event type badge */}
            <span
              className={`text-[12px] border rounded px-1 py-0.5 shrink-0 font-bold uppercase ${eventTypeBadge[event.eventType]}`}
            >
              {event.eventType}
            </span>
            {/* Agent name colored */}
            <span className="shrink-0 font-bold text-[12px]" style={{ color: event.agentColor }}>
              {event.agentName}
            </span>
            {/* Message */}
            <span className={`${eventTypeColors[event.eventType]} flex-1`}>
              {event.message}
            </span>
            {/* Severity badge if finding */}
            {event.severity && (
              <span
                className={`text-[12px] border rounded px-1 py-0.5 shrink-0 font-bold ${severityColors[event.severity]}`}
              >
                {event.severity}
              </span>
            )}
          </div>
        ))}
        {/* Blinking cursor */}
        <div className="flex items-center gap-1 py-0.5 px-1">
          <span className="text-yellow-400 animate-pulse">▊</span>
        </div>
      </div>

      {!autoScroll && (
        <button
          onClick={() => { setAutoScroll(true); scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' }); }}
          className="absolute bottom-2 right-4 bg-zinc-700 text-zinc-300 text-[12px] font-mono px-2 py-1 rounded border border-zinc-600 hover:bg-zinc-600"
        >
          ↓ Latest
        </button>
      )}
    </div>
  );
}
