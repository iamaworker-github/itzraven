import { useState } from 'react';
import type { Finding } from '../types';
import KeyFindings from './KeyFindings';
import AttackGraph from './AttackGraph';
import type { GraphNode, GraphEdge } from '../types';

interface SessionMetrics {
  commandsExecuted: number;
  dataCollected: number;
  findings: number;
  vulnerabilities: number;
  timeElapsed: string;
}

interface Props {
  target: string;
  mode: string;
  ipAddress: string;
  openPorts: number;
  subdomains: number;
  technologies: number;
  attackSurface: string;
  topTech: string[];
  recentDiscoveries: string[];
  findings: Finding[];
  metrics: SessionMetrics;
  riskScore: number;
  riskLevel: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  onExport: () => void;
}

const AI_AGENT_KEYWORDS = ['analysis', 'llm', 'report', 'gpt', 'claude', 'gemini', 'deepseek'];

function isAiFinding(f: Finding): boolean {
  const agent = (f.agent || '').toLowerCase();
  return AI_AGENT_KEYWORDS.some(kw => agent.includes(kw));
}

function CollapsibleSection({ title, count, children, defaultCollapsed = true }: { title: string; count?: number; children: React.ReactNode; defaultCollapsed?: boolean }) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  return (
    <div className="flex flex-col">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-700 shrink-0 cursor-pointer hover:bg-zinc-900" onClick={() => setCollapsed(!collapsed)}>
        <span className="text-zinc-400 font-mono text-[12px] font-bold uppercase tracking-widest">
          {title}{count !== undefined ? ` (${count})` : ''}
        </span>
        <span className="text-zinc-500 text-[12px] font-mono">{collapsed ? '▶' : '▼'}</span>
      </div>
      {!collapsed && <div className="overflow-y-auto">{children}</div>}
    </div>
  );
}

const severityColors: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-700',
  HIGH: 'text-orange-400 border-orange-700',
  MEDIUM: 'text-yellow-400 border-yellow-700',
  LOW: 'text-blue-400 border-blue-700',
  INFO: 'text-zinc-400 border-zinc-700',
};

const severityDot: Record<string, string> = {
  CRITICAL: 'bg-red-400',
  HIGH: 'bg-orange-400',
  MEDIUM: 'bg-yellow-400',
  LOW: 'bg-blue-400',
  INFO: 'bg-zinc-400',
};

export default function RightPanel({
  target,
  mode,
  ipAddress,
  openPorts,
  subdomains,
  technologies,
  attackSurface,
  topTech,
  recentDiscoveries,
  findings,
  metrics,
  riskScore,
  riskLevel,
  nodes,
  edges,
  onExport,
}: Props) {
  const aiFindings = findings.filter(isAiFinding);
  const nonAiFindings = findings.filter(f => !isAiFinding(f));

  return (
    <div className="w-72 shrink-0 border-l border-zinc-700 bg-zinc-950 flex flex-col overflow-hidden text-xs font-mono">
      {/* Target Overview */}
      <div className="px-3 py-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1.5">Target Overview</div>
        <div className="space-y-0.5">
          <Row label="Primary Target" value={target} valueClass="text-green-400" />
          <Row label="IP Address" value={ipAddress || '—'} />
          <Row label="Open Ports" value={openPorts > 0 ? String(openPorts) : '0'} valueClass={openPorts > 0 ? 'text-yellow-400' : 'text-zinc-600'} />
          {mode !== 'PENTEST' && <Row label="Subdomains" value={String(subdomains)} valueClass={subdomains > 0 ? 'text-cyan-400' : 'text-zinc-600'} />}
          <Row label="Technologies" value={String(technologies)} valueClass={technologies > 0 ? 'text-purple-400' : 'text-zinc-600'} />
          <Row label="Attack Surface" value={attackSurface || 'Unknown'} valueClass="text-orange-400" />
        </div>
      </div>

      {/* Top Technologies */}
      <div className="px-3 py-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1">Top Technologies</div>
        {topTech.length > 0 ? (
          topTech.map((t) => (
            <div key={t} className="text-zinc-400 text-[13px]">{t}</div>
          ))
        ) : (
          <div className="text-zinc-600 text-[13px] italic">No technologies detected</div>
        )}
      </div>

      {/* AI Findings — collapsible, collapsed by default */}
      <CollapsibleSection title="AI Findings" count={aiFindings.length}>
        {aiFindings.length > 0 ? (
          aiFindings.map((f) => (
            <div key={f.id} className="flex items-start gap-2 px-3 py-1 border-b border-zinc-900 hover:bg-zinc-900/30">
              <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1 ${severityDot[f.severity]}`} />
              <div className="flex-1 min-w-0">
                <div className="text-zinc-300 font-mono text-[13px] leading-relaxed">{f.title}</div>
                <div className="text-zinc-600 font-mono text-[12px]">{f.agent}</div>
              </div>
              <span className={`text-[13px] font-bold font-mono border rounded px-1 py-0.5 shrink-0 ${severityColors[f.severity]}`}>
                {f.severity}
              </span>
            </div>
          ))
        ) : (
          <div className="text-zinc-600 font-mono text-[12px] italic px-3 py-2">No AI findings yet...</div>
        )}
      </CollapsibleSection>

      {/* Attack Graph */}
      <div className="border-b border-zinc-800 shrink-0">
        <AttackGraph nodes={nodes} edges={edges} />
      </div>

      {/* Findings — collapsible, collapsed by default */}
      <CollapsibleSection title="Findings" count={nonAiFindings.length}>
        {nonAiFindings.length > 0 ? (
          nonAiFindings.map((f) => (
            <div key={f.id} className="flex items-start gap-2 px-3 py-1 border-b border-zinc-900 hover:bg-zinc-900/30">
              <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1 ${severityDot[f.severity]}`} />
              <div className="flex-1 min-w-0">
                <div className="text-zinc-300 font-mono text-[13px] leading-relaxed">{f.title}</div>
                <div className="text-zinc-600 font-mono text-[12px]">{f.agent}</div>
              </div>
              <span className={`text-[13px] font-bold font-mono border rounded px-1 py-0.5 shrink-0 ${severityColors[f.severity]}`}>
                {f.severity}
              </span>
            </div>
          ))
        ) : (
          <div className="text-zinc-600 font-mono text-[12px] italic px-3 py-2">No findings yet...</div>
        )}
      </CollapsibleSection>

      {/* Findings Search */}
      <div className="border-b border-zinc-800 shrink-0">
        <div className="px-3 py-1.5">
          <input
            id="findings-search"
            type="text"
            placeholder="Search findings..."
            onChange={(e) => {
              const q = e.target.value.toLowerCase();
              document.querySelectorAll<HTMLElement>('.finding-row').forEach(el => {
                el.style.display = el.textContent?.toLowerCase().includes(q) ? '' : 'none';
              });
            }}
            className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-[11px] text-zinc-300 placeholder-zinc-600 outline-none"
          />
        </div>
      </div>

      {/* Session Metrics */}
      <div className="px-3 py-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1">Session Metrics</div>
        <div className="space-y-0.5">
          <MetricRow
            label="Commands Executed"
            value={metrics.commandsExecuted > 0 ? String(metrics.commandsExecuted) : '—'}
            valueClass={metrics.commandsExecuted > 0 ? 'text-zinc-300' : 'text-zinc-700'}
          />
          <MetricRow
            label="Data Collected"
            value={metrics.dataCollected > 0 ? `${metrics.dataCollected} MB` : '—'}
            valueClass={metrics.dataCollected > 0 ? 'text-zinc-300' : 'text-zinc-700'}
          />
          <MetricRow
            label="Findings"
            value={String(metrics.findings)}
            valueClass={metrics.findings > 0 ? 'text-yellow-400' : 'text-zinc-600'}
          />
          <MetricRow
            label="Vulnerabilities"
            value={String(metrics.vulnerabilities)}
            valueClass={metrics.vulnerabilities > 0 ? 'text-red-400' : 'text-zinc-600'}
          />
          <MetricRow label="Time Elapsed" value={metrics.timeElapsed} valueClass="text-zinc-300" />
        </div>
      </div>

      {/* Risk Score */}
      <div className="px-3 py-2">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1">Risk Score</div>
        <div className="text-2xl font-bold text-yellow-400">{riskScore.toFixed(1)}</div>
        <div className="text-zinc-500 text-[13px]">{riskLevel}</div>
        <div className="flex gap-0.5 mt-1">
          {Array.from({ length: 12 }).map((_, i) => (
            <div
              key={i}
              className="flex-1 h-1 rounded-sm"
              style={{
                backgroundColor: i < Math.round(riskScore / 10) ? '#facc15' : '#27272a',
              }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function Row({ label, value, valueClass = 'text-zinc-400' }: { label: string; value: string; valueClass?: string }) {
  return (
    <div className="flex justify-between items-center gap-1">
      <span className="text-zinc-600 text-[12px]">{label}</span>
      <span className={`text-[12px] font-bold ${valueClass} text-right break-all`}>{value}</span>
    </div>
  );
}

function MetricRow({ label, value, valueClass = 'text-zinc-400' }: { label: string; value: string; valueClass?: string }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-zinc-600 text-[12px]">{label}</span>
      <span className={`text-[13px] font-bold ${valueClass}`}>{value}</span>
    </div>
  );
}
