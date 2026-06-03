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

      {/* Recent Discoveries — grows when Attack Graph is collapsed */}
      <div className="flex-1 min-h-0 overflow-y-auto px-3 py-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1">Recent Discoveries</div>
        {recentDiscoveries.length > 0 ? (
          recentDiscoveries.map((d, i) => (
            <div key={i} className="text-zinc-400 text-[13px] truncate">• {d}</div>
          ))
        ) : (
          <div className="text-zinc-600 text-[13px] italic">None yet</div>
        )}
      </div>

      {/* Attack Graph — no fixed height, collapses to just header */}
      <div className="border-b border-zinc-800 shrink-0">
        <AttackGraph nodes={nodes} edges={edges} />
      </div>

      {/* Findings Filter/Search */}
      <div className="border-b border-zinc-800 shrink-0">
        <div className="px-3 py-1.5">
          <div className="flex items-center gap-1 mb-1">
            <span className="text-zinc-500 text-[13px] uppercase tracking-widest">Findings</span>
            <span className="text-zinc-600 text-[11px]">({findings.length})</span>
          </div>
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

      {/* Key Findings + Export */}
      <div className="min-h-0 border-b border-zinc-800 overflow-hidden flex flex-col" style={{ maxHeight: '160px' }}>
        <KeyFindings findings={findings} onExport={onExport} />
      </div>

      {/* Session Metrics — FIX: show real data, hide zeros for commands/data */}
      <div className="px-3 py-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1">Session Metrics</div>
        <div className="space-y-0.5">
          {/* FIX: Hide zeros for commands/data if not yet collected */}
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
