import { useState } from 'react';
import type { Finding, Severity } from '../types';

interface Props {
  findings: Finding[];
  onExport: () => void;
}

const severityColors: Record<Severity, string> = {
  CRITICAL: 'text-red-400 border-red-700',
  HIGH: 'text-orange-400 border-orange-700',
  MEDIUM: 'text-yellow-400 border-yellow-700',
  LOW: 'text-blue-400 border-blue-700',
  INFO: 'text-zinc-400 border-zinc-700',
};

const severityDot: Record<Severity, string> = {
  CRITICAL: 'bg-red-400',
  HIGH: 'bg-orange-400',
  MEDIUM: 'bg-yellow-400',
  LOW: 'bg-blue-400',
  INFO: 'bg-zinc-400',
};

export default function KeyFindings({ findings, onExport }: Props) {
  const [sortBy, setSortBy] = useState<'severity' | 'title'>('severity');
  const sorted = [...findings].sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return sortBy === 'severity'
      ? (order[a.severity] ?? 99) - (order[b.severity] ?? 99)
      : a.title.localeCompare(b.title);
  });

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-700 shrink-0">
        <span className="text-zinc-400 font-mono text-[12px] font-bold uppercase tracking-widest">Key Findings</span>
        <div className="flex items-center gap-1">
          <button onClick={() => setSortBy(sortBy === 'severity' ? 'title' : 'severity')} className="text-[10px] text-zinc-500 hover:text-zinc-300 border border-zinc-700 px-1 py-0.5 rounded">{sortBy === 'severity' ? 'Severity ▼' : 'Title ▼'}</button>
          <button onClick={() => window.open('/api/report/html', '_blank')} className="text-[10px] text-amber-400 hover:text-amber-300 border border-amber-800 px-1 py-0.5 rounded">HTML</button>
          <button onClick={() => window.open('/api/report/json', '_blank')} className="text-[10px] text-cyan-400 hover:text-cyan-300 border border-cyan-800 px-1 py-0.5 rounded">JSON</button>
          <button onClick={onExport} className="text-[10px] font-bold text-cyan-400 border border-cyan-700 hover:bg-cyan-900/30 px-1 py-0.5 rounded transition-colors">↑</button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-1">
        {sorted.length === 0 ? (
          <div className="text-zinc-600 font-mono text-[12px] italic p-2">No findings yet...</div>
        ) : (
          sorted.map((finding) => (
            <div key={finding.id} className="finding-row flex items-start gap-2 py-1 border-b border-zinc-900 hover:bg-zinc-900/30">
              <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1 ${severityDot[finding.severity]}`} />
              <div className="flex-1 min-w-0">
                <div className="text-zinc-300 font-mono text-[13px] leading-relaxed">{finding.title}</div>
                <div className="text-zinc-600 font-mono text-[12px]">{finding.agent}</div>
              </div>
              <span className={`text-[13px] font-bold font-mono border rounded px-1 py-0.5 shrink-0 ${severityColors[finding.severity]}`}>
                {finding.severity}
              </span>
            </div>
          ))
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-1">
        {findings.length === 0 ? (
          <div className="text-zinc-600 font-mono text-[12px] italic p-2">No findings yet...</div>
        ) : (
          findings.map((finding) => (
            <div key={finding.id} className="flex items-start gap-2 py-1 border-b border-zinc-900 hover:bg-zinc-900/30">
              <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1 ${severityDot[finding.severity]}`} />
              <div className="flex-1 min-w-0">
                <div className="text-zinc-300 font-mono text-[13px] leading-relaxed">{finding.title}</div>
                <div className="text-zinc-600 font-mono text-[12px]">{finding.agent}</div>
              </div>
              <span className={`text-[13px] font-bold font-mono border rounded px-1 py-0.5 shrink-0 ${severityColors[finding.severity]}`}>
                {finding.severity}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
