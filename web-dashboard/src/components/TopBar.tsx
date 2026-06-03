import { useState, useEffect } from 'react';

interface Props {
  elapsed: string;
  target: string;
  depth: string;
  incremental: boolean;
  isScanRunning: boolean;
  onStopScan: () => void;
  onNewScan: () => void;
}

export default function TopBar({ elapsed, target, depth, incremental, isScanRunning, onStopScan, onNewScan }: Props) {
  const [hasCp, setHasCp] = useState(false);
  const [health, setHealth] = useState<{cpu_percent: number; memory_percent: number; disk_free_gb: number} | null>(null);

  useEffect(() => {
    fetch('/api/checkpoint').then(r => r.json()).then(d => setHasCp(d.status === 'found')).catch(() => {});
    fetch('/api/health').then(r => r.json()).then(d => setHealth(d)).catch(() => {});
  }, []);

  return (
    <div className="flex items-center justify-between px-3 py-1 border-b border-zinc-700 bg-zinc-950 shrink-0">
      <div className="flex items-center gap-3">
        <span className="text-yellow-400 font-bold font-mono text-sm tracking-widest">ITZRAVEN</span>
        <span className="text-zinc-600 font-mono text-xs">v0.0.1</span>
        <span className="text-zinc-600 font-mono text-xs">|</span>
        <span className="text-zinc-400 font-mono text-xs tracking-widest">AUTONOMOUS AI CYBERSECURITY AGENT</span>
        {health && (
          <span className="text-zinc-600 text-[10px]">
            CPU:{health.cpu_percent}% MEM:{health.memory_percent}% DISK:{health.disk_free_gb}G
          </span>
        )}
      </div>
      <div className="flex items-center gap-4 font-mono text-xs">
        <span className="text-zinc-500">TARGET: <span className="text-green-400">{target || '—'}</span></span>
        <span className="text-zinc-500">TIME: <span className="text-white">{elapsed}</span></span>
        <span className="text-zinc-500">DEPTH: <span className="text-purple-400">{depth}</span></span>
        {incremental && <span className="text-amber-400 font-bold text-[10px] border border-amber-700 px-1 rounded">DIFF</span>}
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-green-400 font-bold">LIVE</span>
        </div>
        {hasCp && <button onClick={() => fetch('/api/scan/resume', { method: 'POST' }).catch(() => {})} className="text-[11px] font-mono text-amber-400 hover:text-amber-300 border border-amber-800 hover:border-amber-600 px-1.5 py-0.5 rounded transition-colors">Resume</button>}
        {isScanRunning && <button onClick={onStopScan} className="text-[11px] font-mono text-red-400 hover:text-red-300 border border-red-800 hover:border-red-600 px-1.5 py-0.5 rounded transition-colors">Stop</button>}
        <button onClick={onNewScan} className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 border border-cyan-800 hover:border-cyan-600 px-1.5 py-0.5 rounded transition-colors">New Scan</button>
      </div>
    </div>
  );
}
