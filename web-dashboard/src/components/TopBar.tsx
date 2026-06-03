import { useState, useEffect } from 'react';

interface Props {
  elapsed: string;
  sessionId: string;
  target: string;
  depth: string;
  incremental: boolean;
  onStopScan: () => void;
  onNewScan: () => void;
  onResumeScan: () => void;
}

export default function TopBar({ elapsed, sessionId, target, depth, incremental, onStopScan, onNewScan, onResumeScan }: Props) {
  const [scans, setScans] = useState<{session_id: string; target: string; timestamp: string}[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [showSchedule, setShowSchedule] = useState(false);
  const [schedules, setSchedules] = useState<{id: string; target: string; interval_hours: number; active: boolean}[]>([]);
  const [schedTarget, setSchedTarget] = useState('');
  const [schedInterval, setSchedInterval] = useState(24);
  const [hasCp, setHasCp] = useState(false);
  const [health, setHealth] = useState<{cpu_percent: number; memory_percent: number; disk_free_gb: number} | null>(null);

  useEffect(() => {
    fetch('/api/scans').then(r => r.json()).then(d => setScans(d.scans || [])).catch(() => {});
    fetch('/api/checkpoint').then(r => r.json()).then(d => setHasCp(d.status === 'found')).catch(() => {});
    fetch('/api/schedule').then(r => r.json()).then(d => setSchedules(d.schedules || [])).catch(() => {});
    fetch('/api/health').then(r => r.json()).then(d => setHealth(d)).catch(() => {});
  }, [sessionId]);

  const addSchedule = () => {
    if (!schedTarget) return;
    fetch('/api/schedule', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({target: schedTarget, interval_hours: schedInterval}) })
      .then(r => r.json()).then(d => { setSchedules(prev => [...prev, d.job]); setShowSchedule(false); }).catch(() => {});
  };

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
        <span className="text-zinc-500">SESSION: <span className="text-cyan-400">{sessionId || '—'}</span></span>
        <span className="text-zinc-500">TIME: <span className="text-white">{elapsed}</span></span>
        <span className="text-zinc-500">DEPTH: <span className="text-purple-400">{depth}</span></span>
        {incremental && <span className="text-amber-400 font-bold text-[10px] border border-amber-700 px-1 rounded">DIFF</span>}
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-green-400 font-bold">LIVE</span>
        </div>
        {hasCp && <button onClick={onResumeScan} className="text-[11px] font-mono text-amber-400 hover:text-amber-300 border border-amber-800 hover:border-amber-600 px-1.5 py-0.5 rounded transition-colors">Resume</button>}

        {/* Schedule button */}
        <div className="relative">
          <button onClick={() => setShowSchedule(!showSchedule)} className="text-[11px] font-mono text-purple-400 hover:text-purple-300 border border-purple-800 hover:border-purple-600 px-1.5 py-0.5 rounded transition-colors">Schedule</button>
          {showSchedule && (
            <div className="absolute right-0 top-6 w-72 bg-zinc-900 border border-zinc-700 rounded shadow-xl z-50 p-3">
              <div className="text-zinc-400 text-[11px] font-mono mb-2">Schedule Recurring Scan</div>
              <input type="text" value={schedTarget} onChange={e => setSchedTarget(e.target.value)} placeholder="target.com" className="w-full bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-[12px] text-zinc-300 mb-1 outline-none" />
              <div className="flex gap-1 mb-2">
                <input type="number" value={schedInterval} onChange={e => setSchedInterval(Number(e.target.value))} min={1} max={168} className="w-16 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-[12px] text-zinc-300 outline-none" />
                <span className="text-zinc-500 text-[12px] py-1">hours</span>
              </div>
              <button onClick={addSchedule} className="w-full text-[11px] font-mono text-purple-400 border border-purple-700 hover:bg-purple-900/30 px-2 py-1 rounded">Add Schedule</button>
              {schedules.length > 0 && (
                <div className="mt-2 max-h-24 overflow-y-auto">
                  {schedules.map(s => (
                    <div key={s.id} className="flex justify-between text-[11px] text-zinc-400 py-0.5">
                      <span>{s.target}</span>
                      <span>{s.interval_hours}h {s.active ? '🟢' : '🔴'}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="relative">
          <button onClick={() => setShowHistory(!showHistory)} className="text-[11px] font-mono text-zinc-400 hover:text-zinc-200 border border-zinc-700 hover:border-zinc-500 px-1.5 py-0.5 rounded transition-colors">History</button>
          {showHistory && (
            <div className="absolute right-0 top-6 w-72 bg-zinc-900 border border-zinc-700 rounded shadow-xl z-50 max-h-56 overflow-y-auto">
              <div className="text-zinc-400 text-[11px] font-mono px-2 py-1 border-b border-zinc-700 flex justify-between">
                <span>Past Scans</span>
                {scans.length >= 2 && (
                  <button onClick={() => { const ids = scans.map(s => s.session_id).slice(0,2); window.open(`/api/findings/diff/${ids[0]}/${ids[1]}`, '_blank'); }} className="text-amber-400 hover:text-amber-300">Diff Last 2</button>
                )}
              </div>
              {scans.length === 0 && <div className="text-zinc-600 text-[11px] font-mono px-2 py-2">No scans yet</div>}
              {scans.map(s => (
                <div key={s.session_id} onClick={() => { fetch(`/api/scans/${s.session_id}`); setShowHistory(false); }} className="px-2 py-1 hover:bg-zinc-800 cursor-pointer border-b border-zinc-800 text-[11px]">
                  <div className="text-zinc-300">{s.target || 'unknown'}</div>
                  <div className="text-zinc-600 text-[10px]">{s.session_id} · {s.timestamp || ''}</div>
                </div>
              ))}
            </div>
          )}
        </div>
        <button onClick={onStopScan} className="text-[11px] font-mono text-red-400 hover:text-red-300 border border-red-800 hover:border-red-600 px-1.5 py-0.5 rounded transition-colors">Stop</button>
        <button onClick={onNewScan} className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 border border-cyan-800 hover:border-cyan-600 px-1.5 py-0.5 rounded transition-colors">New Scan</button>
      </div>
    </div>
  );
}
