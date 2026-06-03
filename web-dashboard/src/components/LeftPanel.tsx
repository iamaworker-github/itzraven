import type { Agent } from '../types';

interface Props {
  agents: Agent[];
  cpu: number;
  mem: number;
  net: number;
  tokens: number;
  credits: number;
  elapsed: string;
  llmModel: string;
  riskProfile: string;
  maxParallel: string;
  safeMode: boolean;
  agentStatus: string;
  onPause: (id: string) => void;
  onResume: (id: string) => void;
  onKill: (id: string) => void;
}

const statusColors: Record<string, string> = {
  Done: 'text-cyan-400',
  Running: 'text-green-400',
  Idle: 'text-zinc-500',
  Paused: 'text-yellow-400',
  Killed: 'text-red-500',
  Cancelled: 'text-red-500',
  CANCELLED: 'text-red-500',
};

const statusDot: Record<string, string> = {
  Done: 'bg-cyan-400',
  Running: 'bg-green-400',
  Idle: 'bg-zinc-600',
  Paused: 'bg-yellow-400',
  Killed: 'bg-red-500',
  Cancelled: 'bg-red-500',
  CANCELLED: 'bg-red-500',
};

function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex-1 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full ${color}`}
        style={{ width: `${value}%`, transition: 'width 1s ease' }}
      />
    </div>
  );
}

export default function LeftPanel({ agents, cpu, mem, net, tokens, credits, elapsed, llmModel, riskProfile, maxParallel, safeMode, agentStatus, onPause, onResume, onKill }: Props) {
  const runningCount = agents.filter(a => a.status === 'Running').length;
  const totalCount = agents.length;

  const statusColor: Record<string, string> = {
    IDLE: 'text-zinc-500', PLANNING: 'text-yellow-400', EXECUTING: 'text-green-400', ERROR: 'text-red-500',
  };

  return (
    <div className="w-56 shrink-0 border-r border-zinc-700 bg-zinc-950 flex flex-col overflow-y-auto text-xs font-mono">
      {/* Status */}
      <div className="p-2 border-b border-zinc-800">
        <div className="text-zinc-500 uppercase text-[13px] tracking-widest mb-1">Status</div>
        <div className={`font-bold tracking-widest text-[13px] ${statusColor[agentStatus] || 'text-zinc-500'}`}>{agentStatus}</div>
        <div className="text-zinc-500 mt-1 text-[13px]">MODE</div>
        <div className="text-zinc-300 text-[12px]">PENTEST</div>
      </div>

      {/* Risk Profile */}
      <div className="p-2 border-b border-zinc-800 space-y-1">
        <div className="flex justify-between items-center">
          <span className="text-zinc-500 text-[13px]">Risk Profile</span>
          <span className="text-zinc-300 text-[13px]">{riskProfile}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-zinc-500 text-[13px]">Max Parallel</span>
          <span className="text-zinc-300 text-[13px]">{maxParallel}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-zinc-500 text-[13px]">Safe Mode</span>
          <span className={`text-[13px] font-bold ${safeMode ? 'text-green-400' : 'text-red-400'}`}>{safeMode ? 'ON' : 'OFF'}</span>
        </div>
      </div>

      {/* Agents */}
      <div className="p-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1">
          Agents [{runningCount}/{totalCount}]
        </div>
        <div className="flex flex-col gap-1">
          {agents.map((agent) => (
            <div key={agent.id} className="group">
              <div className="flex items-center gap-1">
                <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${statusDot[agent.status]} ${agent.status === 'Running' ? 'animate-pulse' : ''}`} />
                <span className={`text-[13px] truncate flex-1 ${statusColors[agent.status]}`}>
                  {agent.name}
                </span>
                <span className={`text-[12px] font-bold ${statusColors[agent.status]}`}>
                  {agent.status === 'Done' ? '✓' : agent.status === 'Running' ? '▶' : agent.status === 'Paused' ? '⏸' : agent.status === 'Killed' || agent.status === 'Cancelled' ? '✕' : '○'}
                </span>
              </div>
              {/* FIX: Pause/Kill controls per agent */}
              {(agent.status === 'Running' || agent.status === 'Paused') && (
                <div className="flex gap-1 mt-0.5 pl-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  {agent.status === 'Running' && (
                    <button
                      onClick={() => onPause(agent.id)}
                      className="text-[12px] text-yellow-400 hover:text-yellow-300 border border-yellow-700 hover:border-yellow-400 px-1 rounded"
                    >
                      ⏸ Pause
                    </button>
                  )}
                  {agent.status === 'Paused' && (
                    <button
                      onClick={() => onResume(agent.id)}
                      className="text-[12px] text-green-400 hover:text-green-300 border border-green-700 hover:border-green-400 px-1 rounded"
                    >
                      ▶ Resume
                    </button>
                  )}
                  <button
                    onClick={() => onKill(agent.id)}
                    className="text-[12px] text-red-400 hover:text-red-300 border border-red-800 hover:border-red-500 px-1 rounded"
                  >
                    ✕ Kill
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>



      {/* System Health */}
      <div className="p-2 border-b border-zinc-800">
        <div className="text-zinc-500 text-[13px] uppercase tracking-widest mb-1.5">System Health</div>
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1">
            <span className="text-zinc-400 text-[13px] w-6">CPU</span>
            <Bar value={cpu} color="bg-green-500" />
            <span className="text-zinc-400 text-[13px] w-5 text-right">{cpu}%</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="text-zinc-400 text-[13px] w-6">MEM</span>
            <Bar value={mem} color="bg-yellow-500" />
            <span className="text-zinc-400 text-[13px] w-5 text-right">{mem}%</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="text-zinc-400 text-[13px] w-6">NET</span>
            <Bar value={net} color="bg-cyan-500" />
            <span className="text-zinc-400 text-[13px] w-5 text-right">{net}%</span>
          </div>
        </div>
      </div>

      {/* Tokens / Credits */}
      <div className="p-2">
        <div className="flex justify-between text-[13px] mb-0.5">
          <span className="text-zinc-500">TOKENS</span>
          <span className="text-zinc-300">{(tokens / 1000).toFixed(1)}M / 2M</span>
        </div>
        <div className="w-full h-1 bg-zinc-700 rounded overflow-hidden mb-2">
          <div className="h-full bg-purple-500 rounded" style={{ width: `${(tokens / 2000) * 100}%` }} />
        </div>
        <div className="flex justify-between text-[13px] mb-0.5">
          <span className="text-zinc-500">CREDITS</span>
          <span className="text-zinc-300">{credits.toLocaleString()}</span>
        </div>
        <div className="flex justify-between text-[13px]">
          <span className="text-zinc-500">UPTIME</span>
          <span className="text-zinc-300">{elapsed}</span>
        </div>
        <div className="flex justify-between text-[13px] mt-1">
          <span className="text-zinc-500">AI</span>
          <span className={`${llmModel && llmModel !== 'AI OFF' ? 'text-green-400' : 'text-red-400'} text-[13px]`}>
            {llmModel && llmModel !== 'AI OFF' ? 'On' : 'Off'}
          </span>
        </div>
        <div className="flex justify-between text-[13px]">
          <span className="text-zinc-500">Model</span>
          <span className="text-zinc-300 text-[13px] truncate max-w-[120px] text-right">
            {llmModel && llmModel !== 'AI OFF' ? llmModel : '-'}
          </span>
        </div>
      </div>
    </div>
  );
}
