import type { PipelineStage } from '../types';

interface Props {
  stages: PipelineStage[];
}

export default function PipelineBar({ stages }: Props) {
  return (
    <div className="border-b border-zinc-700 bg-zinc-900 px-4 py-2 shrink-0">
      <div className="text-zinc-500 font-mono text-[13px] uppercase tracking-widest mb-2">Operation Pipeline</div>
      <div className="flex items-start gap-0">
        {stages.map((stage, i) => {
          const pct = stage.total > 0 ? (stage.completed / stage.total) * 100 : 0;
          const isActive = stage.active ?? (stage.completed > 0 && stage.completed < stage.total);
          const isDone = stage.completed === stage.total && stage.total > 0;
          const isCancelled = stage.cancelled === true;
          return (
            <div key={stage.name} className="flex-1 flex flex-col items-center gap-1">
              <div className="flex items-center w-full">
                {i > 0 && (
                  <div className="h-px flex-1 bg-zinc-700" />
                )}
                <div
                  className={`w-2 h-2 rounded-full border flex-shrink-0 ${
                    isCancelled
                      ? 'bg-red-500 border-red-500'
                      : isDone
                      ? 'bg-green-400 border-green-400'
                      : isActive
                      ? 'bg-yellow-400 border-yellow-400 animate-pulse'
                      : 'bg-zinc-700 border-zinc-600'
                  }`}
                />
                {i < stages.length - 1 && (
                  <div
                    className="h-px flex-1 transition-all duration-1000"
                    style={{
                      background: `linear-gradient(to right, ${isCancelled ? '#ef4444' : isDone ? '#4ade80' : isActive ? '#facc15' : '#3f3f46'} ${pct}%, #3f3f46 ${pct}%)`,
                    }}
                  />
                )}
              </div>
              <div className="text-center">
                <div className={`font-mono text-[12px] ${isCancelled ? 'text-red-400' : isDone ? 'text-green-400' : isActive ? 'text-yellow-400' : 'text-zinc-500'}`}>
                  {stage.name}
                </div>
                <div className={`font-mono text-[11px] font-bold ${isCancelled ? 'text-red-500' : isDone ? 'text-green-500' : isActive ? 'text-yellow-400 animate-pulse' : 'text-zinc-600'}`}>
                  {isCancelled ? 'CANCELLED' : isDone ? 'COMPLETED' : isActive ? 'RUNNING' : 'PENDING'}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
