import { useState, useEffect, useRef } from 'react';

interface Props {
  agentName: string;
  thought: string | null;
  lastThought: string | null;
  tokens: string;
  thinkingLines?: string[];
}

export default function ThinkingPanel({ agentName, thought, lastThought, tokens, thinkingLines = [] }: Props) {
  const [isCollapsed, setIsCollapsed] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (thinkingLines.length > 0 || (thought && thought.length > 50)) {
      setIsCollapsed(false);
    }
  }, [thinkingLines, thought]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [thinkingLines, thought]);

  const isEmpty = !thought && thinkingLines.length === 0;

  return (
    <div className={`${isCollapsed ? 'shrink-0' : 'flex-1'} flex flex-col min-h-0 border-t border-zinc-700 bg-zinc-950`}>
      <div
        className="flex items-center justify-between px-3 py-1 border-b border-zinc-800 cursor-pointer hover:bg-zinc-900 shrink-0"
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-purple-500" />
          <span className="text-purple-400 font-mono text-[12px] font-bold uppercase tracking-widest">
            THINKING — {agentName}
          </span>
          {isEmpty && (
            <span className="text-[13px] text-zinc-600 font-mono italic">
              {lastThought ? '(last thought)' : '(idle)'}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {!isEmpty && (
            <span className="text-zinc-600 font-mono text-[13px]">TOKENS: {tokens}</span>
          )}
          <span className="text-zinc-500 text-[12px] font-mono">{isCollapsed ? '▶' : '▼'}</span>
        </div>
      </div>

      {!isCollapsed && (
        <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto px-3 py-2">
          {thinkingLines.length > 0 ? (
            thinkingLines.map((line, i) => (
              <p key={i} className="text-zinc-300 font-mono text-[12px] leading-relaxed">{line}</p>
            ))
          ) : thought ? (
            <p className="text-zinc-300 font-mono text-[12px] leading-relaxed">{thought}</p>
          ) : lastThought ? (
            <p className="text-zinc-600 font-mono text-[12px] leading-relaxed italic">
              Last: {lastThought}
            </p>
          ) : (
            <p className="text-zinc-700 font-mono text-[12px] italic">—</p>
          )}
        </div>
      )}
    </div>
  );
}
