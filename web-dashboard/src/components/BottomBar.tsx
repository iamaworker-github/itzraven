import { useState } from 'react';

interface Props {
  onCommand: (cmd: string) => void;
  onClearChat: () => void;
  scanMode: string;
  onScanModeChange: (mode: string) => void;
  shortcuts?: string[];
}

const MODES = ['pentest', 'osint', 'bugbounty', 'ctf', 'api-pentest'];

export default function BottomBar({ onCommand, onClearChat, scanMode, onScanModeChange, shortcuts = [] }: Props) {
  const [input, setInput] = useState('');
  const [showModes, setShowModes] = useState(false);

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && input.trim()) {
      onCommand(input.trim());
      setInput('');
    }
  };

  return (
    <div className="flex items-center border-t border-zinc-700 bg-zinc-900 shrink-0">
      {/* Mode selector */}
      <div className="relative">
        <button onClick={() => setShowModes(!showModes)} className="text-[11px] font-mono text-yellow-400 hover:text-yellow-300 border border-yellow-700 hover:border-yellow-500 px-1.5 py-1 mx-1 rounded transition-colors uppercase">{scanMode}</button>
        {showModes && (
          <div className="absolute bottom-8 left-0 bg-zinc-900 border border-zinc-700 rounded shadow-xl z-50">
            {MODES.map(m => (
              <button key={m} onClick={() => { onScanModeChange(m); setShowModes(false); }} className={`block w-full text-left px-3 py-1 text-[12px] font-mono hover:bg-zinc-800 ${m === scanMode ? 'text-yellow-400' : 'text-zinc-400'}`}>{m}</button>
            ))}
          </div>
        )}
      </div>

      {/* Input */}
      <div className="flex-1 flex items-center">
        <span className="text-green-400 font-mono text-xs px-2">$</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Type command or ask AI..."
          className="flex-1 bg-transparent text-zinc-300 font-mono text-xs outline-none placeholder-zinc-700 py-2"
        />
      </div>

      {/* Right: action buttons */}
      <div className="flex items-center gap-1 px-2 py-1.5 border-l border-zinc-700">
        <button onClick={onClearChat} className="text-[11px] font-mono text-red-500 hover:text-red-400 border border-zinc-700 hover:border-red-500 px-1.5 py-0.5 rounded transition-colors">Clear</button>
        {shortcuts.map((label) => (
          <span key={label} className="text-[10px] font-mono text-zinc-600 px-1">{label}</span>
        ))}
      </div>
    </div>
  );
}
