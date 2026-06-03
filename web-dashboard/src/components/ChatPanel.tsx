import { useState, useRef, useEffect } from 'react';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  text: string;
  timestamp: string;
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export default function ChatPanel({ isOpen, onClose }: Props) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/chat')
        .then(r => r.json())
        .then(data => {
          if (data.messages?.length) {
            setMessages(data.messages.map((m: any) => ({
              id: m.id || crypto.randomUUID(),
              role: m.role || 'system',
              text: m.text || m.message || '',
              timestamp: m.timestamp || new Date().toLocaleTimeString(),
            })));
          } else {
            setMessages([{
              id: 'welcome',
              role: 'system',
              text: 'Itzraven AI cockpit ready. Ask me anything about the current scan or give me instructions.',
              timestamp: new Date().toLocaleTimeString(),
            }]);
          }
        })
        .catch(() => {
          setMessages([{ id: 'welcome', role: 'system', text: 'Chat ready.', timestamp: new Date().toLocaleTimeString() }]);
        });
    }
  }, [isOpen]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg: ChatMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      text: input.trim(),
      timestamp: new Date().toLocaleTimeString(),
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg.text }),
      });
      const data = await res.json();
      const reply: ChatMessage = {
        id: crypto.randomUUID(),
        role: 'assistant',
        text: data.reply || 'No response',
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages(prev => [...prev, reply]);
    } catch {
      setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'assistant', text: 'Connection error', timestamp: new Date().toLocaleTimeString() }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') sendMessage();
  };

  if (!isOpen) return null;

  return (
    <div className="absolute bottom-0 right-0 w-96 h-80 bg-zinc-900 border border-zinc-700 rounded-tl-lg flex flex-col shadow-2xl z-50" style={{ animation: 'slideInRight 0.2s ease-out' }}>
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-700 bg-zinc-800 rounded-tl-lg">
        <span className="text-xs font-mono text-zinc-400">AI Chat</span>
        <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300 text-xs">&times;</button>
      </div>
      <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
        {messages.map(m => (
          <div key={m.id} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[85%] rounded px-2 py-1 text-xs font-mono ${
              m.role === 'user' ? 'bg-blue-900/50 text-blue-200 border border-blue-800' :
              m.role === 'assistant' ? 'bg-zinc-800 text-zinc-300 border border-zinc-700' :
              'bg-zinc-800/50 text-zinc-400 border border-zinc-700/50'
            }`}>
              <div>{m.text}</div>
              <div className="text-[10px] text-zinc-600 mt-0.5">{m.timestamp}</div>
            </div>
          </div>
        ))}
        {loading && <div className="text-xs text-zinc-500 font-mono px-2">Thinking...</div>}
        <div ref={bottomRef} />
      </div>
      <div className="flex items-center border-t border-zinc-700 px-2 py-1.5">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask AI..."
          className="flex-1 bg-transparent text-zinc-300 font-mono text-xs outline-none placeholder-zinc-700"
        />
        <button onClick={sendMessage} disabled={loading} className="text-zinc-400 hover:text-zinc-200 text-xs ml-2 disabled:opacity-50">
          Send
        </button>
      </div>
    </div>
  );
}
