import { useEffect } from 'react';
import type { Toast } from '../types';

interface Props {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

const severityConfig = {
  CRITICAL: { bg: 'bg-red-900 border-red-500', icon: '🚨', label: 'CRITICAL' },
  HIGH: { bg: 'bg-orange-900 border-orange-500', icon: '⚠️', label: 'HIGH' },
  MEDIUM: { bg: 'bg-yellow-900 border-yellow-500', icon: '⚡', label: 'MEDIUM' },
  LOW: { bg: 'bg-blue-900 border-blue-500', icon: 'ℹ️', label: 'LOW' },
  INFO: { bg: 'bg-zinc-800 border-zinc-600', icon: '📋', label: 'INFO' },
};

export default function ToastNotification({ toasts, onDismiss }: Props) {
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 w-80">
      {toasts.map((toast) => {
        const cfg = severityConfig[toast.severity];
        return (
          <ToastItem key={toast.id} toast={toast} cfg={cfg} onDismiss={onDismiss} />
        );
      })}
    </div>
  );
}

function ToastItem({
  toast,
  cfg,
  onDismiss,
}: {
  toast: Toast;
  cfg: (typeof severityConfig)[keyof typeof severityConfig];
  onDismiss: (id: string) => void;
}) {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss(toast.id), 5000);
    return () => clearTimeout(timer);
  }, [toast.id, onDismiss]);

  return (
    <div
      className={`${cfg.bg} border rounded px-3 py-2 flex items-start gap-2 shadow-lg animate-pulse-once`}
      style={{ animation: 'slideInRight 0.3s ease-out' }}
    >
      <span className="text-lg flex-shrink-0">{cfg.icon}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-xs font-bold text-white font-mono">{cfg.label} FINDING</span>
          <span className="text-xs text-zinc-400 font-mono">{toast.agent}</span>
        </div>
        <p className="text-xs text-zinc-200 font-mono truncate">{toast.message}</p>
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        className="text-zinc-400 hover:text-white text-xs flex-shrink-0 ml-1"
      >
        ✕
      </button>
    </div>
  );
}
