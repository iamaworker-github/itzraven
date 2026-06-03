import { useState, useCallback, useEffect } from 'react';
import type { Toast } from './types';

import { useBackend } from './hooks/useBackend';

import TopBar from './components/TopBar';
import LeftPanel from './components/LeftPanel';
import PipelineBar from './components/PipelineBar';
import UnifiedTimeline from './components/UnifiedTimeline';
import ThinkingPanel from './components/ThinkingPanel';
import RightPanel from './components/RightPanel';
import BottomBar from './components/BottomBar';
import ToastNotification from './components/ToastNotification';

const AGENT_DISPLAY_NAMES: Record<string, string> = {
  'Plan Agent': 'AI Planning Agent',
};

function getAgentDisplayName(name: string): string {
  return AGENT_DISPLAY_NAMES[name] || name;
}

export default function App() {
  const sim = useBackend();
  const [filterAgent, setFilterAgent] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [chatLines, setChatLines] = useState<string[]>([]);
  const [scanMode, setScanMode] = useState('pentest');
  const [scanDepth] = useState('standard');
  const [incremental] = useState(false);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const handlePause = useCallback((id: string) => {
    sim.sendCommand('agent_pause', { agent_id: id });
  }, [sim]);

  const handleResume = useCallback((id: string) => {
    sim.sendCommand('agent_resume', { agent_id: id });
  }, [sim]);

  const handleKill = useCallback((id: string) => {
    sim.sendCommand('agent_kill', { agent_id: id });
  }, [sim]);

  const handleExport = useCallback(() => {
    const report = {
      target: sim.target,
      timestamp: new Date().toISOString(),
      findings: sim.findings,
      pipeline: sim.pipelineStages,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `itzraven-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [sim.target, sim.findings, sim.pipelineStages]);

  const handleCommand = useCallback(async (cmd: string) => {
    const targetPattern = /^https?:\/\/|^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|^[a-zA-Z]:\\|^\.{1,2}\//;
    const lower = cmd.toLowerCase().trim();

    if (lower === '/stop') { handleStopScan(); return; }
    if (lower === '/new') { handleNewScan(); return; }
    if (lower === '/clear') { setChatLines([]); return; }
    if (lower === '/status') {
      setChatLines(prev => [...prev, `You: ${cmd}`, '---', `Status: ${sim.agentStatus} | Target: ${sim.target || 'none'} | Mode: ${scanMode} | Agents: ${sim.agents.length}`]);
      return;
    }

    if (targetPattern.test(cmd)) {
      sim.requestScan(cmd, scanMode, scanDepth, incremental);
    } else {
      setChatLines(prev => [...prev, `You: ${cmd}`, '---', 'Thinking...']);
      const res = await sim.sendChat(cmd);
      if (res?.reply) {
        setChatLines(prev => {
          const updated = [...prev];
          updated[updated.length - 1] = res.reply;
          return updated;
        });
      }
    }
  }, [sim, scanMode]);

  const handleStopScan = useCallback(() => {
    fetch('/api/scan/stop', { method: 'POST' }).catch(() => {});
    setChatLines(prev => [...prev, '⛔ Scan stopped', '---']);
  }, []);

  const handleNewScan = useCallback(() => {
    setChatLines([]);
    fetch('/api/scan/new', { method: 'POST' }).catch(() => {});
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); handleStopScan(); }
      if ((e.ctrlKey || e.metaKey) && e.key === 'n') { e.preventDefault(); handleNewScan(); }
      if ((e.ctrlKey || e.metaKey) && e.key === 'l') { e.preventDefault(); setChatLines([]); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [handleStopScan, handleNewScan]);

  const currentAgent = sim.agents.find((a) => a.status === 'Running') || null;
  const agentDisplayName = currentAgent ? getAgentDisplayName(currentAgent.name) : null;

  const isScanRunning = sim.agentStatus !== 'IDLE' && sim.agentStatus !== 'CANCELLED';

  const sessionMetrics = {
    commandsExecuted: sim.commandCount,
    dataCollected: sim.findings.length > 0 ? sim.findings.length : 0,
    findings: sim.findings.length,
    vulnerabilities: sim.findings.filter((f) => f.severity === 'HIGH' || f.severity === 'CRITICAL').length,
    timeElapsed: sim.elapsed,
  };

  return (
    <div className="flex flex-col h-screen bg-zinc-950 text-zinc-300 overflow-hidden select-none">
      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #18181b; }
        ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: #52525b; }
      `}</style>

      <ToastNotification toasts={toasts} onDismiss={dismissToast} />
      <TopBar elapsed={sim.elapsed} target={sim.target} depth={scanDepth} incremental={incremental} isScanRunning={isScanRunning} onStopScan={handleStopScan} onNewScan={handleNewScan} />

      <div className="flex flex-1 min-h-0 overflow-hidden">
        <LeftPanel
          agents={sim.agents}
          cpu={Math.round(sim.cpu)}
          mem={Math.round(sim.mem)}
          net={Math.round(sim.net)}
          tokens={sim.tokens}
          credits={sim.credits}
          elapsed={sim.elapsed}
          llmModel={sim.llmModel}
          riskProfile={sim.riskProfile}
          maxParallel={sim.maxParallel}
          safeMode={sim.safeMode}
          agentStatus={sim.agentStatus}
          onPause={handlePause}
          onResume={handleResume}
          onKill={handleKill}
        />

        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <PipelineBar stages={sim.pipelineStages} />

          <div className="flex-1 flex flex-col min-h-0 overflow-hidden relative">
            <div className="flex-1 min-h-0 overflow-hidden">
              <UnifiedTimeline
                events={sim.timeline}
                agentName={agentDisplayName || (sim.agentStatus === 'IDLE' ? 'System' : sim.agentStatus)}
                agentStatus={currentAgent?.status || (sim.agentStatus === 'IDLE' ? 'Idle' : 'Running')}
                elapsed={sim.elapsed}
                filterAgent={filterAgent}
                filterSeverity={filterSeverity}
                onFilterAgentChange={setFilterAgent}
                onFilterSeverityChange={setFilterSeverity}
                agents={sim.agents}
              />
            </div>

            <ThinkingPanel
              agentName={chatLines.length ? 'AI Chat' : agentDisplayName || (sim.agentStatus === 'IDLE' ? 'System' : sim.agentStatus)}
              thought={chatLines.length ? chatLines.join('\n') : sim.currentThought}
              lastThought={chatLines.length ? '' : sim.lastThought}
              thinkingLines={chatLines.length ? chatLines : sim.thinkingLines}
              tokens={`${(sim.tokens / 1000).toFixed(1)}M`}
            />
          </div>
          </div>

        <RightPanel
          target={sim.target}
          mode={sim.mode}
          ipAddress={sim.targetIP}
          openPorts={sim.openPorts}
          subdomains={sim.subdomains}
          technologies={sim.technologiesCount}
          attackSurface={sim.attackSurface}
          topTech={sim.topTech}
          recentDiscoveries={sim.recentDiscoveries}
          findings={sim.findings}
          metrics={sessionMetrics}
          riskScore={sim.riskScore}
          riskLevel={sim.riskLevel}
          nodes={sim.graphNodes}
          edges={sim.graphEdges}
          onExport={handleExport}
        />
      </div>

      <BottomBar onCommand={handleCommand} onClearChat={() => setChatLines([])} scanMode={scanMode} onScanModeChange={setScanMode} shortcuts={['Ctrl+S Stop', 'Ctrl+N New', 'Ctrl+L Clear', '/help']} />
    </div>
  );
}
