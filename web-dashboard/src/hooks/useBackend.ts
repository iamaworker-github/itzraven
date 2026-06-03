import { useState, useEffect, useRef, useCallback } from 'react';
import type { Agent, TimelineEvent, Finding, GraphNode, GraphEdge, PipelineStage, Toast, Severity } from '../types';

let idCounter = 1;
const uid = () => `b_${idCounter++}_${Date.now()}`;

interface BackendState {
  cpu?: number; mem?: number; net?: number;
  tokens?: number; maxTokens?: number; credits?: number;
  uptime?: string; sessionId?: string; time?: string;
  target?: string; mode?: string;
  agentStatus?: string; riskProfile?: string;
  maxParallel?: string; safeMode?: boolean;
  activeAgentName?: string; activeAgentTime?: string;
  tokensUsed?: string; memoryPercent?: number; knowledgeBase?: string;
  agents?: BackendAgent[];
  pipeline?: BackendPipelineStage[];
  logs?: BackendLog[];
  thinkingLines?: string[];
  activities?: BackendActivity[];
  findings?: BackendFinding[];
  technologies?: BackendTech[];
  discoveries?: BackendDisc[];
  nodes?: BackendNode[];
  edges?: BackendEdge[];
  riskScore?: number; riskLabel?: string;
  targetIP?: string; openPorts?: number;
  subdomains?: number; technologies_count?: number;
  attackSurface?: string; commandsExecuted?: number;
  dataCollected?: string; findingsCount?: number;
  vulnerabilities?: number;
  llmModel?: string;
}

interface BackendAgent { id?: string; name?: string; status?: string; findings?: number; }
interface BackendPipelineStage { name: string; completed: number; total: number; active?: boolean; }
interface BackendLog { id?: number; text?: string; type?: string; timestamp?: string; agent_name?: string; }
interface BackendActivity { time?: string; agent?: string; message?: string; }
interface BackendFinding { text?: string; title?: string; severity?: string; agent_name?: string; }
interface BackendTech { name?: string; icon?: string; percent?: number; }
interface BackendDisc { name?: string; time?: string; }
interface BackendNode { id?: string; label?: string; sublabel?: string; x?: number; y?: number; type?: string; color?: string; }
interface BackendEdge { from?: string; to?: string; }

function mapAgentStatus(s?: string): Agent['status'] {
  if (!s) return 'Idle';
  const l = s.toLowerCase();
  if (l === 'running' || l === 'executing' || l === 'planning') return 'Running';
  if (l === 'done' || l === 'completed' || l === 'complete') return 'Done';
  if (l === 'paused') return 'Paused';
  if (l === 'killed' || l === 'failed' || l === 'error') return 'Killed';
  return 'Idle';
}

function mapSeverity(s?: string): Severity {
  if (!s) return 'INFO';
  const l = s.toLowerCase();
  if (l === 'critical') return 'CRITICAL';
  if (l === 'high') return 'HIGH';
  if (l === 'medium') return 'MEDIUM';
  if (l === 'low') return 'LOW';
  return 'INFO';
}

function mapNodeType(t?: string): GraphNode['type'] {
  if (!t) return 'Host';
  const l = t.toLowerCase();
  if (l === 'host') return 'Host';
  if (l === 'service') return 'Service';
  if (l === 'application' || l === 'app') return 'Application';
  if (l === 'datastore') return 'DataStore';
  if (l === 'external') return 'External';
  return 'Host';
}

function mapEventType(t?: string): TimelineEvent['eventType'] {
  if (!t) return 'info';
  const l = t.toLowerCase();
  if (l === 'started') return 'started';
  if (l === 'completed' || l === 'done') return 'completed';
  if (l === 'finding' || l === 'warning') return 'finding';
  if (l === 'error' || l === 'failed') return 'error';
  return 'info';
}

const AGENT_COLORS: Record<string, string> = {
  'Plan Agent': '#a855f7',
  'WAF Detection': '#06b6d4',
  'BackMeUp': '#f59e0b',
  'Smart Brute Force': '#ef4444',
  'Nuclei Agent': '#10b981',
  'Recon Agent': '#f97316',
};

function getAgentColor(name: string): string {
  for (const [key, color] of Object.entries(AGENT_COLORS)) {
    if (name.toLowerCase().includes(key.toLowerCase())) return color;
  }
  return '#94a3b8';
}

function formatTime(seconds: number): string {
  const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
  const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
  const s = (seconds % 60).toString().padStart(2, '0');
  return `${h}:${m}:${s}`;
}

const EMPTY_STATE = {
  agents: [] as Agent[],
  timeline: [] as TimelineEvent[],
  findings: [] as Finding[],
  graphNodes: [] as GraphNode[],
  graphEdges: [] as GraphEdge[],
  pipelineStages: [] as PipelineStage[],
  toasts: [] as Toast[],
  cpu: 0, mem: 0, net: 0,
  tokens: 0, credits: 0,
  elapsed: '00:00:00',
  commandCount: 0,
  currentThought: null as string | null,
  lastThought: null as string | null,
  thinkingLines: [] as string[],
  target: '',
  sessionId: '',
  mode: 'PENTEST',
  riskScore: 0,
  riskLevel: 'Unknown',
  targetIP: '',
  openPorts: 0,
  subdomains: 0,
  technologiesCount: 0,
  attackSurface: 'Unknown',
  topTech: [] as string[],
  recentDiscoveries: [] as string[],
  llmModel: '',
  riskProfile: 'Balanced',
  maxParallel: '4 agents',
  safeMode: true,
  agentStatus: 'IDLE',
};

export function useBackend() {
  const [state, setState] = useState({ ...EMPTY_STATE });
  const wsRef = useRef<WebSocket | null>(null);
  const findingsRef = useRef<Finding[]>([]);
  const timelineRef = useRef<TimelineEvent[]>([]);
  const nodeRef = useRef<GraphNode[]>([]);
  const edgeRef = useRef<GraphEdge[]>([]);

  const requestScan = useCallback(async (target: string, mode = 'pentest', depth = 'standard', incremental = false) => {
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode, depth, incremental }),
      });
      return await res.json();
    } catch { return null; }
  }, []);

  const sendCommand = useCallback((type: string, payload?: Record<string, unknown>) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type, payload }));
    }
  }, []);

  const sendChat = useCallback(async (message: string) => {
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      return await res.json();
    } catch { return null; }
  }, []);

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/ws`;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let retries = 0;
    let mounted = true;
    let startTime = Date.now();

    function connect() {
      if (!mounted) return;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type !== 'state' || !data.payload) return;
          const p: BackendState = data.payload;

          setState(prev => {
            // Uptime from server or local counter
            const uptime = p.uptime || formatTime(Math.floor((Date.now() - startTime) / 1000));

            // Agents
            const agents: Agent[] = (p.agents || []).map(a => ({
              id: a.id || uid(),
              name: a.name || 'Unknown',
              status: mapAgentStatus(a.status),
              findings: a.findings ?? 0,
            }));

            // Pipeline
            const pipelineStages: PipelineStage[] = (p.pipeline || []).map(s => ({
              name: s.name,
              completed: s.completed,
              total: s.total,
              active: s.active,
            }));

            // Timeline from logs — full replace to avoid dupes on reconnect
            const newTimeline: TimelineEvent[] = (p.logs || []).map(l => {
              const agentName = l.agent_name || (l.text ? l.text.split('[')[0]?.trim() || 'System' : 'System');
              return {
                id: uid(),
                timestamp: l.timestamp || new Date().toLocaleTimeString(),
                agentName,
                agentColor: getAgentColor(agentName),
                eventType: mapEventType(l.type),
                message: l.text || '',
              };
            });
            timelineRef.current = newTimeline.slice(-100);

            // Findings — full replace to avoid dupes on reconnect
            const newFindings: Finding[] = (p.findings || [])
              .filter((f): f is BackendFinding => f != null)
              .map(f => ({
                id: uid(),
                title: f.text || f.title || '',
                severity: mapSeverity(f.severity),
                agent: f.agent_name || '',
              }));
            findingsRef.current = newFindings.slice(-50);

            // Technologies
            const topTech = (p.technologies || []).map(t => t.name || '').filter(Boolean);

            // Discoveries
            const recentDiscoveries = (p.discoveries || []).map(d => d.name || '').filter(Boolean);

            // Nodes
            const graphNodes: GraphNode[] = (p.nodes || []).map(n => ({
              id: n.id || uid(),
              label: n.label || '',
              type: mapNodeType(n.type),
              state: 'discovered' as const,
              x: n.x ?? 50,
              y: n.y ?? 50,
            }));
            if (graphNodes.length > 0) nodeRef.current = graphNodes;

            // Edges
            const graphEdges: GraphEdge[] = (p.edges || []).map(e => ({
              from: e.from || '',
              to: e.to || '',
            }));
            if (graphEdges.length > 0) edgeRef.current = graphEdges;

            return {
              agents,
              timeline: timelineRef.current,
              findings: findingsRef.current,
              graphNodes: nodeRef.current,
              graphEdges: edgeRef.current,
              pipelineStages,
              toasts: prev.toasts,
              cpu: p.cpu ?? prev.cpu,
              mem: p.mem ?? prev.mem,
              net: p.net ?? prev.net,
              tokens: p.tokens ?? prev.tokens,
              credits: p.credits ?? prev.credits,
              elapsed: uptime,
              commandCount: p.commandsExecuted ?? prev.commandCount,
              currentThought: p.thinkingLines?.length ? p.thinkingLines[p.thinkingLines.length - 1] : null,
              lastThought: prev.currentThought,
              thinkingLines: p.thinkingLines || [],
              target: p.target || prev.target,
              sessionId: p.sessionId || '',
              mode: p.mode || prev.mode,
              riskScore: p.riskScore ?? prev.riskScore,
              riskLevel: p.riskLabel || 'Unknown',
              targetIP: p.targetIP || '',
              openPorts: p.openPorts ?? 0,
              subdomains: p.subdomains ?? 0,
              technologiesCount: p.technologies_count ?? 0,
              attackSurface: p.attackSurface || 'Unknown',
              topTech,
              recentDiscoveries,
              llmModel: p.llmModel ?? 'AI OFF',
              riskProfile: p.riskProfile ?? prev.riskProfile,
              maxParallel: p.maxParallel ?? prev.maxParallel,
              safeMode: p.safeMode ?? prev.safeMode,
              agentStatus: p.agentStatus ?? 'IDLE',
            };
          });
        } catch { /* ignore parse errors */ }
      };

      ws.onclose = () => {
        wsRef.current = null;
        if (!mounted) return;
        const delay = Math.min(1000 * Math.pow(2, retries), 15000);
        retries++;
        reconnectTimer = setTimeout(connect, delay);
      };

      ws.onerror = () => ws.close();
    }

    connect();
    return () => {
      mounted = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close(); }
    };
  }, []);

  return { ...state, requestScan, sendCommand, sendChat };
}
