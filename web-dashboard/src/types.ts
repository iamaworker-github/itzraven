export type AgentStatus = 'Done' | 'Running' | 'Idle' | 'Paused' | 'Killed' | 'Cancelled';
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type NodeType = 'Host' | 'Service' | 'Application' | 'DataStore' | 'External';
export type NodeState = 'discovered' | 'pending' | 'compromised' | 'safe';

export interface Agent {
  id: string;
  name: string;
  status: AgentStatus;
  findings: number;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  agentName: string;
  agentColor: string;
  eventType: 'started' | 'completed' | 'finding' | 'error' | 'info';
  message: string;
  severity?: Severity;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  agent: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  state: NodeState;
  x: number;
  y: number;
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface PipelineStage {
  name: string;
  completed: number;
  total: number;
  active?: boolean;
  cancelled?: boolean;
}

export interface Toast {
  id: string;
  message: string;
  severity: Severity;
  agent: string;
}
