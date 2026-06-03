import type { Agent, TimelineEvent, Finding, GraphNode, GraphEdge, PipelineStage } from './types';

export const initialAgents: Agent[] = [
  { id: 'plan', name: 'Plan Agent', status: 'Done', findings: 1 },
  { id: 'waf', name: 'WAF Detection', status: 'Done', findings: 0 },
  { id: 'backmeup', name: 'BackMeUp', status: 'Running', findings: 1 },
  { id: 'brute', name: 'Smart Brute Force', status: 'Running', findings: 0 },
  { id: 'nuclei', name: 'Nuclei Agent', status: 'Done', findings: 0 },
  { id: 'recon', name: 'Recon Agent', status: 'Running', findings: 0 },
];

export const initialTimeline: TimelineEvent[] = [
  { id: 't1', timestamp: '15:25:06', agentName: 'Plan Agent', agentColor: '#a855f7', eventType: 'started', message: 'Agent started' },
  { id: 't2', timestamp: '15:25:12', agentName: 'WAF Detection Agent', agentColor: '#06b6d4', eventType: 'started', message: 'Agent started' },
  { id: 't3', timestamp: '15:25:18', agentName: 'WAF Detection Agent', agentColor: '#06b6d4', eventType: 'completed', message: 'Agent completed — 0 findings' },
  { id: 't4', timestamp: '15:25:22', agentName: 'BackMeUp Agent', agentColor: '#f59e0b', eventType: 'started', message: 'Agent started' },
  { id: 't5', timestamp: '15:25:24', agentName: 'Smart Brute Force', agentColor: '#ef4444', eventType: 'started', message: 'Agent started' },
  { id: 't6', timestamp: '15:25:26', agentName: 'Nuclei Agent', agentColor: '#10b981', eventType: 'started', message: 'Agent started' },
  { id: 't7', timestamp: '15:25:30', agentName: 'Plan Agent', agentColor: '#a855f7', eventType: 'finding', message: 'Agent Selection Plan [INFO]', severity: 'INFO' },
  { id: 't8', timestamp: '15:25:36', agentName: 'Plan Agent', agentColor: '#a855f7', eventType: 'completed', message: 'Agent completed — 1 findings' },
  { id: 't9', timestamp: '15:25:42', agentName: 'Nuclei Agent', agentColor: '#10b981', eventType: 'started', message: 'Agent started' },
  { id: 't10', timestamp: '15:25:42', agentName: 'Nuclei Agent', agentColor: '#10b981', eventType: 'completed', message: 'Agent completed — 0 findings' },
  { id: 't11', timestamp: '15:25:42', agentName: 'Recon Agent', agentColor: '#f97316', eventType: 'started', message: 'Agent started' },
  { id: 't12', timestamp: '15:25:50', agentName: 'BackMeUp Agent', agentColor: '#f59e0b', eventType: 'finding', message: 'BackMeUp: 10002 URLs for testphp.vulnweb.com [INFO]', severity: 'INFO' },
  { id: 't13', timestamp: '15:26:02', agentName: 'WAF Detection Agent', agentColor: '#06b6d4', eventType: 'started', message: 'Agent started' },
  { id: 't14', timestamp: '15:26:08', agentName: 'WAF Detection Agent', agentColor: '#06b6d4', eventType: 'completed', message: 'Agent completed — 0 findings' },
];

export const initialFindings: Finding[] = [
  { id: 'f1', title: 'Agent Selection Plan', severity: 'INFO', agent: 'Plan Agent' },
  { id: 'f2', title: 'BackMeUp: 10002 URLs for testphp.vulnweb.com', severity: 'INFO', agent: 'BackMeUp Agent' },
  { id: 'f3', title: 'Agent Selection Plan', severity: 'INFO', agent: 'Plan Agent' },
  { id: 'f4', title: 'BackMeUp: 10002 URLs for testphp.vulnweb.com', severity: 'INFO', agent: 'BackMeUp Agent' },
  { id: 'f5', title: 'Agent Selection Plan', severity: 'INFO', agent: 'Plan Agent' },
  { id: 'f6', title: 'BackMeUp: 10002 URLs for testphp.vulnweb.com', severity: 'INFO', agent: 'BackMeUp Agent' },
];

export const initialGraphNodes: GraphNode[] = [
  { id: 'n1', label: 'testphp.vulnweb.com', type: 'Host', state: 'discovered', x: 50, y: 50 },
  { id: 'n2', label: 'HTTP:80', type: 'Service', state: 'pending', x: 20, y: 75 },
  { id: 'n3', label: 'HTTPS:443', type: 'Service', state: 'pending', x: 50, y: 80 },
  { id: 'n4', label: 'Web App', type: 'Application', state: 'pending', x: 80, y: 75 },
  { id: 'n5', label: 'DB Backend', type: 'DataStore', state: 'pending', x: 65, y: 30 },
];

export const initialGraphEdges: GraphEdge[] = [
  { from: 'n1', to: 'n2' },
  { from: 'n1', to: 'n3' },
  { from: 'n1', to: 'n4' },
  { from: 'n4', to: 'n5' },
];

export const pipelineStages: PipelineStage[] = [
  { name: 'Reconnaissance', completed: 2, total: 4 },
  { name: 'Enumeration', completed: 1, total: 4 },
  { name: 'Analysis', completed: 0, total: 3 },
  { name: 'Vulnerability', completed: 0, total: 4 },
  { name: 'Exploitation', completed: 0, total: 2 },
  { name: 'Reporting', completed: 0, total: 2 },
];
