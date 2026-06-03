import { useState, useRef, useEffect, useCallback } from 'react';
import type { GraphNode, GraphEdge } from '../types';

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const nodeColors: Record<string, { fill: string; stroke: string; text: string }> = {
  Host: { fill: '#1e3a2f', stroke: '#4ade80', text: '#4ade80' },
  Service: { fill: '#1e2a3a', stroke: '#60a5fa', text: '#60a5fa' },
  Application: { fill: '#2a1e3a', stroke: '#c084fc', text: '#c084fc' },
  DataStore: { fill: '#3a2a1e', stroke: '#fb923c', text: '#fb923c' },
  External: { fill: '#3a1e1e', stroke: '#f87171', text: '#f87171' },
};

const stateOpacity: Record<string, number> = {
  discovered: 1,
  pending: 0.45,
  compromised: 1,
  safe: 0.7,
};

const typeLegend = [
  { label: 'Host', color: '#4ade80' },
  { label: 'Service', color: '#60a5fa' },
  { label: 'Application', color: '#c084fc' },
  { label: 'DataStore', color: '#fb923c' },
  { label: 'External', color: '#f87171' },
];

const REPULSION = 800;
const ATTRACTION = 0.01;
const DAMPING = 0.85;
const CENTER_STRENGTH = 0.02;

function forceLayout(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number): GraphNode[] {
  if (nodes.length === 0) return nodes;
  const copy = nodes.map(n => ({ ...n }));
  const vel = copy.map(() => ({ x: 0, y: 0 }));
  const cx = width / 2;
  const cy = height / 2;

  for (let iter = 0; iter < 50; iter++) {
    // Repulsion
    for (let i = 0; i < copy.length; i++) {
      for (let j = i + 1; j < copy.length; j++) {
        let dx = copy[j].x - copy[i].x;
        let dy = copy[j].y - copy[i].y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let force = REPULSION / (dist * dist);
        let fx = (dx / dist) * force;
        let fy = (dy / dist) * force;
        vel[i].x -= fx;
        vel[i].y -= fy;
        vel[j].x += fx;
        vel[j].y += fy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const from = copy.find(n => n.id === edge.from);
      const to = copy.find(n => n.id === edge.to);
      if (!from || !to) continue;
      let dx = to.x - from.x;
      let dy = to.y - from.y;
      let dist = Math.sqrt(dx * dx + dy * dy) || 1;
      let force = ATTRACTION * dist;
      let fx = (dx / dist) * force;
      let fy = (dy / dist) * force;
      vel[copy.indexOf(from)].x += fx;
      vel[copy.indexOf(from)].y += fy;
      vel[copy.indexOf(to)].x -= fx;
      vel[copy.indexOf(to)].y -= fy;
    }

    // Center gravity
    for (let i = 0; i < copy.length; i++) {
      vel[i].x += (cx - copy[i].x) * CENTER_STRENGTH;
      vel[i].y += (cy - copy[i].y) * CENTER_STRENGTH;
    }

    // Apply velocity with damping
    for (let i = 0; i < copy.length; i++) {
      vel[i].x *= DAMPING;
      vel[i].y *= DAMPING;
      copy[i].x += vel[i].x;
      copy[i].y += vel[i].y;
    }
  }
  // Normalize to viewport
  const xs = copy.map(n => n.x);
  const ys = copy.map(n => n.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const rangeX = maxX - minX || 1;
  const rangeY = maxY - minY || 1;
  const margin = 15;
  for (const n of copy) {
    n.x = ((n.x - minX) / rangeX) * (width - margin * 2) + margin;
    n.y = ((n.y - minY) / rangeY) * (height - margin * 2) + margin;
  }
  return copy;
}

export default function AttackGraph({ nodes, edges }: Props) {
  const [isCollapsed, setIsCollapsed] = useState(true);
  const [layoutNodes, setLayoutNodes] = useState<GraphNode[]>([]);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 100, h: 100 });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0 });
  const vbRef = useRef(viewBox);
  vbRef.current = viewBox;

  useEffect(() => {
    if (nodes.length > 0) {
      const laid = forceLayout(nodes, edges, 100, 100);
      setLayoutNodes(laid);
      setViewBox({ x: 0, y: 0, w: 100, h: 100 });
    } else {
      setLayoutNodes([]);
    }
  }, [nodes, edges]);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const scale = e.deltaY > 0 ? 1.15 : 0.85;
    const vb = vbRef.current;
    const newW = Math.max(20, Math.min(500, vb.w * scale));
    const newH = Math.max(20, Math.min(500, vb.h * scale));
    const mx = (e.nativeEvent as unknown as PointerEvent).offsetX || 50;
    const my = (e.nativeEvent as unknown as PointerEvent).offsetY || 50;
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const pctX = mx / rect.width;
    const pctY = my / rect.height;
    setViewBox({
      x: vb.x + (vb.w - newW) * pctX,
      y: vb.y + (vb.h - newH) * pctY,
      w: newW,
      h: newH,
    });
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0) {
      isPanning.current = true;
      panStart.current = { x: e.clientX, y: e.clientY };
    }
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanning.current) return;
    const dx = panStart.current.x - e.clientX;
    const dy = panStart.current.y - e.clientY;
    panStart.current = { x: e.clientX, y: e.clientY };
    const vb = vbRef.current;
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const scaleX = vb.w / rect.width;
    const scaleY = vb.h / rect.height;
    setViewBox({ x: vb.x + dx * scaleX, y: vb.y + dy * scaleY, w: vb.w, h: vb.h });
  }, []);

  const handleMouseUp = useCallback(() => {
    isPanning.current = false;
  }, []);

  const nodeRadius = 5;
  const labelY = 9;

  const getNode = (id: string) => layoutNodes.find((n) => n.id === id);

  return (
    <div className={`flex flex-col ${isCollapsed ? '' : 'h-48'}`}>
      <div
        className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-700 shrink-0 cursor-pointer hover:bg-zinc-900"
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <span className="text-zinc-400 font-mono text-[12px] font-bold uppercase tracking-widest">Attack Graph</span>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-green-400 font-mono text-[13px]">LIVE</span>
          </div>
          <span className="text-zinc-500 text-[12px] font-mono">{isCollapsed ? '▶' : '▼'}</span>
        </div>
      </div>

      {!isCollapsed && (
      <div className="flex-1 relative overflow-hidden bg-zinc-950 min-h-0">
        <svg
          ref={svgRef}
          viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
          className="w-full h-full cursor-grab active:cursor-grabbing"
          preserveAspectRatio="xMidYMid meet"
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <defs>
            <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
              <path d="M 10 0 L 0 0 0 10" fill="none" stroke="#27272a" strokeWidth="0.2" />
            </pattern>
          </defs>
          <rect width={viewBox.w} height={viewBox.h} fill="url(#grid)" />

          {edges.map((edge, i) => {
            const from = getNode(edge.from);
            const to = getNode(edge.to);
            if (!from || !to) return null;
            return (
              <line
                key={i}
                x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                stroke={selectedNode && (selectedNode.id === edge.from || selectedNode.id === edge.to) ? '#818cf8' : '#3f3f46'}
                strokeWidth={selectedNode && (selectedNode.id === edge.from || selectedNode.id === edge.to) ? '0.8' : '0.5'}
                strokeDasharray={to.state === 'pending' ? '2 1' : undefined}
              />
            );
          })}

          {layoutNodes.map((node) => {
            const cfg = nodeColors[node.type];
            const opacity = stateOpacity[node.state];
            const isPending = node.state === 'pending';
            const isSelected = selectedNode?.id === node.id;
            return (
              <g
                key={node.id}
                opacity={opacity}
                style={{ cursor: 'pointer' }}
                onClick={(e) => { e.stopPropagation(); setSelectedNode(isSelected ? null : node); }}
              >
                {node.state === 'discovered' && !isSelected && (
                  <circle cx={node.x} cy={node.y} r={nodeRadius + 2} fill={cfg.stroke} opacity="0.12" />
                )}
                {isSelected && (
                  <circle cx={node.x} cy={node.y} r={nodeRadius + 3} fill="none" stroke="#818cf8" strokeWidth="0.5" opacity="0.8" />
                )}
                <circle
                  cx={node.x} cy={node.y} r={nodeRadius - 1}
                  fill={isSelected ? '#1e1b4b' : cfg.fill}
                  stroke={isSelected ? '#818cf8' : cfg.stroke}
                  strokeWidth={isPending ? '0.4' : '0.8'}
                  strokeDasharray={isPending ? '1.5 0.8' : undefined}
                />
                <text x={node.x} y={node.y + 0.8} textAnchor="middle" fontSize="3" fill={cfg.text}>
                  {node.type === 'Host' ? '⬡' : node.type === 'Service' ? '◈' : node.type === 'Application' ? '◉' : node.type === 'DataStore' ? '▣' : '◆'}
                </text>
                <text x={node.x} y={node.y + labelY} textAnchor="middle" fontSize="2.2" fill={isPending ? '#52525b' : cfg.text}>
                  {node.label.length > 25 ? node.label.slice(0, 24) + '…' : node.label}
                </text>
                {isPending && (
                  <text x={node.x} y={node.y - nodeRadius - 2} textAnchor="middle" fontSize="1.8" fill="#6b7280">pending</text>
                )}
              </g>
            );
          })}

          {layoutNodes.length === 0 && (
            <text x={viewBox.w / 2} y={viewBox.h / 2} textAnchor="middle" fontSize="4" fill="#52525b">
              No nodes yet. Start a scan to populate the graph.
            </text>
          )}
        </svg>

        {/* Node detail popup */}
        {selectedNode && (
          <div className="absolute top-2 left-2 bg-zinc-900 border border-zinc-700 rounded p-2 max-w-[200px] text-xs font-mono shadow-xl" onClick={() => setSelectedNode(null)}>
            <div className="font-bold text-zinc-200 mb-1">{selectedNode.label}</div>
            <div className="text-zinc-400">Type: <span style={{ color: nodeColors[selectedNode.type]?.stroke || '#999' }}>{selectedNode.type}</span></div>
            <div className="text-zinc-400">State: {selectedNode.state}</div>
            <div className="text-zinc-400">ID: {selectedNode.id}</div>
            {edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id).length > 0 && (
              <div className="text-zinc-500 mt-1">
                Connections: {edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id).length}
              </div>
            )}
            <div className="text-zinc-600 text-[10px] mt-1">Click to close</div>
          </div>
        )}

        {/* Zoom controls */}
        <div className="absolute bottom-1 right-1 flex gap-1">
          <button
            onClick={() => setViewBox(vb => ({ ...vb, w: Math.max(20, vb.w * 0.85), h: Math.max(20, vb.h * 0.85) }))}
            className="text-zinc-500 hover:text-zinc-300 bg-zinc-900/80 border border-zinc-700 rounded px-1 text-[11px] font-mono"
          >+</button>
          <button
            onClick={() => setViewBox(vb => ({ ...vb, w: Math.min(500, vb.w * 1.15), h: Math.min(500, vb.h * 1.15) }))}
            className="text-zinc-500 hover:text-zinc-300 bg-zinc-900/80 border border-zinc-700 rounded px-1 text-[11px] font-mono"
          >−</button>
          <button
            onClick={() => setViewBox({ x: 0, y: 0, w: 100, h: 100 })}
            className="text-zinc-500 hover:text-zinc-300 bg-zinc-900/80 border border-zinc-700 rounded px-1 text-[11px] font-mono"
          >⊡</button>
        </div>

        <div className="flex flex-wrap gap-x-2 gap-y-0.5 px-2 py-1 border-t border-zinc-800 bg-zinc-950">
          {typeLegend.map((l) => (
            <div key={l.label} className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: l.color }} />
              <span className="text-[12px] font-mono" style={{ color: l.color }}>{l.label}</span>
            </div>
          ))}
          <div className="flex items-center gap-1 ml-2">
            <div className="w-3 h-px border-t border-dashed border-zinc-600" />
            <span className="text-[12px] font-mono text-zinc-600">pending</span>
          </div>
          <div className="flex items-center gap-1 ml-auto">
            <span className="text-[10px] text-zinc-600">scroll zoom · drag pan · click inspect</span>
          </div>
        </div>
      </div>
      )}
      {selectedNode && isCollapsed && (
        <div className="px-3 py-1 text-[11px] text-zinc-500 border-t border-zinc-800">
          Selected: {selectedNode.label} ({selectedNode.type}) — expand graph to see details
        </div>
      )}
    </div>
  );
}
