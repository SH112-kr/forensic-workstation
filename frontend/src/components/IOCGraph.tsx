import { useEffect, useMemo, useState } from 'react';
import type { CSSProperties, FormEvent } from 'react';
import { api, get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

interface GraphNode {
  id: string;
  type: string;
  label: string;
  subtitle?: string;
  count?: number;
  tactic?: string;
  technique_name?: string;
  severity?: string;
  ioc_type?: string;
  confidence?: string;
  visibility?: string;
  note?: string;
  source_reason?: string;
  source_artifact_types?: string[];
  x?: number;
  y?: number;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  weight?: number;
}

interface GraphPayload {
  ok: boolean;
  source_mode: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: Record<string, number>;
  warnings?: string[];
  analysis_limitations?: string[];
}

interface ManualObservation {
  id: string;
  node_type: ManualNodeType;
  value: string;
  ioc_type?: string;
  source_label?: string;
  note?: string;
  timestamp?: string;
  visibility?: string;
  created_at?: string;
}

type ManualNodeType = 'ioc' | 'mitre' | 'finding' | 'evidence' | 'note';
type GraphSource = 'session' | 'case';

const TYPE_ORDER = ['case', 'tool', 'manual', 'artifact', 'ioc', 'finding', 'mitre', 'tactic'];
const MANUAL_TYPES: ManualNodeType[] = ['ioc', 'mitre', 'finding', 'evidence', 'note'];
const IOC_TYPES = ['auto', 'ipv4', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256'];

const TYPE_COLOR: Record<string, { fill: string; stroke: string }> = {
  case: { fill: '#101419', stroke: '#e2e8f0' },
  tool: { fill: '#12151d', stroke: '#38bdf8' },
  manual: { fill: '#10201d', stroke: '#2dd4bf' },
  artifact: { fill: '#121619', stroke: '#22d3ee' },
  ioc: { fill: '#201911', stroke: '#f59e0b' },
  finding: { fill: '#211418', stroke: '#fb7185' },
  mitre: { fill: '#151827', stroke: '#a78bfa' },
  tactic: { fill: '#102019', stroke: '#34d399' },
};

const TYPE_LABEL: Record<string, string> = {
  case: 'CASE',
  tool: 'TOOL',
  manual: 'ANALYST',
  artifact: 'EVIDENCE',
  ioc: 'IOC',
  finding: 'FINDING',
  mitre: 'MITRE',
  tactic: 'TACTIC',
};

export default function IOCGraph() {
  const { language } = useStore();
  const ko = language === 'ko';
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [manualItems, setManualItems] = useState<ManualObservation[]>([]);
  const [graphSource, setGraphSource] = useState<GraphSource>('session');
  const [excludePrivate, setExcludePrivate] = useState(true);
  const [excludeKnownGood, setExcludeKnownGood] = useState(true);
  const [showContextIocs, setShowContextIocs] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [manualSaving, setManualSaving] = useState(false);
  const [error, setError] = useState('');
  const [manualError, setManualError] = useState('');
  const [form, setForm] = useState({
    node_type: 'ioc' as ManualNodeType,
    value: '',
    ioc_type: 'auto',
    source_label: '',
    timestamp: '',
    note: '',
  });

  const loadGraph = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await post<GraphPayload>('/api/ioc/graph', {
        graph_source: graphSource,
        ioc_types: '',
        exclude_private_ips: excludePrivate,
        exclude_known_good: excludeKnownGood,
        max_iocs: 140,
        max_findings: 90,
      });
      setGraph(data);
      setSelectedId('');
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  const loadManualItems = async () => {
    try {
      const data = await get<{ items: ManualObservation[] }>('/api/ioc/graph/manual');
      setManualItems(data.items || []);
    } catch {
      setManualItems([]);
    }
  };

  useEffect(() => {
    loadManualItems();
    loadGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const layout = useMemo(() => layoutNodes(graph?.nodes || []), [graph]);
  const nodeById = useMemo(() => Object.fromEntries(layout.map(n => [n.id, n])), [layout]);
  const visibleIds = useMemo(() => {
    const ids = new Set<string>();
    for (const node of layout) {
      if (typeFilter && node.type !== typeFilter) continue;
      if (!showContextIocs && node.type === 'ioc' && node.confidence === 'context' && node.visibility !== 'analyst_only') continue;
      ids.add(node.id);
    }
    return ids;
  }, [layout, showContextIocs, typeFilter]);
  const nodes = layout.filter(node => visibleIds.has(node.id));
  const edges = (graph?.edges || []).filter(edge => visibleIds.has(edge.source) && visibleIds.has(edge.target));
  const selected = selectedId ? nodeById[selectedId] : null;
  const nodeTypes = Array.from(new Set((graph?.nodes || []).map(n => n.type))).sort(compareTypes);

  const submitManual = async (e: FormEvent) => {
    e.preventDefault();
    const value = form.value.trim();
    if (!value) return;
    setManualSaving(true);
    setManualError('');
    try {
      await post<ManualObservation>('/api/ioc/graph/manual', {
        ...form,
        value,
        ioc_type: form.ioc_type === 'auto' ? '' : form.ioc_type,
      });
      setForm({ node_type: 'ioc', value: '', ioc_type: 'auto', source_label: '', timestamp: '', note: '' });
      await loadManualItems();
      await loadGraph();
    } catch (e: any) {
      setManualError(e.message || String(e));
    } finally {
      setManualSaving(false);
    }
  };

  const removeManual = async (id: string) => {
    setManualSaving(true);
    setManualError('');
    try {
      await api(`/api/ioc/graph/manual/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await loadManualItems();
      await loadGraph();
    } catch (e: any) {
      setManualError(e.message || String(e));
    } finally {
      setManualSaving(false);
    }
  };

  const title = ko ? 'IOC 관계 그래프' : 'IOC Relationship Graph';
  const graphLabel = graphSource === 'session' ? (ko ? '세션' : 'Session') : (ko ? '케이스' : 'Case');

  return (
    <section style={rootStyle}>
      <div style={toolbarStyle}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13 }}>{title}</div>
          <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>
            {graph?.source_mode || 'not_loaded'} | {graph?.stats?.nodes || 0} nodes | {graph?.stats?.edges || 0} edges
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <div className="btn-group" style={{ display: 'flex' }}>
            <button className={`btn btn-sm ${graphSource === 'session' ? 'btn-primary' : ''}`} onClick={() => setGraphSource('session')}>
              {ko ? '세션' : 'Session'}
            </button>
            <button className={`btn btn-sm ${graphSource === 'case' ? 'btn-primary' : ''}`} onClick={() => setGraphSource('case')}>
              {ko ? '케이스' : 'Case'}
            </button>
          </div>
          <label style={checkStyle}>
            <input type="checkbox" checked={excludePrivate} onChange={e => setExcludePrivate(e.target.checked)} />
            {ko ? '사설 IP 제외' : 'Private IPs'}
          </label>
          <label style={checkStyle}>
            <input type="checkbox" checked={excludeKnownGood} onChange={e => setExcludeKnownGood(e.target.checked)} />
            {ko ? 'Known-good 제외' : 'Known-good'}
          </label>
          <label style={checkStyle}>
            <input type="checkbox" checked={showContextIocs} onChange={e => setShowContextIocs(e.target.checked)} />
            {ko ? 'Context IOC' : 'Context IOCs'}
          </label>
          <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} style={selectStyle}>
            <option value="">{ko ? '모든 노드' : 'All nodes'}</option>
            {nodeTypes.map(type => <option key={type} value={type}>{TYPE_LABEL[type] || type}</option>)}
          </select>
          <button className="btn btn-primary btn-sm" onClick={loadGraph} disabled={loading}>
            {loading ? (ko ? '로딩...' : 'Loading...') : (ko ? '그래프 로드' : 'Load Graph')}
          </button>
        </div>
      </div>

      {error && <div style={errorStyle}>{error}</div>}

      <div style={contentStyle}>
        <div style={graphPaneStyle}>
          <div style={graphHeaderStyle}>
            <span>{graphLabel}</span>
            <span>{nodes.length}/{graph?.nodes?.length || 0}</span>
          </div>
          <svg viewBox="0 0 1100 520" style={svgStyle} role="img" aria-label={title}>
            <defs>
              <marker id="iocGraphArrow" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto">
                <path d="M0,0 L7,3.5 L0,7 Z" fill="rgba(148,163,184,0.62)" />
              </marker>
            </defs>
            {edges.map(edge => {
              const source = nodeById[edge.source];
              const target = nodeById[edge.target];
              if (!source || !target) return null;
              return (
                <g key={edge.id}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke="rgba(148,163,184,0.32)"
                    strokeWidth={Math.min(4, 1 + Math.log2((edge.weight || 1) + 1))}
                    markerEnd="url(#iocGraphArrow)"
                  />
                  <title>{edge.label}</title>
                </g>
              );
            })}
            {nodes.map(node => {
              const colors = TYPE_COLOR[node.type] || { fill: '#111827', stroke: '#94a3b8' };
              const active = selectedId === node.id;
              return (
                <g key={node.id} transform={`translate(${node.x}, ${node.y})`} onClick={() => setSelectedId(node.id)} style={{ cursor: 'pointer' }}>
                  <circle r={active ? 33 : 28} fill={colors.fill} stroke={colors.stroke} strokeWidth={active ? 3 : 2} />
                  <text y={-4} textAnchor="middle" fill="var(--text)" fontSize="10" fontWeight="700">
                    {TYPE_LABEL[node.type] || node.type.toUpperCase()}
                  </text>
                  <text y={10} textAnchor="middle" fill="var(--text-dim)" fontSize="9">
                    {shortLabel(node.label)}
                  </text>
                  <title>{node.label}</title>
                </g>
              );
            })}
          </svg>
          {!graph && !loading && (
            <div style={emptyStyle}>{ko ? '그래프를 로드하세요.' : 'Load a graph to review IOC relationships.'}</div>
          )}
        </div>

        <aside style={sideStyle}>
          <div style={panelStyle}>
            <div style={panelTitleStyle}>{ko ? '선택 노드' : 'Selected Node'}</div>
            {selected ? (
              <div style={{ display: 'grid', gap: 7 }}>
                <Detail label="Type" value={TYPE_LABEL[selected.type] || selected.type} />
                <Detail label="Label" value={selected.label} mono />
                {selected.subtitle && <Detail label="Subtitle" value={selected.subtitle} />}
                {selected.confidence && <Detail label="Confidence" value={selected.confidence} />}
                {selected.count !== undefined && <Detail label="Count" value={String(selected.count)} />}
                {selected.tactic && <Detail label="Tactic" value={selected.tactic} />}
                {selected.source_reason && <Detail label="Reason" value={selected.source_reason} />}
                {selected.note && <Detail label="Note" value={selected.note} />}
              </div>
            ) : (
              <div style={mutedStyle}>{ko ? '노드를 선택하세요.' : 'Select a node.'}</div>
            )}
          </div>

          <form onSubmit={submitManual} style={panelStyle}>
            <div style={panelTitleStyle}>{ko ? '분석가 노드' : 'Analyst Node'}</div>
            <select value={form.node_type} onChange={e => setForm({ ...form, node_type: e.target.value as ManualNodeType })} style={inputStyle}>
              {MANUAL_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
            </select>
            <input value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} placeholder={ko ? '값' : 'Value'} style={inputStyle} />
            {form.node_type === 'ioc' && (
              <select value={form.ioc_type} onChange={e => setForm({ ...form, ioc_type: e.target.value })} style={inputStyle}>
                {IOC_TYPES.map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            )}
            <input value={form.source_label} onChange={e => setForm({ ...form, source_label: e.target.value })} placeholder={ko ? '출처' : 'Source'} style={inputStyle} />
            <input value={form.timestamp} onChange={e => setForm({ ...form, timestamp: e.target.value })} placeholder="2026-01-01T00:00:00Z" style={inputStyle} />
            <textarea value={form.note} onChange={e => setForm({ ...form, note: e.target.value })} placeholder={ko ? '메모' : 'Note'} style={{ ...inputStyle, minHeight: 54, resize: 'vertical' }} />
            {manualError && <div style={errorStyle}>{manualError}</div>}
            <button className="btn btn-primary btn-sm" disabled={manualSaving || !form.value.trim()}>
              {manualSaving ? (ko ? '저장 중...' : 'Saving...') : (ko ? '추가' : 'Add')}
            </button>
            <div style={manualListStyle}>
              {manualItems.slice(0, 8).map(item => (
                <div key={item.id} style={manualItemStyle}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.value}</div>
                    <div style={mutedStyle}>{item.node_type} | {item.source_label || 'Analyst'}</div>
                  </div>
                  <button type="button" className="btn btn-sm" onClick={() => removeManual(item.id)} disabled={manualSaving}>x</button>
                </div>
              ))}
            </div>
          </form>

          {!!graph?.warnings?.length && (
            <div style={panelStyle}>
              <div style={panelTitleStyle}>{ko ? '경고' : 'Warnings'}</div>
              {graph.warnings.slice(0, 4).map((item, idx) => <div key={idx} style={noteStyle}>{item}</div>)}
            </div>
          )}
          {!!graph?.analysis_limitations?.length && (
            <div style={panelStyle}>
              <div style={panelTitleStyle}>{ko ? '제한사항' : 'Limitations'}</div>
              {graph.analysis_limitations.slice(0, 4).map((item, idx) => <div key={idx} style={noteStyle}>{item}</div>)}
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}

function layoutNodes(nodes: GraphNode[]): GraphNode[] {
  const grouped = new Map<string, GraphNode[]>();
  for (const node of nodes) {
    const group = node.type || 'other';
    grouped.set(group, [...(grouped.get(group) || []), node]);
  }
  const groups = Array.from(grouped.keys()).sort(compareTypes);
  const width = 1000;
  const startX = 50;
  const stepX = groups.length > 1 ? width / (groups.length - 1) : width / 2;
  const laidOut: GraphNode[] = [];
  groups.forEach((group, groupIdx) => {
    const items = grouped.get(group) || [];
    const span = Math.min(430, Math.max(120, items.length * 72));
    const top = 260 - span / 2;
    items.forEach((node, idx) => {
      const stepY = items.length > 1 ? span / (items.length - 1) : 0;
      laidOut.push({ ...node, x: startX + groupIdx * stepX, y: items.length === 1 ? 260 : top + idx * stepY });
    });
  });
  return laidOut;
}

function compareTypes(a: string, b: string) {
  const ai = TYPE_ORDER.indexOf(a);
  const bi = TYPE_ORDER.indexOf(b);
  if (ai === -1 && bi === -1) return a.localeCompare(b);
  if (ai === -1) return 1;
  if (bi === -1) return -1;
  return ai - bi;
}

function shortLabel(value: string) {
  if (value.length <= 18) return value;
  return `${value.slice(0, 15)}...`;
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div style={mutedStyle}>{label}</div>
      <div style={{ fontSize: 11, wordBreak: 'break-word', fontFamily: mono ? 'var(--mono)' : undefined }}>{value}</div>
    </div>
  );
}

const rootStyle: CSSProperties = {
  borderTop: '1px solid var(--border)',
  borderBottom: '1px solid var(--border)',
  background: 'var(--bg)',
  minHeight: 540,
  display: 'flex',
  flexDirection: 'column',
};
const toolbarStyle: CSSProperties = {
  padding: '10px 16px',
  display: 'flex',
  justifyContent: 'space-between',
  gap: 12,
  alignItems: 'center',
  background: 'var(--surface)',
  borderBottom: '1px solid var(--border)',
  flexWrap: 'wrap',
};
const contentStyle: CSSProperties = { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 300px', minHeight: 500 };
const graphPaneStyle: CSSProperties = { position: 'relative', minWidth: 0, overflow: 'hidden' };
const graphHeaderStyle: CSSProperties = {
  position: 'absolute',
  top: 10,
  left: 12,
  right: 12,
  display: 'flex',
  justifyContent: 'space-between',
  color: 'var(--text-dim)',
  fontSize: 11,
  zIndex: 1,
};
const svgStyle: CSSProperties = { width: '100%', height: 500, display: 'block', background: 'var(--bg)' };
const sideStyle: CSSProperties = { borderLeft: '1px solid var(--border)', background: 'var(--surface)', overflow: 'auto', padding: 10, display: 'grid', gap: 10, alignContent: 'start' };
const panelStyle: CSSProperties = { border: '1px solid var(--border)', borderRadius: 6, padding: 10, display: 'grid', gap: 8, background: 'var(--surface)' };
const panelTitleStyle: CSSProperties = { fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)' };
const checkStyle: CSSProperties = { fontSize: 11, color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: 4 };
const inputStyle: CSSProperties = { width: '100%', padding: '5px 8px', border: '1px solid var(--border)', borderRadius: 5, background: 'var(--bg)', color: 'var(--text)', fontSize: 11 };
const selectStyle: CSSProperties = { ...inputStyle, width: 116 };
const errorStyle: CSSProperties = { color: 'var(--high)', fontSize: 11, padding: '6px 10px', whiteSpace: 'pre-wrap' };
const mutedStyle: CSSProperties = { color: 'var(--text-dim)', fontSize: 11 };
const noteStyle: CSSProperties = { color: 'var(--text-dim)', fontSize: 11, lineHeight: 1.35 };
const emptyStyle: CSSProperties = { position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', color: 'var(--text-dim)', fontSize: 12, pointerEvents: 'none' };
const manualListStyle: CSSProperties = { display: 'grid', gap: 6, borderTop: '1px solid var(--border)', paddingTop: 8 };
const manualItemStyle: CSSProperties = { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 8, alignItems: 'center' };
