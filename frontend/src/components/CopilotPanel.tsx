import { useEffect, useRef, useState } from 'react';

interface MCPEvent {
  timestamp: string;
  type: 'request' | 'response' | 'error';
  tool: string;
  params?: any;
  result?: any;
  data?: any;
  duration_ms?: number;
}

export default function CopilotPanel() {
  const [events, setEvents] = useState<MCPEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [filter, setFilter] = useState('');
  const [autoscroll, setAutoscroll] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    function connect() {
      if (closed) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${protocol}//${window.location.host}/ws/mcp-monitor`);

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) {
          reconnectTimer = setTimeout(connect, 2000);
        }
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'ping') return; // ignore heartbeat
          setEvents(prev => {
            const updated = [...prev, data as MCPEvent];
            return updated.length > 500 ? updated.slice(-500) : updated;
          });
        } catch {}
      };
    }

    connect();

    return () => {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, []);

  useEffect(() => {
    if (autoscroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, autoscroll]);

  const filtered = filter
    ? events.filter(e => e.tool.toLowerCase().includes(filter.toLowerCase()) ||
        JSON.stringify(e.params || e.result || e.data || '').toLowerCase().includes(filter.toLowerCase()))
    : events;

  const typeStyles: Record<string, { bg: string; color: string; label: string; icon: string }> = {
    request:  { bg: 'var(--accent-light)', color: 'var(--accent)', label: 'REQ', icon: '→' },
    response: { bg: 'var(--low-bg)', color: 'var(--low)', label: 'RES', icon: '←' },
    error:    { bg: 'var(--critical-bg)', color: 'var(--critical)', label: 'ERR', icon: '✕' },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{
        padding: '8px 12px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0,
      }}>
        <span style={{ fontWeight: 700, fontSize: 12 }}>MCP Monitor</span>
        <span style={{
          width: 7, height: 7, borderRadius: '50%',
          background: connected ? 'var(--low)' : 'var(--critical)',
        }} />
        <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>
          {connected ? 'Watching' : 'Disconnected'}
        </span>
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>{events.length}</span>
        <button className="btn btn-sm" onClick={() => setEvents([])} style={{ fontSize: 10, padding: '2px 6px' }}>Clear</button>
      </div>

      {/* Filter */}
      <div style={{ padding: '6px 12px', borderBottom: '1px solid var(--border-light)', display: 'flex', gap: 6, flexShrink: 0 }}>
        <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
          placeholder="Filter tools/data..."
          style={{ flex: 1, padding: '4px 8px', borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 11 }} />
        <label style={{ fontSize: 10, display: 'flex', alignItems: 'center', gap: 3, color: 'var(--text-dim)' }}>
          <input type="checkbox" checked={autoscroll} onChange={e => setAutoscroll(e.target.checked)} />
          Auto-scroll
        </label>
      </div>

      {/* Event stream */}
      <div style={{ flex: 1, overflowY: 'auto', fontFamily: 'var(--mono)', fontSize: 11 }}>
        {filtered.length === 0 && (
          <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-dim)', fontSize: 11, fontFamily: 'var(--font)' }}>
            {connected ? (
              <>
                Waiting for MCP traffic...<br /><br />
                <span style={{ fontSize: 10 }}>
                  Claude Code에서 MCP 도구를 호출하면<br />
                  여기에 실시간으로 표시됩니다.
                </span>
              </>
            ) : (
              'WebSocket disconnected. Reconnecting...'
            )}
          </div>
        )}
        {filtered.map((evt, i) => {
          const style = typeStyles[evt.type] || typeStyles.request;
          const isExpanded = expandedIdx === i;
          const time = evt.timestamp?.split('T')[1]?.slice(0, 12) || '';

          return (
            <div key={i}
              onClick={() => setExpandedIdx(isExpanded ? null : i)}
              style={{
                padding: '6px 12px', borderBottom: '1px solid var(--border-light)',
                cursor: 'pointer', transition: 'background 0.1s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface2)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              {/* Main line */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ color: 'var(--text-light)', fontSize: 10, minWidth: 72 }}>{time}</span>
                <span style={{
                  display: 'inline-block', padding: '0 5px', borderRadius: 3,
                  background: style.bg, color: style.color, fontSize: 9, fontWeight: 700, minWidth: 28, textAlign: 'center',
                }}>
                  {style.icon} {style.label}
                </span>
                <span style={{ fontWeight: 600, color: 'var(--text)' }}>{evt.tool}</span>
                {evt.duration_ms != null && (
                  <span style={{ color: 'var(--text-light)', fontSize: 10 }}>{evt.duration_ms}ms</span>
                )}
                {/* Brief params/result preview */}
                {evt.type === 'request' && evt.params && Object.keys(evt.params).length > 0 && (
                  <span style={{ color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
                    {Object.entries(evt.params).filter(([,v]) => v).map(([k,v]) => `${k}=${JSON.stringify(v)}`).join(' ').slice(0, 80)}
                  </span>
                )}
                {evt.type === 'response' && evt.result && (
                  <span style={{ color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
                    {summarize(evt.result)}
                  </span>
                )}
                {evt.type === 'error' && evt.data?.error && (
                  <span style={{ color: 'var(--critical)' }}>{String(evt.data.error).slice(0, 80)}</span>
                )}
              </div>

              {/* Expanded detail */}
              {isExpanded && (
                <pre style={{
                  marginTop: 6, padding: 8, borderRadius: 4,
                  background: 'var(--surface)', border: '1px solid var(--border-light)',
                  fontSize: 10, lineHeight: 1.5, overflow: 'auto', maxHeight: 200,
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  color: 'var(--text)',
                }}>
                  {evt.type === 'request' && evt.params && JSON.stringify(evt.params, null, 2)}
                  {evt.type === 'response' && evt.result && JSON.stringify(evt.result, null, 2)}
                  {evt.type === 'error' && evt.data && JSON.stringify(evt.data, null, 2)}
                </pre>
              )}
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {/* Status bar */}
      <div style={{
        padding: '4px 12px', borderTop: '1px solid var(--border)',
        fontSize: 10, color: 'var(--text-dim)', display: 'flex', gap: 12, flexShrink: 0,
      }}>
        <span>{events.filter(e => e.type === 'request').length} calls</span>
        <span>{events.filter(e => e.type === 'error').length} errors</span>
        {events.length > 0 && events[events.length - 1].duration_ms != null && (
          <span>Last: {events[events.length - 1].duration_ms}ms</span>
        )}
      </div>
    </div>
  );
}

function summarize(result: any): string {
  if (!result || typeof result !== 'object') return '';
  if (result.total_hits) return `${result.total_hits.toLocaleString()} hits`;
  if (result.total_estimated) return `${result.total_estimated} found`;
  if (result.total_findings != null) return `${result.total_findings} findings`;
  if (result.total_iocs) return `${result.total_iocs} IOCs`;
  if (result.total_events) return `${result.total_events} events`;
  if (result.attack_phases) return `${result.attack_phases} phases`;
  if (result.status) return result.status;
  return '';
}
