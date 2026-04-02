import { useState } from 'react';
import { post } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

export default function LogAnalysis() {
  const [connected, setConnected] = useState(false);
  const [path, setPath] = useState('');
  const [loading, setLoading] = useState('');
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);
  const [events, setEvents] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [minLevel, setMinLevel] = useState('medium');
  const [filter, setFilter] = useState('');

  const openEvtx = async () => {
    if (!path.trim()) return;
    setLoading('Opening EVTX...');
    setError('');
    try {
      await post('/api/logs/open', { path: path.trim() });
      setConnected(true);
      scan();
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const scan = async () => {
    setLoading('Running Hayabusa scan...');
    try {
      const data = await post('/api/logs/scan', { min_level: minLevel });
      setEvents(data.events || []);
      setTotal(data.total_events || 0);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const filtered = filter
    ? events.filter(e => JSON.stringify(e).toLowerCase().includes(filter.toLowerCase()))
    : events;

  const levelColors: Record<string, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', informational: 'info' };

  if (!connected) {
    return (
      <div style={{ padding: 40, maxWidth: 500, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 16 }}>EVTX Log Analysis (Hayabusa)</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input type="text" value={path} onChange={e => setPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && openEvtx()}
            placeholder="Path to .evtx file or directory"
            style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
          <button className="btn" onClick={() => setBrowserOpen(true)}>Browse</button>
          <button className="btn btn-primary" onClick={openEvtx} disabled={!!loading}>Open</button>
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--accent)' }}>{loading}</div>}
        {error && <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 8 }}>{error}</div>}
        <FileBrowser open={browserOpen} onClose={() => setBrowserOpen(false)}
          onSelect={(p) => { setPath(p); setBrowserOpen(false); }} title="Select EVTX" />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: '10px 16px', display: 'flex', gap: 8, borderBottom: '1px solid var(--border)', background: 'var(--surface)', alignItems: 'center' }}>
        <select value={minLevel} onChange={e => setMinLevel(e.target.value)}
          style={{ padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12 }}>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">All</option>
        </select>
        <button className="btn btn-primary btn-sm" onClick={scan} disabled={!!loading}>
          {loading ? 'Scanning...' : 'Re-scan'}
        </button>
        <div style={{ flex: 1 }} />
        <input type="text" placeholder="Filter events..." value={filter} onChange={e => setFilter(e.target.value)}
          style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, width: 200 }} />
        <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{filtered.length}/{total} events</span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 && !loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>No events found.</div>
        )}
        {loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            <div style={{ width: 20, height: 20, border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 12px' }} />
            {loading}
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead><tr>
            <th style={thS}>Level</th><th style={thS}>Timestamp</th><th style={thS}>Computer</th>
            <th style={thS}>Rule</th><th style={thS}>Details</th>
          </tr></thead>
          <tbody>
            {filtered.slice(0, 500).map((e, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                <td style={tdS}><span className={`badge badge-${levelColors[e.Level?.toLowerCase()] || 'info'}`}>{e.Level}</span></td>
                <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11 }}>{e.Timestamp}</td>
                <td style={tdS}>{e.Computer}</td>
                <td style={{ ...tdS, fontWeight: 600 }}>{e.RuleTitle || e.rule_title}</td>
                <td style={{ ...tdS, color: 'var(--text-dim)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  title={JSON.stringify(e.Details || e.details)}>
                  {typeof e.Details === 'object' ? JSON.stringify(e.Details).slice(0, 100) : String(e.Details || '').slice(0, 100)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const thS: React.CSSProperties = { padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)', borderBottom: '2px solid var(--border)', position: 'sticky', top: 0 };
const tdS: React.CSSProperties = { padding: '6px 12px' };
