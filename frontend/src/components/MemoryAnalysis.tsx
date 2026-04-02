import { useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

export default function MemoryAnalysis() {
  const [connected, setConnected] = useState(false);
  const [path, setPath] = useState('');
  const [loading, setLoading] = useState('');
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [pslist, setPslist] = useState<any[]>([]);
  const [netscan, setNetscan] = useState<any[]>([]);
  const [malfind, setMalfind] = useState<any[]>([]);
  const [cmdline, setCmdline] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState('pslist');

  const openDump = async () => {
    if (!path.trim()) return;
    setLoading('Opening memory dump...');
    setError('');
    try {
      await post('/api/memory/open', { path: path.trim() });
      setConnected(true);
      setLoading('Loading process list...');
      const ps = await get('/api/memory/pslist');
      setPslist(ps.processes || []);
    } catch (e: any) {
      setError(e.message);
    } finally { setLoading(''); }
  };

  const loadPlugin = async (plugin: string) => {
    setLoading(`Running ${plugin}...`);
    try {
      if (plugin === 'pslist') { const r = await get('/api/memory/pslist'); setPslist(r.processes || []); }
      else if (plugin === 'netscan') { const r = await get('/api/memory/netscan'); setNetscan(r.connections || []); }
      else if (plugin === 'malfind') { const r = await get('/api/memory/malfind'); setMalfind(r.findings || []); }
      else if (plugin === 'cmdline') { const r = await get('/api/memory/cmdline'); setCmdline(r.processes || []); }
      setActiveTab(plugin);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  if (!connected) {
    return (
      <div style={{ padding: 40, maxWidth: 500, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 16 }}>Memory Analysis (Volatility 3)</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input type="text" value={path} onChange={e => setPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && openDump()}
            placeholder="Path to memory dump (.raw, .vmem, .dmp)"
            style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
          <button className="btn" onClick={() => setBrowserOpen(true)} style={{ padding: '8px 12px' }}>
            Browse...
          </button>
          <button className="btn btn-primary" onClick={openDump} disabled={!!loading}>
            {loading ? 'Loading...' : 'Open'}
          </button>
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--accent)' }}>{loading}</div>}
        {error && <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 8 }}>{error}</div>}

        <FileBrowser
          open={browserOpen}
          onClose={() => setBrowserOpen(false)}
          onSelect={(selected) => { setPath(selected); setBrowserOpen(false); }}
          title="Select Memory Dump"
        />
      </div>
    );
  }

  const tabs = [
    { id: 'pslist', label: 'Processes', count: pslist.length },
    { id: 'netscan', label: 'Network', count: netscan.length },
    { id: 'malfind', label: 'Malfind', count: malfind.length },
    { id: 'cmdline', label: 'Cmdline', count: cmdline.length },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface)',
        padding: '0 16px', alignItems: 'center', gap: 4,
      }}>
        {tabs.map(t => (
          <div key={t.id}
            onClick={() => { setActiveTab(t.id); if ((t.id === 'netscan' && !netscan.length) || (t.id === 'malfind' && !malfind.length) || (t.id === 'cmdline' && !cmdline.length)) loadPlugin(t.id); }}
            style={{
              padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              borderBottom: `2px solid ${activeTab === t.id ? 'var(--accent)' : 'transparent'}`,
              color: activeTab === t.id ? 'var(--accent)' : 'var(--text-dim)',
            }}>
            {t.label} {t.count > 0 && <span style={{ fontSize: 10, opacity: 0.7 }}>({t.count})</span>}
          </div>
        ))}
        <div style={{ flex: 1 }} />
        {loading && <span style={{ fontSize: 11, color: 'var(--accent)' }}>{loading}</span>}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {activeTab === 'pslist' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr>
              <th style={thS}>PID</th><th style={thS}>PPID</th><th style={thS}>Name</th>
              <th style={thS}>Threads</th><th style={thS}>Handles</th><th style={thS}>Create Time</th>
            </tr></thead>
            <tbody>
              {pslist.map((p, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={tdS}>{p.PID}</td><td style={tdS}>{p.PPID}</td>
                  <td style={{ ...tdS, fontWeight: 600 }}>{p.ImageFileName}</td>
                  <td style={tdS}>{p.Threads}</td><td style={tdS}>{p.Handles}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11 }}>{p.CreateTime}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'netscan' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr>
              <th style={thS}>Proto</th><th style={thS}>Local</th><th style={thS}>Remote</th>
              <th style={thS}>State</th><th style={thS}>PID</th><th style={thS}>Owner</th>
            </tr></thead>
            <tbody>
              {netscan.map((n, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={tdS}>{n.Proto}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{n.LocalAddr}:{n.LocalPort}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{n.ForeignAddr}:{n.ForeignPort}</td>
                  <td style={tdS}><span className={`badge badge-${n.State === 'ESTABLISHED' ? 'high' : n.State === 'LISTENING' ? 'medium' : 'info'}`}>{n.State}</span></td>
                  <td style={tdS}>{n.PID}</td>
                  <td style={tdS}>{n.Owner}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'malfind' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr>
              <th style={thS}>PID</th><th style={thS}>Process</th><th style={thS}>Address</th>
              <th style={thS}>Protection</th><th style={thS}>Tag</th>
            </tr></thead>
            <tbody>
              {malfind.map((m, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={tdS}>{m.PID}</td>
                  <td style={{ ...tdS, fontWeight: 600 }}>{m.Process}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{m['Start VPN']}</td>
                  <td style={tdS}><span className="badge badge-critical">{m.Protection}</span></td>
                  <td style={tdS}>{m.Tag}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'cmdline' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>PID</th><th style={thS}>Process</th><th style={thS}>Command Line</th></tr></thead>
            <tbody>
              {cmdline.map((c, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={tdS}>{c.PID}</td>
                  <td style={{ ...tdS, fontWeight: 600 }}>{c.Process}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11, wordBreak: 'break-all' }}>{c.Args}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const thS: React.CSSProperties = { padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)', borderBottom: '2px solid var(--border)', position: 'sticky', top: 0 };
const tdS: React.CSSProperties = { padding: '6px 12px' };
