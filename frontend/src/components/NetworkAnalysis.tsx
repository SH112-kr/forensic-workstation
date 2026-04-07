import { useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

export default function NetworkAnalysis() {
  const [connected, setConnected] = useState(false);
  const [path, setPath] = useState('');
  const [loading, setLoading] = useState('');
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [conversations, setConversations] = useState<any[]>([]);
  const [dns, setDns] = useState<any[]>([]);
  const [http, setHttp] = useState<any[]>([]);
  const [iocs, setIocs] = useState<any>(null);
  const [activeTab, setActiveTab] = useState('conversations');

  const openPcap = async () => {
    if (!path.trim()) return;
    setLoading('Opening PCAP...');
    setError('');
    try {
      await post('/api/network/open', { path: path.trim() });
      setConnected(true);
      loadTab('conversations');
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const loadTab = async (tab: string) => {
    setActiveTab(tab);
    const needsFetch =
      (tab === 'conversations' && !conversations.length) ||
      (tab === 'dns' && !dns.length) ||
      (tab === 'http' && !http.length) ||
      (tab === 'iocs' && !iocs);
    if (!needsFetch) return;
    setLoading(`Loading ${tab}...`);
    try {
      if (tab === 'conversations' && !conversations.length) {
        const r = await get('/api/network/conversations');
        setConversations(r.conversations || []);
      } else if (tab === 'dns' && !dns.length) {
        const r = await get('/api/network/dns');
        setDns(r.dns_queries || []);
      } else if (tab === 'http' && !http.length) {
        const r = await get('/api/network/http');
        setHttp(r.http_requests || []);
      } else if (tab === 'iocs' && !iocs) {
        const r = await get('/api/network/iocs');
        setIocs(r);
      }
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  if (!connected) {
    return (
      <div style={{ padding: 40, maxWidth: 500, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 16 }}>Network Analysis (PyShark)</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input type="text" value={path} onChange={e => setPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && openPcap()}
            placeholder="Path to .pcap or .pcapng file"
            style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
          <button className="btn" onClick={() => setBrowserOpen(true)}>Browse</button>
          <button className="btn btn-primary" onClick={openPcap} disabled={!!loading}>Open</button>
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--accent)' }}>{loading}</div>}
        {error && <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 8 }}>{error}</div>}
        <FileBrowser open={browserOpen} onClose={() => setBrowserOpen(false)}
          onSelect={(p) => { setPath(p); setBrowserOpen(false); }} title="Select PCAP" />
      </div>
    );
  }

  const tabs = [
    { id: 'conversations', label: 'Flows', count: conversations.length },
    { id: 'dns', label: 'DNS', count: dns.length },
    { id: 'http', label: 'HTTP', count: http.length },
    { id: 'iocs', label: 'IOCs', count: iocs ? (iocs.total_ips || 0) + (iocs.total_domains || 0) : 0 },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface)', padding: '0 16px', alignItems: 'center' }}>
        {tabs.map(t => (
          <div key={t.id} onClick={() => loadTab(t.id)} style={{
            padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
            borderBottom: `2px solid ${activeTab === t.id ? 'var(--accent)' : 'transparent'}`,
            color: activeTab === t.id ? 'var(--accent)' : 'var(--text-dim)',
          }}>{t.label} {t.count > 0 && <span style={{ fontSize: 10, opacity: 0.7 }}>({t.count})</span>}</div>
        ))}
        {loading && <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--accent)' }}>{loading}</span>}
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {activeTab === 'conversations' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>Source</th><th style={thS}>Destination</th><th style={thS}>Proto</th><th style={thS}>Packets</th><th style={thS}>Bytes</th></tr></thead>
            <tbody>
              {conversations.map((c, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{c.src}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{c.dst}</td>
                  <td style={tdS}>{c.protocol}</td>
                  <td style={tdS}>{c.packets}</td>
                  <td style={tdS}>{c.bytes?.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'dns' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>Query</th><th style={thS}>Type</th><th style={thS}>Response</th><th style={thS}>Time</th></tr></thead>
            <tbody>
              {dns.map((d, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{d.query}</td>
                  <td style={tdS}>{d.type}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{d.response}</td>
                  <td style={{ ...tdS, fontSize: 11, color: 'var(--text-dim)' }}>{d.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'http' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>Method</th><th style={thS}>Host</th><th style={thS}>URI</th><th style={thS}>Source</th><th style={thS}>Time</th></tr></thead>
            <tbody>
              {http.map((h, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={tdS}><span className="badge badge-medium">{h.method}</span></td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{h.host}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>{h.uri}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11 }}>{h.src}</td>
                  <td style={{ ...tdS, fontSize: 11, color: 'var(--text-dim)' }}>{h.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'iocs' && iocs && (
          <div style={{ padding: 16 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 12 }}>
              <div className="card">
                <div className="card-label">Unique IPs ({iocs.total_ips})</div>
                <div style={{ marginTop: 8, maxHeight: 200, overflowY: 'auto' }}>
                  {(iocs.unique_ips || []).map((ip: string) => (
                    <div key={ip} style={{ fontFamily: 'var(--mono)', fontSize: 12, padding: '2px 0' }}>{ip}</div>
                  ))}
                </div>
              </div>
              <div className="card">
                <div className="card-label">Unique Domains ({iocs.total_domains})</div>
                <div style={{ marginTop: 8, maxHeight: 200, overflowY: 'auto' }}>
                  {(iocs.unique_domains || []).map((d: string) => (
                    <div key={d} style={{ fontFamily: 'var(--mono)', fontSize: 12, padding: '2px 0' }}>{d}</div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const thS: React.CSSProperties = { padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)', borderBottom: '2px solid var(--border)', position: 'sticky', top: 0 };
const tdS: React.CSSProperties = { padding: '6px 12px' };
