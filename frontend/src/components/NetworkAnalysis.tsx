import { useEffect, useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

type TabKey = 'conversations' | 'dns' | 'http' | 'iocs';

interface Status {
  pyshark_available: boolean;
  loaded: boolean;
  metadata: any | null;
  install_hint: string | null;
}

export default function NetworkAnalysis() {
  const [status, setStatus] = useState<Status | null>(null);
  const [path, setPath] = useState('');
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [conversations, setConversations] = useState<any[]>([]);
  const [dns, setDns] = useState<any[]>([]);
  const [http, setHttp] = useState<any[]>([]);
  const [iocs, setIocs] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<TabKey>('conversations');
  const [tabLoading, setTabLoading] = useState<TabKey | ''>('');
  const [tabError, setTabError] = useState('');

  useEffect(() => {
    get('/api/network/status').then(setStatus).catch(() => setStatus({
      pyshark_available: false,
      loaded: false,
      metadata: null,
      install_hint: 'Status endpoint failed — check the backend log.',
    }));
  }, []);

  useEffect(() => {
    if (status?.loaded && conversations.length === 0) loadTab('conversations');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.loaded]);

  const openPcap = async () => {
    if (!path.trim()) return;
    setOpening(true);
    setOpenError('');
    try {
      await post('/api/network/open', { path: path.trim() });
      const s = await get('/api/network/status');
      setStatus(s);
    } catch (e: any) {
      setOpenError(e?.message || 'Failed to open PCAP');
    } finally {
      setOpening(false);
    }
  };

  const loadTab = async (tab: TabKey) => {
    setActiveTab(tab);
    const alreadyLoaded =
      (tab === 'conversations' && conversations.length > 0) ||
      (tab === 'dns' && dns.length > 0) ||
      (tab === 'http' && http.length > 0) ||
      (tab === 'iocs' && iocs !== null);
    if (alreadyLoaded) return;
    setTabLoading(tab);
    setTabError('');
    try {
      if (tab === 'conversations') {
        const r = await get('/api/network/conversations');
        setConversations(r.conversations || []);
      } else if (tab === 'dns') {
        const r = await get('/api/network/dns');
        setDns(r.dns_queries || []);
      } else if (tab === 'http') {
        const r = await get('/api/network/http');
        setHttp(r.http_requests || []);
      } else if (tab === 'iocs') {
        const r = await get('/api/network/iocs');
        setIocs(r);
      }
    } catch (e: any) {
      setTabError(e?.message || `Failed to load ${tab}`);
    } finally {
      setTabLoading('');
    }
  };

  if (!status) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
        <span className="spinner" aria-hidden="true" /> Checking network analysis status…
      </div>
    );
  }

  // Dependency missing — show install guidance, no upload form.
  if (!status.pyshark_available) {
    return (
      <div style={{ padding: 40, maxWidth: 620, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 10 }}>Network Analysis</h2>
        <div style={{
          padding: '14px 18px', borderRadius: 10,
          background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
          fontSize: 13, color: 'var(--text)',
        }}>
          <div style={{ fontWeight: 700, color: '#f59e0b', marginBottom: 6 }}>
            pyshark is not installed
          </div>
          <div className="help-text" style={{ marginBottom: 10 }}>
            {status.install_hint || 'Install pyshark to enable PCAP parsing.'}
          </div>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: 12, padding: '8px 10px',
            borderRadius: 6, background: 'var(--bg)', border: '1px solid var(--border)',
          }}>
            pip install pyshark<br />
            {/* Wireshark / tshark is required for live parsing */}
            # plus install Wireshark (provides tshark) from https://www.wireshark.org
          </div>
          <div className="help-text" style={{ marginTop: 10 }}>
            After installation, restart the backend (python backend/main.py) and reload this view.
          </div>
        </div>
      </div>
    );
  }

  if (!status.loaded) {
    return (
      <div style={{ padding: 40, maxWidth: 560, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 4 }}>Network Analysis (PyShark)</h2>
        <div className="help-text" style={{ marginBottom: 12 }}>
          Load a .pcap or .pcapng capture. All processing happens locally — no packets leave this machine.
        </div>
        <div className="field">
          <label className="label" htmlFor="fw-pcap-path">PCAP path</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              id="fw-pcap-path"
              className={`input input-mono${openError ? ' input-invalid' : ''}`}
              style={{ flex: 1 }}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && openPcap()}
              placeholder="C:\\captures\\traffic.pcapng"
              aria-invalid={!!openError}
              aria-describedby={openError ? 'fw-pcap-err' : undefined}
            />
            <button className="btn" onClick={() => setBrowserOpen(true)}>Browse…</button>
            <button
              className="btn btn-primary"
              onClick={openPcap}
              disabled={opening || !path.trim()}
              aria-busy={opening}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            >
              {opening && <span className="spinner spinner-sm" aria-hidden="true" />}
              {opening ? 'Opening…' : 'Open'}
            </button>
          </div>
          {openError && <span id="fw-pcap-err" className="field-error" role="alert">{openError}</span>}
        </div>
        <FileBrowser
          open={browserOpen}
          onClose={() => setBrowserOpen(false)}
          onSelect={(p) => { setPath(p); setBrowserOpen(false); }}
          title="Select PCAP"
        />
      </div>
    );
  }

  const tabs: { id: TabKey; label: string; count?: number }[] = [
    { id: 'conversations', label: 'Flows', count: conversations.length },
    { id: 'dns', label: 'DNS', count: dns.length },
    { id: 'http', label: 'HTTP', count: http.length },
    { id: 'iocs', label: 'IOCs', count: iocs ? (iocs.total_ips || 0) + (iocs.total_domains || 0) : 0 },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {status.metadata && (
        <div style={{
          padding: '6px 16px', background: 'var(--surface)',
          borderBottom: '1px solid var(--border-light)',
          fontSize: 11, color: 'var(--text-dim)',
        }}>
          <span style={{ fontFamily: 'var(--mono)' }}>{status.metadata.path || status.metadata.file}</span>
        </div>
      )}
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface)',
        padding: '0 16px', alignItems: 'center', gap: 4,
      }}>
        {tabs.map((t) => (
          <div
            key={t.id}
            onClick={() => loadTab(t.id)}
            style={{
              padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              borderBottom: `2px solid ${activeTab === t.id ? 'var(--accent)' : 'transparent'}`,
              color: activeTab === t.id ? 'var(--accent)' : 'var(--text-dim)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
            role="tab" aria-selected={activeTab === t.id} tabIndex={0}
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && loadTab(t.id)}
          >
            {t.label}
            {tabLoading === t.id && <span className="spinner spinner-sm" aria-hidden="true" />}
            {typeof t.count === 'number' && t.count > 0 && <span style={{ fontSize: 10, opacity: 0.7 }}>({t.count})</span>}
          </div>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {tabError && (
          <div role="alert" style={{
            margin: 16, padding: '10px 14px', borderRadius: 8,
            background: 'var(--critical-bg)', color: 'var(--critical)',
            border: '1px solid var(--critical)', fontSize: 12,
          }}>
            {tabError}
          </div>
        )}
        {activeTab === 'conversations' && (
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>Source</th><th style={thS}>Destination</th>
              <th style={thS}>Proto</th><th style={thS}>Packets</th><th style={thS}>Bytes</th>
            </tr></thead>
            <tbody>
              {conversations.map((c, i) => (
                <tr key={i} style={trS}>
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
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>Query</th><th style={thS}>Type</th>
              <th style={thS}>Response</th><th style={thS}>Time</th>
            </tr></thead>
            <tbody>
              {dns.map((d, i) => (
                <tr key={i} style={trS}>
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
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>Method</th><th style={thS}>Host</th><th style={thS}>URI</th>
              <th style={thS}>Source</th><th style={thS}>Time</th>
            </tr></thead>
            <tbody>
              {http.map((h, i) => (
                <tr key={i} style={trS}>
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
                <div style={{ marginTop: 8, maxHeight: 240, overflowY: 'auto' }}>
                  {(iocs.unique_ips || []).map((ip: string) => (
                    <div key={ip} style={{ fontFamily: 'var(--mono)', fontSize: 12, padding: '2px 0' }}>{ip}</div>
                  ))}
                </div>
              </div>
              <div className="card">
                <div className="card-label">Unique Domains ({iocs.total_domains})</div>
                <div style={{ marginTop: 8, maxHeight: 240, overflowY: 'auto' }}>
                  {(iocs.unique_domains || []).map((d: string) => (
                    <div key={d} style={{ fontFamily: 'var(--mono)', fontSize: 12, padding: '2px 0' }}>{d}</div>
                  ))}
                </div>
              </div>
              {iocs.unique_urls && iocs.unique_urls.length > 0 && (
                <div className="card">
                  <div className="card-label">URLs ({iocs.total_urls})</div>
                  <div style={{ marginTop: 8, maxHeight: 240, overflowY: 'auto' }}>
                    {iocs.unique_urls.map((u: string) => (
                      <div key={u} style={{ fontFamily: 'var(--mono)', fontSize: 12, padding: '2px 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const tableS: React.CSSProperties = { width: '100%', borderCollapse: 'collapse', fontSize: 12 };
const thS: React.CSSProperties = {
  padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11,
  textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)',
  borderBottom: '2px solid var(--border)', position: 'sticky', top: 0,
};
const tdS: React.CSSProperties = { padding: '6px 12px' };
const trS: React.CSSProperties = { borderBottom: '1px solid var(--border-light)' };
