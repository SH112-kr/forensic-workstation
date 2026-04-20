import { useEffect, useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

type TabKey = 'pslist' | 'pstree' | 'netscan' | 'malfind' | 'cmdline';

interface PluginState {
  loaded: boolean;
  rows: any[];
  loading: boolean;
  error: string;
}

const INITIAL_PLUGIN: PluginState = { loaded: false, rows: [], loading: false, error: '' };

export default function MemoryAnalysis() {
  const [connected, setConnected] = useState(false);
  const [meta, setMeta] = useState<any>(null);
  const [path, setPath] = useState('');
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [plugins, setPlugins] = useState<Record<TabKey, PluginState>>({
    pslist: { ...INITIAL_PLUGIN },
    pstree: { ...INITIAL_PLUGIN },
    netscan: { ...INITIAL_PLUGIN },
    malfind: { ...INITIAL_PLUGIN },
    cmdline: { ...INITIAL_PLUGIN },
  });
  const [activeTab, setActiveTab] = useState<TabKey>('pslist');

  useEffect(() => {
    get('/api/memory/status')
      .then((d) => {
        if (d && d.loaded) {
          setConnected(true);
          setMeta(d.metadata || null);
          loadPlugin('pslist');
        }
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const updatePlugin = (key: TabKey, patch: Partial<PluginState>) =>
    setPlugins((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }));

  const loadPlugin = async (key: TabKey) => {
    updatePlugin(key, { loading: true, error: '' });
    try {
      const r = await get(`/api/memory/${key}`);
      const rows =
        key === 'netscan' ? (r.connections || []) :
        key === 'malfind' ? (r.findings || []) :
        (r.processes || []);
      updatePlugin(key, { rows, loaded: true, loading: false });
    } catch (e: any) {
      updatePlugin(key, { loading: false, error: e?.message || 'Failed' });
    }
  };

  const openDump = async () => {
    if (!path.trim()) return;
    setOpening(true);
    setOpenError('');
    try {
      const m = await post('/api/memory/open', { path: path.trim() });
      setMeta(m);
      setConnected(true);
      loadPlugin('pslist');
    } catch (e: any) {
      setOpenError(e?.message || 'Failed to open memory dump');
    } finally {
      setOpening(false);
    }
  };

  if (!connected) {
    return (
      <div style={{ padding: 40, maxWidth: 560, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 4 }}>Memory Analysis (Volatility 3)</h2>
        <div className="help-text" style={{ marginBottom: 12 }}>
          Load a memory dump (.raw, .vmem, .dmp, .mem). Analysis runs fully offline through
          Volatility 3 — no external API call.
        </div>
        <div className="field">
          <label className="label" htmlFor="fw-mem-path">Memory dump path</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              id="fw-mem-path"
              className={`input input-mono${openError ? ' input-invalid' : ''}`}
              style={{ flex: 1 }}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && openDump()}
              placeholder="C:\\dumps\\memory.raw"
              aria-invalid={!!openError}
              aria-describedby={openError ? 'fw-mem-err' : undefined}
            />
            <button className="btn" onClick={() => setBrowserOpen(true)}>Browse…</button>
            <button
              className="btn btn-primary"
              onClick={openDump}
              disabled={opening || !path.trim()}
              aria-busy={opening}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            >
              {opening && <span className="spinner spinner-sm" aria-hidden="true" />}
              {opening ? 'Loading…' : 'Open'}
            </button>
          </div>
          {openError && (
            <span id="fw-mem-err" className="field-error" role="alert">
              {openError}
            </span>
          )}
        </div>

        <FileBrowser
          open={browserOpen}
          onClose={() => setBrowserOpen(false)}
          onSelect={(selected) => { setPath(selected); setBrowserOpen(false); }}
          title="Select Memory Dump"
        />
      </div>
    );
  }

  const tabs: { id: TabKey; label: string }[] = [
    { id: 'pslist', label: 'Processes' },
    { id: 'pstree', label: 'Process Tree' },
    { id: 'netscan', label: 'Network' },
    { id: 'cmdline', label: 'Cmdline' },
    { id: 'malfind', label: 'Malfind' },
  ];

  const selectTab = (id: TabKey) => {
    setActiveTab(id);
    const s = plugins[id];
    if (!s.loaded && !s.loading) loadPlugin(id);
  };

  const state = plugins[activeTab];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Metadata header */}
      {meta && (
        <div style={{
          padding: '6px 16px', background: 'var(--surface)',
          borderBottom: '1px solid var(--border-light)',
          fontSize: 11, color: 'var(--text-dim)',
          display: 'flex', gap: 16, flexWrap: 'wrap',
        }}>
          {meta.image_profile && <span>Profile: <strong style={{ color: 'var(--text)' }}>{meta.image_profile}</strong></span>}
          {meta.source_path && <span style={{ fontFamily: 'var(--mono)' }}>{meta.source_path}</span>}
        </div>
      )}

      {/* Tab bar */}
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface)',
        padding: '0 16px', alignItems: 'center', gap: 4,
      }}>
        {tabs.map((t) => {
          const s = plugins[t.id];
          return (
            <div key={t.id}
              onClick={() => selectTab(t.id)}
              style={{
                padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
                borderBottom: `2px solid ${activeTab === t.id ? 'var(--accent)' : 'transparent'}`,
                color: activeTab === t.id ? 'var(--accent)' : 'var(--text-dim)',
                display: 'flex', alignItems: 'center', gap: 6,
              }}
              role="tab"
              aria-selected={activeTab === t.id}
              tabIndex={0}
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && selectTab(t.id)}
            >
              {t.label}
              {s.loading && <span className="spinner spinner-sm" aria-hidden="true" />}
              {s.loaded && s.rows.length > 0 && (
                <span style={{ fontSize: 10, opacity: 0.7 }}>({s.rows.length})</span>
              )}
            </div>
          );
        })}
        <div style={{ flex: 1 }} />
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {state.loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
            <span className="spinner" aria-hidden="true" /> Running {activeTab}…
            <div className="help-text" style={{ marginTop: 10 }}>
              Large dumps can take minutes. Timeout is managed by FW_TIMEOUT_MEDIUM (default 600s).
            </div>
          </div>
        )}
        {state.error && (
          <div role="alert" style={{
            margin: 16, padding: '10px 14px', borderRadius: 8,
            background: 'var(--critical-bg)', color: 'var(--critical)',
            border: '1px solid var(--critical)', fontSize: 12,
          }}>
            {state.error}
          </div>
        )}
        {!state.loading && !state.error && state.loaded && state.rows.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
            No rows returned by {activeTab}.
          </div>
        )}

        {activeTab === 'pslist' && state.rows.length > 0 && (
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>PID</th><th style={thS}>PPID</th><th style={thS}>Name</th>
              <th style={thS}>Threads</th><th style={thS}>Handles</th><th style={thS}>Create Time</th>
            </tr></thead>
            <tbody>
              {state.rows.map((p, i) => (
                <tr key={i} style={trS}>
                  <td style={tdS}>{p.PID}</td><td style={tdS}>{p.PPID}</td>
                  <td style={{ ...tdS, fontWeight: 600 }}>{p.ImageFileName}</td>
                  <td style={tdS}>{p.Threads}</td><td style={tdS}>{p.Handles}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11 }}>{p.CreateTime}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'pstree' && state.rows.length > 0 && (
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>PID</th><th style={thS}>PPID</th><th style={thS}>Name</th>
              <th style={thS}>Create Time</th>
            </tr></thead>
            <tbody>
              {state.rows.map((p, i) => {
                const depth = typeof p.Depth === 'number' ? p.Depth : (p.Indent || 0);
                return (
                  <tr key={i} style={trS}>
                    <td style={tdS}>{p.PID}</td>
                    <td style={tdS}>{p.PPID}</td>
                    <td style={{ ...tdS, fontWeight: 600, paddingLeft: 12 + depth * 18 }}>
                      {depth > 0 && <span style={{ color: 'var(--text-dim)', marginRight: 6 }}>└─</span>}
                      {p.ImageFileName}
                    </td>
                    <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11 }}>{p.CreateTime}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {activeTab === 'netscan' && state.rows.length > 0 && (
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>Proto</th><th style={thS}>Local</th><th style={thS}>Remote</th>
              <th style={thS}>State</th><th style={thS}>PID</th><th style={thS}>Owner</th>
            </tr></thead>
            <tbody>
              {state.rows.map((n, i) => (
                <tr key={i} style={trS}>
                  <td style={tdS}>{n.Proto}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{n.LocalAddr}:{n.LocalPort}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{n.ForeignAddr}:{n.ForeignPort}</td>
                  <td style={tdS}>
                    <span className={`badge badge-${n.State === 'ESTABLISHED' ? 'high' : n.State === 'LISTENING' ? 'medium' : 'info'}`}>{n.State}</span>
                  </td>
                  <td style={tdS}>{n.PID}</td>
                  <td style={tdS}>{n.Owner}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'malfind' && state.rows.length > 0 && (
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>PID</th><th style={thS}>Process</th><th style={thS}>Address</th>
              <th style={thS}>Protection</th><th style={thS}>Tag</th>
            </tr></thead>
            <tbody>
              {state.rows.map((m, i) => (
                <tr key={i} style={trS}>
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

        {activeTab === 'cmdline' && state.rows.length > 0 && (
          <table style={tableS}>
            <thead><tr>
              <th style={thS}>PID</th><th style={thS}>Process</th><th style={thS}>Command Line</th>
            </tr></thead>
            <tbody>
              {state.rows.map((c, i) => (
                <tr key={i} style={trS}>
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

const tableS: React.CSSProperties = { width: '100%', borderCollapse: 'collapse', fontSize: 12 };
const thS: React.CSSProperties = {
  padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11,
  textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)',
  borderBottom: '2px solid var(--border)', position: 'sticky', top: 0,
};
const tdS: React.CSSProperties = { padding: '6px 12px' };
const trS: React.CSSProperties = { borderBottom: '1px solid var(--border-light)' };
