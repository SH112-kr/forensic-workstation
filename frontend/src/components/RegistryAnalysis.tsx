import { useEffect, useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

type TabKey = 'plugins' | 'search' | 'timeline';

interface Status {
  regipy_available: boolean;
  loaded: boolean;
  metadata: any | null;
  install_hint: string | null;
}

export default function RegistryAnalysis() {
  const [status, setStatus] = useState<Status | null>(null);
  const [path, setPath] = useState('');
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [plugins, setPlugins] = useState<any>(null);
  const [timelineEntries, setTimelineEntries] = useState<any[]>([]);
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [activeTab, setActiveTab] = useState<TabKey>('plugins');
  const [tabLoading, setTabLoading] = useState<TabKey | ''>('');
  const [tabError, setTabError] = useState('');

  useEffect(() => {
    get('/api/registry/status').then(setStatus).catch(() => setStatus({
      regipy_available: false, loaded: false, metadata: null,
      install_hint: 'Status endpoint failed — check the backend log.',
    }));
  }, []);

  useEffect(() => {
    if (status?.loaded && !plugins && !tabLoading) {
      loadTab('plugins');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.loaded]);

  const openHive = async () => {
    if (!path.trim()) return;
    setOpening(true);
    setOpenError('');
    try {
      await post('/api/registry/open', { path: path.trim() });
      const s = await get('/api/registry/status');
      setStatus(s);
    } catch (e: any) {
      setOpenError(e?.message || 'Failed to open hive');
    } finally {
      setOpening(false);
    }
  };

  const loadTab = async (tab: TabKey) => {
    setActiveTab(tab);
    if (tab === 'plugins' && plugins) return;
    if (tab === 'timeline' && timelineEntries.length > 0) return;
    setTabLoading(tab);
    setTabError('');
    try {
      if (tab === 'plugins') {
        const r = await get('/api/registry/plugins');
        setPlugins(r);
      } else if (tab === 'timeline') {
        const r = await get('/api/registry/timeline?limit=300');
        setTimelineEntries(r.entries || []);
      }
    } catch (e: any) {
      setTabError(e?.message || `Failed to load ${tab}`);
    } finally {
      setTabLoading('');
    }
  };

  const runSearch = async () => {
    const kw = searchKeyword.trim();
    if (!kw) return;
    setActiveTab('search');
    setTabLoading('search');
    setTabError('');
    try {
      const r = await get(`/api/registry/search?keyword=${encodeURIComponent(kw)}&limit=100`);
      setSearchResults(r.entries || []);
    } catch (e: any) {
      setTabError(e?.message || 'Search failed');
    } finally {
      setTabLoading('');
    }
  };

  if (!status) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
        <span className="spinner" aria-hidden="true" /> Checking registry analysis status…
      </div>
    );
  }

  if (!status.regipy_available) {
    return (
      <div style={{ padding: 40, maxWidth: 620, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 10 }}>Registry Analysis</h2>
        <div style={{
          padding: '14px 18px', borderRadius: 10,
          background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
          fontSize: 13, color: 'var(--text)',
        }}>
          <div style={{ fontWeight: 700, color: '#f59e0b', marginBottom: 6 }}>regipy is not installed</div>
          <div className="help-text" style={{ marginBottom: 10 }}>
            {status.install_hint || 'Install regipy to enable hive parsing.'}
          </div>
          <div style={{
            fontFamily: 'var(--mono)', fontSize: 12, padding: '8px 10px',
            borderRadius: 6, background: 'var(--bg)', border: '1px solid var(--border)',
          }}>
            pip install regipy
          </div>
          <div className="help-text" style={{ marginTop: 10 }}>
            After installation, restart the backend and reload this view.
          </div>
        </div>
      </div>
    );
  }

  if (!status.loaded) {
    return (
      <div style={{ padding: 40, maxWidth: 560, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 4 }}>Registry Analysis (regipy)</h2>
        <div className="help-text" style={{ marginBottom: 12 }}>
          Load a registry hive (NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY, UsrClass.dat, Amcache.hve).
          All parsing happens locally — nothing leaves this machine.
        </div>
        <div className="field">
          <label className="label" htmlFor="fw-reg-path">Hive path</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              id="fw-reg-path"
              className={`input input-mono${openError ? ' input-invalid' : ''}`}
              style={{ flex: 1 }}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && openHive()}
              placeholder="C:\\Windows\\System32\\config\\SOFTWARE"
              aria-invalid={!!openError}
              aria-describedby={openError ? 'fw-reg-err' : undefined}
            />
            <button className="btn" onClick={() => setBrowserOpen(true)}>Browse…</button>
            <button
              className="btn btn-primary"
              onClick={openHive}
              disabled={opening || !path.trim()}
              aria-busy={opening}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            >
              {opening && <span className="spinner spinner-sm" aria-hidden="true" />}
              {opening ? 'Opening…' : 'Open'}
            </button>
          </div>
          {openError && <span id="fw-reg-err" className="field-error" role="alert">{openError}</span>}
        </div>
        <FileBrowser
          open={browserOpen}
          onClose={() => setBrowserOpen(false)}
          onSelect={(p) => { setPath(p); setBrowserOpen(false); }}
          title="Select Registry Hive"
        />
      </div>
    );
  }

  const meta = status.metadata || {};
  const tabs: { id: TabKey; label: string; count?: number }[] = [
    { id: 'plugins', label: 'Plugins', count: plugins ? plugins.plugins_run : undefined },
    { id: 'search', label: 'Search', count: searchResults.length },
    { id: 'timeline', label: 'Timeline', count: timelineEntries.length },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{
        padding: '10px 16px', borderBottom: '1px solid var(--border)',
        background: 'var(--surface)', display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>{meta.hive_type || 'Registry'}</span>
        <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>
          {meta.file || meta.path}
        </span>
        <div style={{ flex: 1 }} />
        <label className="label" htmlFor="fw-reg-search" style={{ margin: 0 }}>Search</label>
        <input
          id="fw-reg-search"
          className="input input-sm"
          style={{ width: 220 }}
          value={searchKeyword}
          onChange={(e) => setSearchKeyword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runSearch()}
          placeholder="key name, value, or path substring"
        />
        <button className="btn btn-sm" onClick={runSearch} disabled={!searchKeyword.trim()}>Search</button>
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)',
        background: 'var(--surface)', padding: '0 16px', alignItems: 'center', gap: 4,
      }}>
        {tabs.map((t) => (
          <div
            key={t.id}
            onClick={() => loadTab(t.id)}
            style={{
              padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              borderBottom: `2px solid ${activeTab === t.id ? 'var(--accent)' : 'transparent'}`,
              color: activeTab === t.id ? 'var(--accent)' : 'var(--text-dim)',
              textTransform: 'capitalize',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
            role="tab" aria-selected={activeTab === t.id} tabIndex={0}
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && loadTab(t.id)}
          >
            {t.label}
            {tabLoading === t.id && <span className="spinner spinner-sm" aria-hidden="true" />}
            {typeof t.count === 'number' && t.count > 0 && (
              <span style={{ fontSize: 10, opacity: 0.7 }}>({t.count})</span>
            )}
          </div>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
        {tabError && (
          <div role="alert" style={{
            padding: '10px 14px', borderRadius: 8, marginBottom: 12,
            background: 'var(--critical-bg)', color: 'var(--critical)',
            border: '1px solid var(--critical)', fontSize: 12,
          }}>
            {tabError}
          </div>
        )}

        {activeTab === 'plugins' && plugins && (
          <>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
              {plugins.plugins_run} plugins executed on {plugins.hive_type}.
              {plugins.errors?.length > 0 && (
                <span style={{ color: 'var(--high)', marginLeft: 8 }}>
                  {plugins.errors.length} errors — see browser console for details.
                </span>
              )}
            </div>
            {Object.entries(plugins.results || {}).map(([name, entries]: [string, any]) => (
              <div key={name} style={{ marginBottom: 16 }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)', marginBottom: 8 }}>
                  {name} ({Array.isArray(entries) ? entries.length : 1})
                </h3>
                {Array.isArray(entries) ? entries.slice(0, 20).map((entry: any, i: number) => (
                  <div key={i} style={{
                    padding: '6px 0', borderBottom: '1px solid var(--border-light)',
                    fontSize: 12, fontFamily: 'var(--mono)',
                  }}>
                    {typeof entry === 'object' ? (
                      Object.entries(entry).slice(0, 5).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 12 }}>
                          <span style={{ color: 'var(--text-dim)' }}>{k}:</span> {String(v).slice(0, 120)}
                        </span>
                      ))
                    ) : String(entry)}
                  </div>
                )) : <div style={{ fontSize: 12 }}>{JSON.stringify(entries).slice(0, 300)}</div>}
              </div>
            ))}
          </>
        )}

        {activeTab === 'search' && (
          <>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
              {searchResults.length} results for "{searchKeyword}"
            </div>
            {searchResults.map((entry, i) => (
              <div key={i} style={{
                padding: '8px 0', borderBottom: '1px solid var(--border-light)', fontSize: 12,
              }}>
                <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)' }}>
                    {entry.path}
                  </span>
                  {entry.timestamp && (
                    <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>
                      {String(entry.timestamp).slice(0, 19)}
                    </span>
                  )}
                </div>
                {(entry.values || []).slice(0, 8).map((v: any, j: number) => (
                  <div key={j} style={{ paddingLeft: 12, fontSize: 11, fontFamily: 'var(--mono)' }}>
                    <span style={{ color: 'var(--text-dim)' }}>{v.name}:</span>{' '}
                    {String(v.value).slice(0, 200)}
                  </div>
                ))}
              </div>
            ))}
          </>
        )}

        {activeTab === 'timeline' && (
          <>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
              Keys sorted by Last Write time (most recent first). Useful for isolating recent persistence or service
              changes without guessing which keys to inspect.
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={thS}>Last Write</th>
                  <th style={thS}>Path</th>
                  <th style={thS}>Values</th>
                </tr>
              </thead>
              <tbody>
                {timelineEntries.map((e, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                    <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' }}>
                      {String(e.timestamp).slice(0, 19)}
                    </td>
                    <td style={{ ...tdS, fontFamily: 'var(--mono)', fontSize: 11 }}>{e.path}</td>
                    <td style={{ ...tdS, textAlign: 'right' }}>{e.values_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}

const thS: React.CSSProperties = {
  padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11,
  textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)',
  borderBottom: '2px solid var(--border)', position: 'sticky', top: 0,
};
const tdS: React.CSSProperties = { padding: '6px 12px' };
