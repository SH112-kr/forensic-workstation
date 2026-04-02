import { useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

export default function RegistryAnalysis() {
  const [connected, setConnected] = useState(false);
  const [path, setPath] = useState('');
  const [meta, setMeta] = useState<any>(null);
  const [loading, setLoading] = useState('');
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [plugins, setPlugins] = useState<any>(null);
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [activeTab, setActiveTab] = useState('plugins');

  const openHive = async () => {
    if (!path.trim()) return;
    setLoading('Opening registry hive...');
    setError('');
    try {
      const data = await post('/api/registry/open', { path: path.trim() });
      setMeta(data);
      setConnected(true);
      setLoading('Running plugins...');
      const p = await get('/api/registry/plugins');
      setPlugins(p);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const search = async () => {
    if (!searchKeyword.trim()) return;
    setLoading('Searching...');
    try {
      const data = await get(`/api/registry/search?keyword=${encodeURIComponent(searchKeyword)}&limit=50`);
      setSearchResults(data.entries || []);
      setActiveTab('search');
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  if (!connected) {
    return (
      <div style={{ padding: 40, maxWidth: 500, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 16 }}>Registry Analysis (regipy)</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input type="text" value={path} onChange={e => setPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && openHive()}
            placeholder="Path to hive (NTUSER.DAT, SAM, SYSTEM, SOFTWARE)"
            style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
          <button className="btn" onClick={() => setBrowserOpen(true)}>Browse</button>
          <button className="btn btn-primary" onClick={openHive} disabled={!!loading}>Open</button>
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--accent)' }}>{loading}</div>}
        {error && <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 8 }}>{error}</div>}
        <FileBrowser open={browserOpen} onClose={() => setBrowserOpen(false)}
          onSelect={(p) => { setPath(p); setBrowserOpen(false); }} title="Select Registry Hive" />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--surface)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>{meta?.hive_type || 'Registry'}</span>
        <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>{meta?.file}</span>
        <div style={{ flex: 1 }} />
        <input type="text" value={searchKeyword} onChange={e => setSearchKeyword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()} placeholder="Search keys/values..."
          style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, width: 200 }} />
        <button className="btn btn-sm" onClick={search}>Search</button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface)', padding: '0 16px' }}>
        {['plugins', 'search'].map(t => (
          <div key={t} onClick={() => setActiveTab(t)} style={{
            padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
            borderBottom: `2px solid ${activeTab === t ? 'var(--accent)' : 'transparent'}`,
            color: activeTab === t ? 'var(--accent)' : 'var(--text-dim)', textTransform: 'capitalize',
          }}>{t}</div>
        ))}
        {loading && <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--accent)', alignSelf: 'center' }}>{loading}</span>}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
        {activeTab === 'plugins' && plugins && (
          <>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>
              {plugins.plugins_run} plugins executed
            </div>
            {Object.entries(plugins.results || {}).map(([name, entries]: [string, any]) => (
              <div key={name} style={{ marginBottom: 16 }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)', marginBottom: 8 }}>
                  {name} ({Array.isArray(entries) ? entries.length : 1})
                </h3>
                {Array.isArray(entries) ? entries.slice(0, 20).map((entry: any, i: number) => (
                  <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border-light)', fontSize: 12 }}>
                    {typeof entry === 'object' ? (
                      Object.entries(entry).slice(0, 5).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 12 }}>
                          <span style={{ color: 'var(--text-dim)' }}>{k}:</span> {String(v).slice(0, 100)}
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
              <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border-light)', fontSize: 12 }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)', marginBottom: 4 }}>{entry.path}</div>
                {(entry.values || []).slice(0, 5).map((v: any, j: number) => (
                  <div key={j} style={{ paddingLeft: 12, fontSize: 11 }}>
                    <span style={{ color: 'var(--text-dim)' }}>{v.name}:</span> {String(v.value).slice(0, 150)}
                  </div>
                ))}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
