import { useState } from 'react';
import { post, get } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

export default function BinaryAnalysis() {
  const [connected, setConnected] = useState(false);
  const [path, setPath] = useState('');
  const [meta, setMeta] = useState<any>(null);
  const [loading, setLoading] = useState('');
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState(false);

  const [functions, setFunctions] = useState<any[]>([]);
  const [imports, setImports] = useState<any>(null);
  const [suspicious, setSuspicious] = useState<any>(null);
  const [strings, setStrings] = useState<any[]>([]);
  const [decompiled, setDecompiled] = useState<any>(null);
  const [activeTab, setActiveTab] = useState('overview');

  const analyze = async () => {
    if (!path.trim()) return;
    setLoading('Analyzing binary (this may take 1-3 minutes)...');
    setError('');
    try {
      const data = await post('/api/binary/analyze', { path: path.trim() });
      setMeta(data);
      setConnected(true);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const loadTab = async (tab: string) => {
    setActiveTab(tab);
    // Skip loading indicator if data already cached
    const needsFetch =
      (tab === 'functions' && !functions.length) ||
      (tab === 'imports' && !imports) ||
      (tab === 'suspicious' && !suspicious) ||
      (tab === 'strings' && !strings.length);
    if (!needsFetch) return;
    setLoading(`Loading ${tab}...`);
    try {
      if (tab === 'functions' && !functions.length) {
        const r = await get('/api/binary/functions');
        setFunctions(r.functions || []);
      } else if (tab === 'imports' && !imports) {
        const r = await get('/api/binary/imports');
        setImports(r);
      } else if (tab === 'suspicious' && !suspicious) {
        const r = await get('/api/binary/suspicious');
        setSuspicious(r);
      } else if (tab === 'strings' && !strings.length) {
        const r = await get('/api/binary/strings');
        setStrings(r.strings || []);
      }
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const decompile = async (addr: string) => {
    setLoading('Decompiling...');
    try {
      const r = await post('/api/binary/decompile', { address: addr });
      setDecompiled(r);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  if (!connected) {
    return (
      <div style={{ padding: 40, maxWidth: 500, margin: '0 auto' }}>
        <h2 style={{ fontSize: 16, marginBottom: 16 }}>Binary Analysis (Ghidra)</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input type="text" value={path} onChange={e => setPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && analyze()}
            placeholder="Path to binary (.exe, .dll, .sys)"
            style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
          <button className="btn" onClick={() => setBrowserOpen(true)} style={{ padding: '8px 12px' }}>
            Browse...
          </button>
          <button className="btn btn-primary" onClick={analyze} disabled={!!loading}>
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </div>
        {loading && <div style={{ fontSize: 12, color: 'var(--accent)' }}>{loading}</div>}
        {error && <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 8 }}>{error}</div>}

        <FileBrowser
          open={browserOpen}
          onClose={() => setBrowserOpen(false)}
          onSelect={(selected) => { setPath(selected); setBrowserOpen(false); }}
          title="Select Binary"
        />
      </div>
    );
  }

  const tabs = ['overview', 'functions', 'imports', 'suspicious', 'strings'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface)',
        padding: '0 16px', alignItems: 'center', gap: 4,
      }}>
        {tabs.map(t => (
          <div key={t}
            onClick={() => loadTab(t)}
            style={{
              padding: '10px 16px', cursor: 'pointer', fontSize: 12, fontWeight: 500,
              borderBottom: `2px solid ${activeTab === t ? 'var(--accent)' : 'transparent'}`,
              color: activeTab === t ? 'var(--accent)' : 'var(--text-dim)',
              textTransform: 'capitalize',
            }}>
            {t}
          </div>
        ))}
        <div style={{ flex: 1 }} />
        {loading && <span style={{ fontSize: 11, color: 'var(--accent)' }}>{loading}</span>}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: activeTab === 'overview' ? 24 : 0 }}>
        {activeTab === 'overview' && meta && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
            {Object.entries(meta).filter(([k]) => k !== 'status').map(([k, v]) => (
              <div key={k} className="card">
                <div className="card-label">{k}</div>
                <div style={{ fontSize: 13, fontFamily: 'var(--mono)', marginTop: 4, wordBreak: 'break-all' }}>{String(v)}</div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'functions' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>Address</th><th style={thS}>Name</th><th style={thS}>Size</th><th style={thS}>Params</th><th style={thS}>Action</th></tr></thead>
            <tbody>
              {functions.map((f, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{f.address}</td>
                  <td style={{ ...tdS, fontWeight: 600 }}>{f.name}</td>
                  <td style={tdS}>{f.size}</td>
                  <td style={tdS}>{f.parameter_count}</td>
                  <td style={tdS}><button className="btn btn-sm" onClick={() => decompile(f.address)}>Decompile</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'imports' && imports && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>DLL</th><th style={thS}>Function</th></tr></thead>
            <tbody>
              {(imports.imports || []).map((imp: any, i: number) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ ...tdS, color: 'var(--text-dim)' }}>{imp.namespace}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)' }}>{imp.name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === 'suspicious' && suspicious && (
          <div style={{ padding: 16 }}>
            <div style={{ marginBottom: 12, fontSize: 13 }}>
              <strong style={{ color: 'var(--critical)' }}>{suspicious.total_suspicious}</strong> suspicious APIs / {suspicious.total_imports} total imports
            </div>
            {(suspicious.findings || []).map((f: any, i: number) => (
              <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border-light)', fontSize: 12 }}>
                <span style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--critical)' }}>{f.api}</span>
                <span style={{ color: 'var(--text-dim)', marginLeft: 8 }}>{f.description}</span>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'strings' && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr><th style={thS}>Address</th><th style={thS}>Value</th><th style={thS}>Length</th></tr></thead>
            <tbody>
              {strings.map((s, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border-light)' }}>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>{s.address}</td>
                  <td style={{ ...tdS, fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>{s.value}</td>
                  <td style={tdS}>{s.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Decompile panel */}
      {decompiled && (
        <div style={{
          borderTop: '1px solid var(--border)', height: 300, display: 'flex', flexDirection: 'column',
        }}>
          <div style={{ padding: '8px 16px', background: 'var(--surface)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 600, fontSize: 12 }}>Decompiled: {decompiled.function_name}</span>
            <div style={{ flex: 1 }} />
            <button className="btn btn-sm" onClick={() => setDecompiled(null)}>Close</button>
          </div>
          <pre style={{
            flex: 1, overflowY: 'auto', padding: 16, margin: 0,
            fontFamily: 'var(--mono)', fontSize: 12, lineHeight: 1.6,
            background: 'var(--surface2)', color: 'var(--text)',
          }}>
            {decompiled.decompiled_c || '(decompilation failed)'}
          </pre>
        </div>
      )}
    </div>
  );
}

const thS: React.CSSProperties = { padding: '8px 12px', textAlign: 'left', fontWeight: 600, fontSize: 11, textTransform: 'uppercase', color: 'var(--text-dim)', background: 'var(--surface)', borderBottom: '2px solid var(--border)', position: 'sticky', top: 0 };
const tdS: React.CSSProperties = { padding: '6px 12px' };
