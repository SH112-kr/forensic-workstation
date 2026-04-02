import { useState } from 'react';
import { post } from '../hooks/useApi';
import FileBrowser from './FileBrowser';

export default function YaraScan() {
  const [rulesLoaded, setRulesLoaded] = useState(false);
  const [rulesPath, setRulesPath] = useState('');
  const [targetPath, setTargetPath] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState('');
  const [error, setError] = useState('');
  const [browserOpen, setBrowserOpen] = useState<'rules' | 'target' | null>(null);

  const loadRules = async () => {
    if (!rulesPath.trim()) return;
    setLoading('Loading YARA rules...');
    setError('');
    try {
      await post('/api/yara/load', { path: rulesPath.trim() });
      setRulesLoaded(true);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const scanFile = async () => {
    if (!targetPath.trim()) return;
    setLoading('Scanning...');
    setError('');
    try {
      const data = await post('/api/yara/scan-file', { target_path: targetPath.trim() });
      setResults(data.results || []);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  const scanDir = async () => {
    if (!targetPath.trim()) return;
    setLoading('Scanning directory...');
    setError('');
    try {
      const data = await post('/api/yara/scan-directory', { target_path: targetPath.trim() });
      setResults(data.results || []);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(''); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: 16, borderBottom: '1px solid var(--border)', background: 'var(--surface)' }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>YARA Scan</h2>
        {/* Rules */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
          <input type="text" value={rulesPath} onChange={e => setRulesPath(e.target.value)}
            placeholder="Path to .yar file or rules directory"
            style={{ flex: 1, padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
          <button className="btn btn-sm" onClick={() => setBrowserOpen('rules')}>Browse</button>
          <button className="btn btn-primary btn-sm" onClick={loadRules} disabled={!!loading}>
            {rulesLoaded ? 'Reload Rules' : 'Load Rules'}
          </button>
        </div>
        {/* Target */}
        {rulesLoaded && (
          <div style={{ display: 'flex', gap: 8 }}>
            <input type="text" value={targetPath} onChange={e => setTargetPath(e.target.value)}
              placeholder="Target file or directory to scan"
              style={{ flex: 1, padding: '6px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, fontFamily: 'var(--mono)' }} />
            <button className="btn btn-sm" onClick={() => setBrowserOpen('target')}>Browse</button>
            <button className="btn btn-primary btn-sm" onClick={scanFile} disabled={!!loading}>Scan File</button>
            <button className="btn btn-sm" onClick={scanDir} disabled={!!loading}>Scan Dir</button>
          </div>
        )}
        {loading && <div style={{ fontSize: 12, color: 'var(--accent)', marginTop: 8 }}>{loading}</div>}
        {error && <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 8 }}>{error}</div>}
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {results.length === 0 && !loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            {rulesLoaded ? 'No matches. Select a target and scan.' : 'Load YARA rules to begin.'}
          </div>
        )}
        {results.map((r, i) => (
          <div key={i} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-light)' }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
              <span className="badge badge-critical">{r.rule}</span>
              <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{r.namespace}</span>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>{r.file}</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              {r.strings_matched} strings matched
              {r.tags?.length > 0 && ` | Tags: ${r.tags.join(', ')}`}
            </div>
            {r.meta && Object.keys(r.meta).length > 0 && (
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>
                {Object.entries(r.meta).map(([k, v]) => `${k}: ${v}`).join(' | ')}
              </div>
            )}
          </div>
        ))}
      </div>

      <FileBrowser open={!!browserOpen} onClose={() => setBrowserOpen(null)}
        onSelect={(p) => { if (browserOpen === 'rules') setRulesPath(p); else setTargetPath(p); setBrowserOpen(null); }}
        title={browserOpen === 'rules' ? 'Select YARA Rules' : 'Select Scan Target'} />
    </div>
  );
}
