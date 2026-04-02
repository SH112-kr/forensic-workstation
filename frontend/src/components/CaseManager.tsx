import { useState } from 'react';
import { post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

interface FileItem {
  name: string;
  path: string;
  type: 'drive' | 'directory' | 'file';
  file_type?: string;
  size_display?: string;
  extension?: string;
}

export default function CaseManager() {
  const { setCaseInfo, setCaseLoading, setActiveView } = useStore();
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState('');

  // Recent cases
  const [recentCases, setRecentCases] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem('recentCases') || '[]'); } catch { return []; }
  });

  const addRecentCase = (casePath: string) => {
    const updated = [casePath, ...recentCases.filter(p => p !== casePath)].slice(0, 5);
    setRecentCases(updated);
    localStorage.setItem('recentCases', JSON.stringify(updated));
  };

  // File browser state
  const [browserOpen, setBrowserOpen] = useState(false);
  const [browserPath, setBrowserPath] = useState('');
  const [browserItems, setBrowserItems] = useState<FileItem[]>([]);
  const [browserLoading, setBrowserLoading] = useState(false);
  const [showAll, setShowAll] = useState(false);

  const openCase = async (filePath?: string) => {
    const target = filePath || path.trim();
    if (!target) return;
    setLoading(true);
    setCaseLoading(true);
    setError('');
    setLoadingMsg('Connecting to database...');

    try {
      // Simulate progress stages
      const progressTimer = setTimeout(() => setLoadingMsg('Loading artifact metadata...'), 1500);
      const progressTimer2 = setTimeout(() => setLoadingMsg('Building fragment cache...'), 3000);

      const data = await post('/api/cases/open', { path: target });
      clearTimeout(progressTimer);
      clearTimeout(progressTimer2);

      setCaseInfo(data);
      addRecentCase(target);
      setActiveView('dashboard');
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
      setCaseLoading(false);
      setLoadingMsg('');
    }
  };

  const browse = async (targetPath: string = '', forceShowAll?: boolean) => {
    setBrowserLoading(true);
    try {
      const data = await post('/api/files/browse', {
        path: targetPath,
        show_all: forceShowAll !== undefined ? forceShowAll : showAll,
      });
      setBrowserPath(data.current || '');
      setBrowserItems(data.items || []);
      if (data.error) {
        console.warn('Browse error:', data.error);
      }
    } catch (e) {
      console.error('Browse API error:', e);
      setBrowserItems([]);
    } finally {
      setBrowserLoading(false);
    }
  };

  const openBrowser = () => {
    setBrowserOpen(true);
    browse('');
  };

  const selectFile = (item: FileItem) => {
    if (item.type === 'drive' || item.type === 'directory') {
      browse(item.path);
    } else {
      setPath(item.path);
      setBrowserOpen(false);
    }
  };

  const icons: Record<string, string> = {
    drive: '💾',
    directory: '📁',
    'AXIOM Case': '🔬',
    'Memory Dump': '🧠',
    'Binary': '⚙️',
    'Event Log': '📋',
    'PCAP': '🌐',
    'YARA Rules': '🎯',
    'Registry Hive': '🗂️',
    'Other': '📄',
  };

  return (
    <div style={{ maxWidth: 700, margin: '60px auto', padding: '0 24px' }}>
      {/* Title */}
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <h1 style={{ fontSize: 32, fontWeight: 300, marginBottom: 4 }}>
          <strong>Forensic</strong> Workstation
        </h1>
        <p style={{ color: 'var(--text-dim)', fontSize: 14 }}>
          Digital Forensics & Incident Response Investigation Platform
        </p>
      </div>

      {/* File input */}
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12,
        padding: 24, marginBottom: 16,
      }}>
        <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: 8 }}>
          Case File Path
        </label>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && openCase()}
            placeholder="Select a file or enter path..."
            style={{
              flex: 1, padding: '10px 14px', borderRadius: 8,
              border: '1px solid var(--border)', background: 'var(--bg)',
              color: 'var(--text)', fontSize: 13, fontFamily: 'var(--mono)',
            }}
          />
          <button className="btn" onClick={openBrowser} style={{ padding: '10px 16px' }}>
            Browse...
          </button>
          <button
            className="btn btn-primary"
            onClick={() => openCase()}
            disabled={loading || !path.trim()}
            style={{ padding: '10px 24px', minWidth: 100 }}
          >
            {loading ? 'Opening...' : 'Open'}
          </button>
        </div>

        {/* Loading indicator */}
        {loading && (
          <div style={{
            marginTop: 16, padding: 16, borderRadius: 8,
            background: 'var(--accent-light)', border: '1px solid var(--accent)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 20, height: 20, border: '3px solid var(--border)',
                borderTopColor: 'var(--accent)', borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{loadingMsg || 'Loading...'}</div>
                <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>
                  This may take a few seconds for large case files
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div style={{
            marginTop: 12, padding: '10px 14px', borderRadius: 8,
            background: 'var(--critical-bg)', color: 'var(--critical)', fontSize: 12,
          }}>
            {error}
          </div>
        )}
      </div>

      {/* Supported files info */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
        gap: 8, marginBottom: 24,
      }}>
        {[
          { ext: '.mfdb', label: 'AXIOM Case', desc: 'Disk forensics' },
          { ext: '.raw/.vmem', label: 'Memory Dump', desc: 'Volatility analysis' },
          { ext: '.exe/.dll', label: 'Binary', desc: 'Ghidra analysis' },
          { ext: '.evtx', label: 'Event Log', desc: 'Hayabusa scan' },
          { ext: '.pcap', label: 'PCAP', desc: 'Network analysis' },
        ].map((f) => (
          <div key={f.ext} style={{
            padding: '10px 12px', borderRadius: 8,
            border: '1px solid var(--border-light)', fontSize: 11,
          }}>
            <div style={{ fontWeight: 600, marginBottom: 2 }}>{f.label}</div>
            <div style={{ color: 'var(--text-dim)' }}>{f.ext}</div>
            <div style={{ color: 'var(--text-light)', fontSize: 10 }}>{f.desc}</div>
          </div>
        ))}
      </div>

      {/* Recent Cases */}
      {recentCases.length > 0 && (
        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12,
          padding: 16, marginBottom: 24,
        }}>
          <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-dim)', display: 'block', marginBottom: 8 }}>
            Recent Cases
          </label>
          {recentCases.map((p, i) => (
            <div key={i}
              onClick={() => { setPath(p); openCase(p); }}
              style={{
                padding: '6px 10px', borderRadius: 6, cursor: 'pointer',
                fontSize: 12, fontFamily: 'var(--mono)', color: 'var(--text)',
                marginBottom: 2,
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-light)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              {p}
            </div>
          ))}
        </div>
      )}

      {/* File Browser Modal */}
      {browserOpen && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
        }} onClick={() => setBrowserOpen(false)}>
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: 600, maxHeight: '70vh', background: 'var(--bg)',
              border: '1px solid var(--border)', borderRadius: 12,
              display: 'flex', flexDirection: 'column', overflow: 'hidden',
            }}
          >
            {/* Browser header */}
            <div style={{
              padding: '12px 16px', borderBottom: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span style={{ fontWeight: 600, fontSize: 14 }}>Select File</span>
              <div style={{ flex: 1 }} />
              <label style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-dim)' }}>
                <input type="checkbox" checked={showAll} onChange={(e) => { setShowAll(e.target.checked); browse(browserPath, e.target.checked); }} />
                Show all files
              </label>
              <button className="btn btn-sm" onClick={() => setBrowserOpen(false)}>Close</button>
            </div>

            {/* Path bar */}
            <div style={{
              padding: '8px 16px', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
              fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-dim)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <button className="btn btn-sm" onClick={() => browse('')}>Drives</button>
              <span>{browserPath || 'Select a drive'}</span>
              {browserLoading && <span style={{ color: 'var(--accent)' }}>Loading...</span>}
            </div>

            {/* File list */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {browserItems.map((item, i) => (
                <div
                  key={i}
                  onClick={() => selectFile(item)}
                  onDoubleClick={() => item.type === 'file' && openCase(item.path)}
                  style={{
                    padding: '8px 16px', cursor: 'pointer', display: 'flex',
                    alignItems: 'center', gap: 10, borderBottom: '1px solid var(--border-light)',
                    fontSize: 13,
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--accent-light)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  <span>{icons[item.type === 'file' ? (item.file_type || 'Other') : item.type] || '📄'}</span>
                  <span style={{ flex: 1, fontWeight: item.type !== 'file' ? 600 : 400 }}>
                    {item.name}
                  </span>
                  {item.file_type && (
                    <span style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 600 }}>{item.file_type}</span>
                  )}
                  {item.size_display && (
                    <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>
                      {item.size_display}
                    </span>
                  )}
                </div>
              ))}
              {browserItems.length === 0 && !browserLoading && (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-dim)' }}>
                  No forensic files found. Enable "Show all files" to see everything.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Spinner animation */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
