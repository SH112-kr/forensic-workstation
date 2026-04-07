import { useEffect, useState } from 'react';
import { useStore } from '../hooks/useStore';
import { get, post } from '../hooks/useApi';

interface OpenCase {
  case_id: string;
  source_type: string;
  total_hits: number;
}

export default function Header() {
  const { theme, toggleTheme, copilotOpen, toggleCopilot, caseInfo, setCaseInfo, setDetection, setKapeDiagnostics } = useStore();
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [cases, setCases] = useState<OpenCase[]>([]);
  const [activeCase, setActiveCase] = useState('');

  // Fetch open cases
  useEffect(() => {
    if (!caseInfo) return;
    get('/api/cases/list').then(data => {
      const list: OpenCase[] = (data.cases || []).map((c: any) => ({
        case_id: c.case_id,
        source_type: c.metadata?.source_type || '?',
        total_hits: c.metadata?.total_hits || 0,
      }));
      setCases(list);
      // Find active case
      const active = list.find(c =>
        caseInfo.case_name === c.case_id ||
        caseInfo.case_name?.includes(c.case_id)
      );
      if (active) setActiveCase(active.case_id);
      else if (list.length > 0) setActiveCase(list[list.length - 1].case_id);
    }).catch(() => {});
  }, [caseInfo]);

  const switchCase = async (caseId: string) => {
    if (caseId === activeCase) return;
    try {
      await post(`/api/cases/switch?case_id=${encodeURIComponent(caseId)}`, {});
      // Refresh case info
      const summary = await get('/api/cases/summary');
      setCaseInfo(summary);
      setDetection(null, null); // Clear detection cache to re-run
      setKapeDiagnostics(summary.kape_diagnostics || null);
      setActiveCase(caseId);
    } catch (e) {
      console.error('Switch failed:', e);
    }
  };

  const sourceTag = (type: string) => {
    if (type === 'kape') return { label: 'KAPE', color: '#60a5fa' };
    return { label: 'MFDB', color: '#4ade80' };
  };

  return (
    <header style={{
      height: 'var(--header-h)', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center', padding: '0 16px', gap: 12, flexShrink: 0,
    }}>
      <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-dim)' }}>
        FORENSIC WORKSTATION
      </span>

      {/* Case Selector — shows when multiple cases are open */}
      {cases.length > 1 ? (
        <div style={{ display: 'flex', gap: 4 }}>
          {cases.map(c => {
            const tag = sourceTag(c.source_type);
            const isActive = c.case_id === activeCase;
            return (
              <button key={c.case_id} onClick={() => switchCase(c.case_id)}
                style={{
                  padding: '3px 10px', borderRadius: 5, border: 'none', fontSize: 11,
                  cursor: 'pointer', fontWeight: isActive ? 700 : 400,
                  background: isActive ? `${tag.color}22` : 'transparent',
                  color: isActive ? tag.color : 'var(--text-dim)',
                  outline: isActive ? `1px solid ${tag.color}44` : 'none',
                }}
                title={`${c.case_id} (${c.total_hits.toLocaleString()} hits)`}
              >
                <span style={{
                  fontSize: 9, fontWeight: 700, marginRight: 4,
                  padding: '1px 4px', borderRadius: 3,
                  background: `${tag.color}22`, color: tag.color,
                }}>{tag.label}</span>
                {c.case_id.length > 20 ? c.case_id.slice(0, 20) + '...' : c.case_id}
              </button>
            );
          })}
        </div>
      ) : caseInfo && (
        <span style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>
          {caseInfo.case_name}
        </span>
      )}

      <div style={{ flex: 1 }} />
      <div style={{ position: 'relative' }}>
        <button
          className="btn btn-sm"
          onClick={() => setShowShortcuts(!showShortcuts)}
          title="Keyboard shortcuts"
          style={{ minWidth: 28 }}
        >
          ?
        </button>
        {showShortcuts && (
          <div style={{
            position: 'absolute', top: '100%', right: 0, marginTop: 4,
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '12px 16px', zIndex: 1000,
            fontSize: 12, whiteSpace: 'nowrap', minWidth: 200,
            boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
          }}>
            <div style={{ fontWeight: 700, marginBottom: 8, color: 'var(--text)' }}>Keyboard Shortcuts</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, color: 'var(--text-dim)' }}>
              <div><kbd style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text)' }}>Ctrl+1~9</kbd> Switch tabs</div>
              <div><kbd style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text)' }}>Ctrl+K</kbd> Search</div>
              <div><kbd style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text)' }}>Ctrl+B</kbd> Co-pilot</div>
              <div><kbd style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text)' }}>Esc</kbd> Close panels</div>
            </div>
          </div>
        )}
      </div>
      <button className="btn btn-sm" onClick={toggleTheme}>
        {theme === 'light' ? 'Dark' : 'Light'}
      </button>
      <button
        className={`btn btn-sm ${copilotOpen ? 'btn-primary' : ''}`}
        onClick={toggleCopilot}
      >
        AI Co-pilot
      </button>
    </header>
  );
}
