import { useState } from 'react';
import { useStore } from '../hooks/useStore';

export default function Header() {
  const { theme, toggleTheme, copilotOpen, toggleCopilot, caseInfo } = useStore();
  const [showShortcuts, setShowShortcuts] = useState(false);

  return (
    <header style={{
      height: 'var(--header-h)', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center', padding: '0 16px', gap: 12, flexShrink: 0,
    }}>
      <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-dim)' }}>
        FORENSIC WORKSTATION
      </span>
      {caseInfo && (
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
