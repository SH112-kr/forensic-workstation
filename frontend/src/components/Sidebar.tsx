import { useState } from 'react';
import { useStore } from '../hooks/useStore';

interface NavItem {
  id: string;
  label: string;
  code: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
  defaultCollapsed?: boolean;
}

const SECTIONS: NavSection[] = [
  {
    title: 'Investigation',
    items: [
      { id: 'dashboard', label: 'Dashboard', code: 'DASH' },
      { id: 'detection', label: 'Detections', code: 'DET' },
      { id: 'timeline', label: 'Timeline', code: 'TIME' },
      { id: 'coverage', label: 'Coverage', code: 'COV' },
      { id: 'pivot', label: 'Pivot', code: 'PIV' },
      { id: 'compare', label: 'Compare', code: 'CMP' },
    ],
  },
  {
    title: 'Artifacts',
    items: [
      { id: 'artifacts', label: 'Artifact Browser', code: 'ART' },
      { id: 'ioc', label: 'IOC Tracker', code: 'IOC' },
      { id: 'logs', label: 'EVTX Logs', code: 'EVT' },
      { id: 'registry', label: 'Registry', code: 'REG' },
      { id: 'network', label: 'Network', code: 'NET' },
    ],
  },
  {
    title: 'Advanced Tools',
    defaultCollapsed: true,
    items: [
      { id: 'memory', label: 'Memory', code: 'MEM' },
      { id: 'binary', label: 'Binary', code: 'BIN' },
      { id: 'yara', label: 'YARA', code: 'YARA' },
    ],
  },
  {
    title: 'Output',
    items: [
      { id: 'report', label: 'Report', code: 'RPT' },
      { id: 'kape', label: 'KAPE', code: 'KAPE' },
      { id: 'settings', label: 'Settings', code: 'SET' },
    ],
  },
];

export default function Sidebar() {
  const { activeView, setActiveView, caseInfo } = useStore();
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    SECTIONS.forEach(s => { if (s.defaultCollapsed) init[s.title] = true; });
    return init;
  });

  const toggleSection = (title: string) => {
    setCollapsed(prev => ({ ...prev, [title]: !prev[title] }));
  };

  return (
    <aside style={{
      width: 'var(--sidebar-w)',
      background: 'var(--surface)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      flexShrink: 0,
      overflow: 'hidden',
    }}>
      <div style={{ padding: '14px 16px 12px', position: 'relative' }}>
        <div style={{
          fontFamily: 'var(--mono)',
          fontSize: 12,
          fontWeight: 700,
          color: 'var(--text)',
          letterSpacing: '0.03em',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          paddingRight: 16,
        }}>
          {caseInfo?.case_name || 'No case loaded'}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
          {caseInfo?.source_type ? `${caseInfo.source_type.toUpperCase()} case` : 'Workspace'}
          {caseInfo?.case_mode ? ` | ${caseInfo.case_mode.toUpperCase()}` : ''}
        </div>
        <span style={{
          position: 'absolute',
          top: 16,
          right: 16,
          width: 7,
          height: 7,
          borderRadius: '50%',
          background: caseInfo ? 'var(--low)' : 'var(--text-subtle)',
        }} />
      </div>

      <div style={{ borderTop: '1px solid var(--border)', margin: '0 12px' }} />

      <nav style={{ flex: 1, overflowY: 'auto', paddingTop: 4 }}>
        {SECTIONS.map(section => (
          <div key={section.title} style={{ marginTop: 4 }}>
            <button
              onClick={() => toggleSection(section.title)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                padding: '5px 16px',
                background: 'transparent',
                border: 0,
                cursor: 'pointer',
                color: 'var(--text-subtle)',
                fontSize: 10,
                fontFamily: 'var(--font)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                fontWeight: 700,
              }}
            >
              <span>{section.title}</span>
              <span style={{
                fontFamily: 'var(--mono)',
                fontSize: 9,
                transform: collapsed[section.title] ? 'rotate(-90deg)' : 'none',
                transition: 'transform 100ms',
              }}>
                v
              </span>
            </button>
            {!collapsed[section.title] && section.items.map(item => {
              const active = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    width: '100%',
                    padding: '6px 16px',
                    background: active ? 'var(--surface-2)' : 'transparent',
                    border: 0,
                    borderLeft: active ? '2px solid var(--medium)' : '2px solid transparent',
                    cursor: 'pointer',
                    color: active ? 'var(--text)' : 'var(--text-muted)',
                    fontSize: 13,
                    fontFamily: 'var(--font)',
                    textAlign: 'left',
                  }}
                >
                  <span style={{
                    width: 34,
                    fontFamily: 'var(--mono)',
                    fontSize: 9,
                    color: active ? 'var(--medium)' : 'var(--text-subtle)',
                  }}>
                    {item.code}
                  </span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {caseInfo && (
        <>
          <div style={{ borderTop: '1px solid var(--border)', margin: '0 12px' }} />
          <div style={{ padding: '10px 16px', fontSize: 11 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ color: 'var(--text-subtle)' }}>Artifacts</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {caseInfo.total_hits?.toLocaleString()}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-subtle)' }}>Families</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {caseInfo.artifact_type_count}
              </span>
            </div>
          </div>
        </>
      )}
    </aside>
  );
}
