import { useState } from 'react';
import { useStore } from '../hooks/useStore';

interface NavItem {
  id: string;
  label: string;
  icon: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
  defaultCollapsed?: boolean;
}

const SECTIONS: NavSection[] = [
  {
    title: 'Case Analysis',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: '📊' },
      { id: 'artifacts', label: 'Artifacts', icon: '🔍' },
      { id: 'timeline', label: 'Timeline', icon: '⏱' },
      { id: 'detection', label: 'Detection', icon: '🛡' },
      { id: 'ioc', label: 'IOC', icon: '🎯' },
    ],
  },
  {
    title: 'Advanced Tools',
    defaultCollapsed: true,
    items: [
      { id: 'memory', label: 'Memory', icon: '🧠' },
      { id: 'binary', label: 'Binary', icon: '⚙' },
      { id: 'logs', label: 'EVTX Logs', icon: '📋' },
      { id: 'network', label: 'Network', icon: '🌐' },
      { id: 'yara', label: 'YARA', icon: '🎯' },
      { id: 'registry', label: 'Registry', icon: '🗂' },
    ],
  },
  {
    title: 'Output',
    items: [
      { id: 'report', label: 'Report', icon: '📄' },
    ],
  },
  {
    title: 'System',
    items: [
      { id: 'kape', label: 'KAPE', icon: '\u25B6' },
      { id: 'settings', label: 'Settings', icon: '\u2699' },
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
      width: 'var(--sidebar-w)', background: 'var(--surface)', borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', flexShrink: 0, overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        padding: '14px 16px', borderBottom: '1px solid var(--border)',
        fontWeight: 700, fontSize: 14,
      }}>
        Forensic Workstation
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
        {SECTIONS.map((section) => (
          <div key={section.title} style={{ marginBottom: 4 }}>
            <div
              onClick={() => toggleSection(section.title)}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '6px 12px', cursor: 'pointer', userSelect: 'none',
                fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                letterSpacing: '0.05em', color: 'var(--text-dim)',
              }}
            >
              <span>{section.title}</span>
              <span style={{ fontSize: 10 }}>{collapsed[section.title] ? '▸' : '▾'}</span>
            </div>
            {!collapsed[section.title] && section.items.map((item) => (
              <div
                key={item.id}
                onClick={() => setActiveView(item.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '8px 12px', borderRadius: 6, cursor: 'pointer',
                  fontSize: 13, fontWeight: activeView === item.id ? 600 : 400,
                  background: activeView === item.id ? 'var(--accent-light)' : 'transparent',
                  color: activeView === item.id ? 'var(--accent)' : 'var(--text)',
                  transition: 'all 0.1s',
                  marginBottom: 2,
                }}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        ))}
      </nav>

      {/* Case info */}
      {caseInfo && (
        <div style={{
          padding: '12px 16px', borderTop: '1px solid var(--border)',
          fontSize: 11, color: 'var(--text-dim)',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4,
          }}>
            {caseInfo.source_type && (
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                background: caseInfo.source_type === 'kape' ? 'rgba(96,165,250,0.15)' : 'rgba(74,222,128,0.15)',
                color: caseInfo.source_type === 'kape' ? '#60a5fa' : '#4ade80',
              }}>{caseInfo.source_type.toUpperCase()}</span>
            )}
            <span style={{ fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {caseInfo.case_name}
            </span>
          </div>
          <div>{caseInfo.total_hits?.toLocaleString()} artifacts</div>
          <div>{caseInfo.artifact_type_count} types</div>
        </div>
      )}
    </aside>
  );
}
