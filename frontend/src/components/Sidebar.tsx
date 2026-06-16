import { useState } from 'react';
import { useStore } from '../hooks/useStore';
import { useI18n } from '../i18n/useI18n';
import type { TranslationKey } from '../i18n/translations';

interface NavItem {
  id: string;
  labelKey: TranslationKey;
  code: string;
}

interface NavSection {
  titleKey: TranslationKey;
  items: NavItem[];
  defaultCollapsed?: boolean;
}

const SECTIONS: NavSection[] = [
  {
    titleKey: 'nav.investigation',
    items: [
      { id: 'dashboard', labelKey: 'nav.dashboard', code: 'DASH' },
      { id: 'detection', labelKey: 'nav.detections', code: 'DET' },
      { id: 'timeline', labelKey: 'nav.timeline', code: 'TIME' },
      { id: 'coverage', labelKey: 'nav.coverage', code: 'COV' },
      { id: 'pivot', labelKey: 'nav.pivot', code: 'PIV' },
      { id: 'compare', labelKey: 'nav.compare', code: 'CMP' },
    ],
  },
  {
    titleKey: 'nav.artifacts',
    items: [
      { id: 'artifacts', labelKey: 'nav.artifactBrowser', code: 'ART' },
      { id: 'ioc', labelKey: 'nav.iocTracker', code: 'IOC' },
      { id: 'logs', labelKey: 'nav.evtxLogs', code: 'EVT' },
      { id: 'registry', labelKey: 'nav.registry', code: 'REG' },
      { id: 'network', labelKey: 'nav.network', code: 'NET' },
    ],
  },
  {
    titleKey: 'nav.advancedTools',
    defaultCollapsed: true,
    items: [
      { id: 'memory', labelKey: 'nav.memory', code: 'MEM' },
      { id: 'binary', labelKey: 'nav.binary', code: 'BIN' },
      { id: 'yara', labelKey: 'nav.yara', code: 'YARA' },
    ],
  },
  {
    titleKey: 'nav.output',
    items: [
      { id: 'report', labelKey: 'nav.report', code: 'RPT' },
      { id: 'kape', labelKey: 'nav.kape', code: 'KAPE' },
      { id: 'settings', labelKey: 'nav.settings', code: 'SET' },
    ],
  },
];

export default function Sidebar() {
  const { activeView, setActiveView, caseInfo } = useStore();
  const { t } = useI18n();
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    SECTIONS.forEach(s => { if (s.defaultCollapsed) init[s.titleKey] = true; });
    return init;
  });

  const toggleSection = (titleKey: TranslationKey) => {
    setCollapsed(prev => ({ ...prev, [titleKey]: !prev[titleKey] }));
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
          {caseInfo?.case_name || t('sidebar.noCaseLoaded')}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
          {caseInfo?.source_type
            ? t('sidebar.sourceCase', { source: caseInfo.source_type.toUpperCase() })
            : t('common.workspace')}
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
          <div key={section.titleKey} style={{ marginTop: 4 }}>
            <button
              onClick={() => toggleSection(section.titleKey)}
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
              <span>{t(section.titleKey)}</span>
              <span style={{
                fontFamily: 'var(--mono)',
                fontSize: 9,
                transform: collapsed[section.titleKey] ? 'rotate(-90deg)' : 'none',
                transition: 'transform 100ms',
              }}>
                v
              </span>
            </button>
            {!collapsed[section.titleKey] && section.items.map(item => {
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
                  <span>{t(item.labelKey)}</span>
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
              <span style={{ color: 'var(--text-subtle)' }}>{t('common.artifacts')}</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {caseInfo.total_hits?.toLocaleString()}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-subtle)' }}>{t('common.families')}</span>
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
