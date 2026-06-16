import { useEffect, useState } from 'react';
import { useStore } from '../hooks/useStore';
import { get, post } from '../hooks/useApi';
import { useI18n } from '../i18n/useI18n';

interface OpenCase {
  case_id: string;
  case_name: string;
  source_type: string;
  total_hits: number;
}

interface CaseListResponse {
  active_case_id?: string;
  cases?: Array<{
    case_id: string;
    case_name?: string;
    source_type?: string;
    total_hits?: number;
    metadata?: {
      source_type?: string;
      total_hits?: number;
    };
  }>;
}

export default function Header() {
  const {
    theme, toggleTheme, copilotOpen, toggleCopilot, caseInfo, setCaseInfo,
    setDetection, setKapeDiagnostics, setCaseManagerOpen, setActiveView,
  } = useStore();
  const { language, setLanguage, t } = useI18n();
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [cases, setCases] = useState<OpenCase[]>([]);
  const [activeCase, setActiveCase] = useState('');

  useEffect(() => {
    if (!caseInfo) return;
    get<CaseListResponse>('/api/cases/list').then(data => {
      const list: OpenCase[] = (data.cases || []).map((c) => ({
        case_id: c.case_id,
        case_name: c.case_name || c.case_id,
        source_type: c.source_type || c.metadata?.source_type || '?',
        total_hits: c.total_hits ?? c.metadata?.total_hits ?? 0,
      }));
      setCases(list);
      if (data.active_case_id) {
        setActiveCase(data.active_case_id);
      } else if (!activeCase && list.length > 0) {
        setActiveCase(list[list.length - 1].case_id);
      }
    }).catch(() => {});
  }, [caseInfo, activeCase]);

  const switchCase = async (caseId: string) => {
    if (caseId === activeCase) return;
    try {
      setActiveCase(caseId);
      await post(`/api/cases/switch?case_id=${encodeURIComponent(caseId)}`, {});
      const summary = await get('/api/cases/summary');
      setCaseInfo(summary);
      setDetection(null, null);
      setKapeDiagnostics(summary.kape_diagnostics || null);
    } catch (e) {
      console.error('Switch failed:', e);
    }
  };

  const sourceTag = (type: string) => {
    if (type === 'kape') return { label: 'KAPE', color: '#60a5fa' };
    if (type === 'mfdb') return { label: 'MFDB', color: '#3fb950' };
    return { label: type?.toUpperCase?.() || 'CASE', color: 'var(--text-muted)' };
  };

  const activeCaseName = cases.find(c => c.case_id === activeCase)?.case_name || caseInfo?.case_name || '-';
  const statusLabel = caseInfo?.case_mode
    ? t('header.directMode', { mode: caseInfo.case_mode.toUpperCase() })
    : t('header.localAnalysisReady');

  return (
    <header style={{
      height: 'var(--header-h)',
      background: 'var(--surface)',
      borderBottom: '1px solid var(--border)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 16px',
      gap: 14,
      flexShrink: 0,
      minWidth: 0,
    }}>
      <button
        onClick={() => setActiveView('dashboard')}
        title={t('header.dashboardTitle')}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          background: 'transparent',
          border: 0,
          padding: 0,
          cursor: 'pointer',
          color: 'var(--text)',
        }}
      >
        <span style={{
          fontFamily: 'var(--mono)',
          fontSize: 11,
          fontWeight: 700,
          color: 'var(--critical)',
          letterSpacing: '0.1em',
          border: '1px solid var(--critical-border)',
          padding: '1px 6px',
          borderRadius: 2,
        }}>
          FSEC
        </span>
        <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.04em' }}>
          DFIR Workstation
        </span>
      </button>

      <div style={{ width: 1, height: 18, background: 'var(--border)' }} />

      {caseInfo && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0 }}>
          <Meta label={t('common.case')} value={activeCaseName} />
          <Meta label={t('common.artifacts')} value={(caseInfo.total_hits || 0).toLocaleString()} />
          <Meta label={t('common.types')} value={String(caseInfo.artifact_type_count || 0)} />

          {cases.length > 0 && (
            <div style={{ display: 'flex', gap: 4, alignItems: 'center', minWidth: 0 }}>
              {cases.slice(0, 4).map(c => {
                const tag = sourceTag(c.source_type);
                const isActive = c.case_id === activeCase;
                const label = c.case_name || c.case_id;
                return (
                  <button
                    key={c.case_id}
                    onClick={() => switchCase(c.case_id)}
                    title={`${c.case_id} | ${c.source_type.toUpperCase()} | ${c.total_hits.toLocaleString()} hits`}
                    style={{
                      padding: '2px 7px',
                      borderRadius: 3,
                      border: `1px solid ${isActive ? tag.color : 'var(--border)'}`,
                      background: isActive ? `${tag.color}22` : 'transparent',
                      color: isActive ? tag.color : 'var(--text-muted)',
                      fontFamily: 'var(--mono)',
                      fontSize: 10,
                      cursor: 'pointer',
                      maxWidth: 150,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {tag.label} {label.length > 18 ? `${label.slice(0, 18)}...` : label}
                  </button>
                );
              })}
            </div>
          )}

          <button className="btn btn-sm" onClick={() => setCaseManagerOpen(true)} title={t('header.openAnotherCase')}>
            {t('header.addCase')}
          </button>
          {cases.length >= 2 && (
            <button className="btn btn-sm" onClick={() => setActiveView('compare')} title={t('header.compareLoaded')}>
              {t('common.compare')}
            </button>
          )}
        </div>
      )}

      <div style={{ flex: 1 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: caseInfo?.case_mode ? 'var(--high)' : 'var(--low)',
        }} />
        <span style={{
          fontFamily: 'var(--mono)',
          fontSize: 10,
          color: caseInfo?.case_mode ? 'var(--high)' : 'var(--low)',
          fontWeight: 700,
          letterSpacing: '0.06em',
          whiteSpace: 'nowrap',
        }}>
          {statusLabel}
        </span>
      </div>

      <div style={{ width: 1, height: 18, background: 'var(--border)' }} />

      <div style={{ position: 'relative' }}>
        <button className="btn btn-sm" onClick={() => setShowShortcuts(!showShortcuts)} title={t('header.keyboardShortcuts')}>
          ?
        </button>
        {showShortcuts && (
          <div style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: 6,
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 4,
            padding: '10px 12px',
            zIndex: 1000,
            fontSize: 12,
            whiteSpace: 'nowrap',
            minWidth: 210,
            boxShadow: '0 12px 32px rgba(0,0,0,0.35)',
          }}>
            <div style={{ fontWeight: 700, marginBottom: 8, color: 'var(--text)' }}>{t('header.keyboardShortcuts')}</div>
            <Shortcut keys="Ctrl+1-9" label={t('header.switchViews')} />
            <Shortcut keys="Ctrl+K" label={t('header.searchArtifacts')} />
            <Shortcut keys="Ctrl+B" label={t('header.mcpMonitor')} />
            <Shortcut keys="Esc" label={t('header.closePanels')} />
          </div>
        )}
      </div>

      <div
        title={t('language.toggleTitle')}
        style={{
          display: 'flex',
          border: '1px solid var(--border)',
          borderRadius: 4,
          overflow: 'hidden',
        }}
      >
        {(['en', 'ko'] as const).map((lang) => (
          <button
            key={lang}
            onClick={() => setLanguage(lang)}
            style={{
              border: 0,
              padding: '4px 7px',
              fontSize: 10,
              fontFamily: 'var(--mono)',
              cursor: 'pointer',
              background: language === lang ? 'var(--surface-2)' : 'transparent',
              color: language === lang ? 'var(--text)' : 'var(--text-muted)',
            }}
          >
            {lang.toUpperCase()}
          </button>
        ))}
      </div>

      <button className="btn btn-sm" onClick={toggleTheme} title={t('header.toggleTheme')}>
        {theme === 'dark' ? t('header.light') : t('header.dark')}
      </button>
      <button className={`btn btn-sm ${copilotOpen ? 'btn-primary' : ''}`} onClick={toggleCopilot} title={t('header.toggleMcpMonitor')}>
        {t('header.mcpMonitor')}
      </button>
    </header>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', gap: 5, alignItems: 'center', minWidth: 0 }}>
      <span style={{ fontSize: 10, color: 'var(--text-subtle)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {label}
      </span>
      <span style={{
        fontFamily: 'var(--mono)',
        fontSize: 11,
        color: 'var(--text-muted)',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        maxWidth: 180,
      }}>
        {value}
      </span>
    </div>
  );
}

function Shortcut({ keys, label }: { keys: string; label: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 18, color: 'var(--text-muted)', marginTop: 4 }}>
      <kbd style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text)' }}>{keys}</kbd>
      <span>{label}</span>
    </div>
  );
}
