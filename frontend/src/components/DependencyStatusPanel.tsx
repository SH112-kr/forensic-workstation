import { useEffect, useState } from 'react';
import { get } from '../hooks/useApi';
import { useI18n } from '../i18n/useI18n';

interface DependencyItem {
  key: string;
  display_name: string;
  kind: string;
  available: boolean;
  required: boolean;
  affects_overall_status: boolean;
  severity: 'ok' | 'blocked' | 'degraded' | 'optional';
  required_for: string;
  blocked_capabilities: string[];
  install_hint: string;
  missing_imports?: string[];
  missing_binaries?: string[];
}

interface DependencyReport {
  overall_status: 'ready' | 'degraded' | 'blocked';
  python_executable: string;
  dependencies: DependencyItem[];
  summary: {
    total: number;
    available: number;
    missing_required: number;
    missing_optional: number;
    missing_affecting_overall: number;
  };
}

interface Props {
  compact?: boolean;
}

export default function DependencyStatusPanel({ compact = false }: Props) {
  const { t } = useI18n();
  const [report, setReport] = useState<DependencyReport | null>(null);
  const [expanded, setExpanded] = useState(!compact);

  useEffect(() => {
    get<DependencyReport>('/api/health/dependencies')
      .then(setReport)
      .catch(() => setReport(null));
  }, []);

  if (!report) return null;

  const missing = report.dependencies.filter((d) => !d.available);
  const blocked = missing.filter((d) => d.required);
  const degraded = missing.filter((d) => !d.required && d.affects_overall_status !== false);
  const tone = report.overall_status === 'blocked' || blocked.length > 0
    ? { bg: 'var(--critical-bg)', border: 'var(--critical-border)', color: 'var(--critical)', label: t('common.blocked') }
    : report.overall_status === 'degraded' || degraded.length > 0
      ? { bg: 'var(--high-bg)', border: 'var(--high)', color: 'var(--high)', label: t('common.degraded') }
      : { bg: 'var(--low-bg)', border: 'var(--low)', color: 'var(--low)', label: t('common.ready') };

  return (
    <div style={{
      background: tone.bg,
      border: `1px solid ${tone.border}`,
      borderRadius: 8,
      padding: compact ? '12px 14px' : 20,
      marginBottom: 16,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ fontWeight: 700, fontSize: compact ? 13 : 15, color: tone.color }}>
          {t('dependency.title', { status: tone.label })}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
          {report.summary.available}/{report.summary.total} {t('common.available')}
        </div>
        <div style={{ flex: 1 }} />
        {compact && missing.length > 0 && (
          <button
            className="btn btn-sm"
            onClick={() => setExpanded(!expanded)}
            style={{ fontSize: 10, padding: '3px 8px' }}
          >
            {expanded ? t('common.hide') : t('common.details')}
          </button>
        )}
      </div>

      {missing.length === 0 && !compact && (
        <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-dim)' }}>
          {t('dependency.allAvailable')}
        </div>
      )}

      {missing.length > 0 && (
        <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
          {t('dependency.missingHint')}
        </div>
      )}

      {expanded && missing.length > 0 && (
        <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
          {missing.map((dep) => (
            <div key={dep.key} style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: '10px 12px',
            }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: dep.required
                    ? 'var(--critical)'
                    : dep.affects_overall_status === false ? 'var(--text-dim)' : 'var(--high)',
                  border: `1px solid ${dep.required
                    ? 'var(--critical-border)'
                    : dep.affects_overall_status === false ? 'var(--border)' : 'var(--high)'}`,
                  borderRadius: 3,
                  padding: '1px 5px',
                }}>
                  {dep.required ? t('common.required') : t('common.optional')}
                </span>
                <span style={{ fontWeight: 700, fontSize: 13 }}>{dep.display_name}</span>
                <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{dep.required_for}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 6 }}>
                {t('dependency.blocks')} {dep.blocked_capabilities.join(', ')}
              </div>
              <code style={{
                display: 'block',
                padding: '6px 8px',
                borderRadius: 4,
                background: 'var(--bg)',
                border: '1px solid var(--border-light)',
                fontSize: 11,
                color: 'var(--text)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}>
                {dep.install_hint}
              </code>
            </div>
          ))}
        </div>
      )}

      {!compact && (
        <div style={{ marginTop: 12, fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>
          {t('dependency.python')} {report.python_executable}
        </div>
      )}
    </div>
  );
}
