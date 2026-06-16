import { useEffect, useState } from 'react';
import { post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';
import { useI18n } from '../i18n/useI18n';

interface Cause {
  cause: string;
  confidence: string;
  detail: string;
  reason?: string;
}

interface Suggestion {
  tool_name: string;
  params: Record<string, any>;
  why: string;
}

interface ZeroResultsHintProps {
  /** Tool name that returned 0 rows (e.g. "search_artifacts"). */
  toolName: string;
  /** The params that produced the empty response. */
  params: Record<string, any>;
  /** Emoji / icon override. */
  icon?: string;
  /** Extra note shown above the causes list. */
  message?: string;
  /** Optional one-click retry that the caller controls. When provided and
   *  the diagnosis includes a date-range cause, a "Retry with full range"
   *  button fires this callback with the same params minus start_date/end_date. */
  onRetryFullRange?: (paramsSansDates: Record<string, any>) => void;
}

const CONFIDENCE_COLOR: Record<string, string> = {
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#94a3b8',
};

export default function ZeroResultsHint({
  toolName,
  params,
  icon = '💡',
  message,
  onRetryFullRange,
}: ZeroResultsHintProps) {
  const { setActiveView } = useStore();
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [causes, setCauses] = useState<Cause[]>([]);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    post('/api/cases/explain-zero', { tool_name: toolName, params })
      .then((r) => {
        if (cancelled) return;
        setCauses(r.likely_causes || []);
        setSuggestions(r.suggested_queries || []);
      })
      .catch((e) => !cancelled && setError(e?.message || t('zero.failed')))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
  // Re-run when the query signature changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toolName, JSON.stringify(params)]);

  return (
    <div style={{
      padding: '16px 20px', borderRadius: 10, marginTop: 16,
      background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.25)',
      maxWidth: 640, margin: '24px auto',
    }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', marginBottom: 10 }}>
        <span style={{ fontSize: 16 }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--text)' }}>
            {message || t('zero.why')}
          </div>
          <div className="help-text" style={{ marginTop: 2 }}>
            {t('zero.offlineDiagnosis')}
          </div>
        </div>
        <button className="btn btn-sm" onClick={() => setActiveView('coverage')}>
          {t('zero.openCoverage')}
        </button>
      </div>

      {loading && <div className="help-text">{t('zero.diagnosing')}</div>}
      {error && <div className="field-error">{error}</div>}

      {!loading && !error && causes.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="label" style={{ marginBottom: 6 }}>{t('zero.likelyCauses')}</div>
          {causes.map((c, i) => (
            <div key={i} style={{
              padding: '8px 10px', background: 'var(--bg)',
              border: '1px solid var(--border-light)', borderRadius: 6,
              marginBottom: 6, fontSize: 12,
            }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 3 }}>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
                  background: 'var(--surface2)',
                  color: CONFIDENCE_COLOR[c.confidence] || 'var(--text-dim)',
                  textTransform: 'uppercase',
                }}>{c.confidence}</span>
                <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-dim)', fontSize: 11 }}>
                  {c.cause}
                </span>
              </div>
              <div style={{ color: 'var(--text)' }}>{c.detail}</div>
              {c.reason && (
                <div className="help-text" style={{ marginTop: 4 }}>
                  {c.reason}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {!loading && !error && onRetryFullRange && causes.some(c =>
          c.cause === 'date_range_after_case' || c.cause === 'date_range_before_case') && (
        <div style={{ marginTop: 10 }}>
          <button
            className="btn btn-primary btn-sm"
            onClick={() => {
              const clean = { ...params };
              delete clean.start_date;
              delete clean.end_date;
              onRetryFullRange(clean);
            }}>
            {t('zero.retryFullRange')}
          </button>
          <span className="help-text" style={{ marginLeft: 8 }}>
            {t('zero.retryFullRangeHint')}
          </span>
        </div>
      )}

      {!loading && !error && suggestions.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div className="label" style={{ marginBottom: 6 }}>{t('zero.suggestedNextQueries')}</div>
          {suggestions.map((s, i) => (
            <div key={i} style={{
              padding: '8px 10px', background: 'var(--bg)',
              border: '1px solid var(--border-light)', borderRadius: 6,
              marginBottom: 6, fontSize: 12,
            }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)', marginBottom: 2 }}>
                {s.tool_name}({Object.entries(s.params).filter(([_, v]) => v).slice(0, 3).map(([k, v]) => `${k}="${v}"`).join(', ')})
              </div>
              <div className="help-text">{s.why}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
