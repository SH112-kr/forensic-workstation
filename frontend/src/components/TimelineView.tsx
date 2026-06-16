import { useEffect, useRef, useState } from 'react';
import { get, post } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';
import ZeroResultsHint from './ZeroResultsHint';
import { useI18n } from '../i18n/useI18n';

export default function TimelineView() {
  const { caseInfo } = useStore();
  const { t } = useI18n();
  const [entries, setEntries] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [filter, setFilter] = useState('');
  const [limit] = useState(500);
  const [allCases, setAllCases] = useState(false);
  const [caseCount, setCaseCount] = useState(1);
  // Slice filters (user/process/host/path) — post-filter substrings matched
  // case-insensitively against description + artifact_type + fields.
  const [sliceUser, setSliceUser] = useState('');
  const [sliceProcess, setSliceProcess] = useState('');
  const [sliceHost, setSliceHost] = useState('');
  const [slicePath, setSlicePath] = useState('');
  const [showSlice, setShowSlice] = useState(false);
  const didAutoLoad = useRef(false);

  useEffect(() => {
    get('/api/cases/list').then((d) => setCaseCount((d.cases || []).length)).catch(() => {});
  }, []);

  const load = async (start?: string, end?: string) => {
    setLoading(true);
    try {
      const data = await post('/api/timeline', {
        start_date: start ?? startDate, end_date: end ?? endDate, limit, all_cases: allCases,
      });
      setEntries(data.entries || []);
      setTotal(data.total_events || 0);
    } catch {} finally { setLoading(false); }
  };

  // Auto-load timeline using case date range on first mount
  useEffect(() => {
    if (didAutoLoad.current) return;
    didAutoLoad.current = true;
    const start = caseInfo?.date_range_start ? caseInfo.date_range_start.slice(0, 10) : '';
    const end = caseInfo?.date_range_end ? caseInfo.date_range_end.slice(0, 10) : '';
    if (start) setStartDate(start);
    if (end) setEndDate(end);
    load(start, end);
  }, []);

  const sliceMatch = (e: any, sub: string) => {
    if (!sub) return true;
    const hay = `${e.description || ''} ${e.artifact_type || ''} ${Object.values(e.fields || {}).join(' ')}`.toLowerCase();
    return hay.includes(sub.toLowerCase());
  };
  const filtered = entries.filter(e => {
    if (filter && !((e.description || '').toLowerCase().includes(filter.toLowerCase()) ||
                    (e.artifact_type || '').toLowerCase().includes(filter.toLowerCase()))) return false;
    if (!sliceMatch(e, sliceUser)) return false;
    if (!sliceMatch(e, sliceProcess)) return false;
    if (!sliceMatch(e, sliceHost)) return false;
    if (!sliceMatch(e, slicePath)) return false;
    return true;
  });
  const sliceActive = sliceUser || sliceProcess || sliceHost || slicePath;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Controls */}
      <div style={{
        padding: '10px 16px', display: 'flex', gap: 8, borderBottom: '1px solid var(--border)',
        background: 'var(--surface)', alignItems: 'center', flexWrap: 'wrap',
      }}>
        <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>{t('timeline.from')}</label>
        <input type="date" value={startDate} onChange={e => setStartDate(e.target.value)}
          style={{ padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12 }} />
        <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>{t('timeline.to')}</label>
        <input type="date" value={endDate} onChange={e => setEndDate(e.target.value)}
          style={{ padding: '5px 8px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12 }} />
        <button className="btn btn-primary btn-sm" onClick={() => load()} disabled={loading}>
          {loading ? t('timeline.loadingTimeline') : t('timeline.loadTimeline')}
        </button>
        {caseCount >= 2 && (
          <label
            style={{
              display: 'flex', alignItems: 'center', gap: 6, fontSize: 11,
              color: allCases ? 'var(--accent)' : 'var(--text-dim)', cursor: 'pointer',
              padding: '4px 10px', borderRadius: 6,
              border: '1px solid var(--border)',
              background: allCases ? 'var(--accent-light)' : 'transparent',
            }}
            title={t('timeline.mergeAllCases')}
          >
            <input type="checkbox" checked={allCases} onChange={(e) => setAllCases(e.target.checked)} style={{ margin: 0 }} />
            {t('common.allCases')}
          </label>
        )}
        <div style={{ flex: 1 }} />
        <input type="text" placeholder={t('timeline.filterPlaceholder')} value={filter} onChange={e => setFilter(e.target.value)}
          style={{ padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: 12, width: 200 }} />
        <button
          onClick={() => setShowSlice(!showSlice)}
          className="btn btn-sm"
          title={t('timeline.sliceTitle')}
          style={{ borderColor: sliceActive ? 'var(--accent)' : undefined, color: sliceActive ? 'var(--accent)' : undefined }}>
          {showSlice ? '▾' : '▸'} {t('timeline.slice')}{sliceActive ? ' ●' : ''}
        </button>
        <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
          {t('timeline.eventsCount', { shown: filtered.length, total })}
        </span>
      </div>

      {/* Slice filters */}
      {showSlice && (
        <div style={{
          padding: '10px 16px', display: 'flex', gap: 8, flexWrap: 'wrap',
          borderBottom: '1px solid var(--border)', background: 'var(--surface)',
          alignItems: 'center',
        }}>
          <span className="help-text">{t('timeline.sliceHelp')}</span>
          <input placeholder={t('timeline.user')} value={sliceUser} onChange={e => setSliceUser(e.target.value)}
            className="input input-sm" style={{ width: 120 }} />
          <input placeholder={t('timeline.process')} value={sliceProcess} onChange={e => setSliceProcess(e.target.value)}
            className="input input-sm" style={{ width: 140 }} />
          <input placeholder={t('timeline.host')} value={sliceHost} onChange={e => setSliceHost(e.target.value)}
            className="input input-sm" style={{ width: 120 }} />
          <input placeholder={t('timeline.path')} value={slicePath} onChange={e => setSlicePath(e.target.value)}
            className="input input-sm" style={{ width: 160 }} />
          {sliceActive && (
            <button className="btn btn-sm"
              onClick={() => { setSliceUser(''); setSliceProcess(''); setSliceHost(''); setSlicePath(''); }}>
              {t('common.clear')}
            </button>
          )}
        </div>
      )}

      {/* Timeline list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 && !loading && (
          <>
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
              {entries.length === 0 ? t('timeline.noEvents') : t('timeline.noFilterMatches')}
            </div>
            {entries.length === 0 && (
              <ZeroResultsHint
                toolName="build_timeline"
                params={{ start_date: startDate, end_date: endDate, all_cases: allCases }}
                message={t('timeline.zeroDiagnostic')}
                onRetryFullRange={() => {
                  setStartDate("");
                  setEndDate("");
                  setTimeout(() => load("", ""), 0);
                }}
              />
            )}
          </>
        )}
        {loading && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
            <div style={{ width: 20, height: 20, border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 12px' }} />
            {t('timeline.building')}
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}
        {filtered.map((e, i) => (
          <div key={i} style={{
            display: 'grid',
            gridTemplateColumns: allCases ? '150px 110px 180px 1fr' : '150px 180px 1fr',
            gap: 8,
            padding: '6px 16px', borderBottom: '1px solid var(--border-light)',
            fontSize: 12, alignItems: 'start',
          }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-dim)' }}>
              {(e.timestamp || '').substring(0, 23)}
            </span>
            {allCases && (
              <span style={{ fontSize: 11, fontWeight: 600, color: '#60a5fa' }} title={e.source_path}>
                {e.case_id || '—'}
              </span>
            )}
            <span style={{ fontWeight: 600, color: 'var(--accent)', fontSize: 11 }}>
              {e.artifact_type}
            </span>
            <span style={{ color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              title={e.description}>
              {e.description}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
