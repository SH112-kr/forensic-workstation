import { useCallback, useEffect, useRef, useState } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { AllCommunityModule, ModuleRegistry, type ColDef } from 'ag-grid-community';
import { post, get } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';
import ZeroResultsHint from './ZeroResultsHint';
import { useI18n } from '../i18n/useI18n';

ModuleRegistry.registerModules([AllCommunityModule]);

const PAGE_SIZE = 100;

export default function ArtifactBrowser() {
  const { caseInfo } = useStore();
  const { t } = useI18n();
  const gridRef = useRef<AgGridReact>(null);
  const [detail, setDetail] = useState<any>(null);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [artifactType, setArtifactType] = useState('');
  const [types, setTypes] = useState<string[]>([]);
  const [rows, setRows] = useState<any[]>([]);
  const [totalRows, setTotalRows] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [allCases, setAllCases] = useState(false);
  const [caseCount, setCaseCount] = useState(1);

  useEffect(() => {
    get('/api/cases/list').then((d) => setCaseCount((d.cases || []).length)).catch(() => {});
  }, []);

  const fetchRows = useCallback(async (
    newOffset: number,
    keyword?: string,
    type?: string,
    startOverride?: string,
    endOverride?: string,
  ) => {
    // Codex Round-12b fix: preset and retry paths pass explicit date
    // overrides so a stale closure from setState + setTimeout cannot
    // re-run the same bounded query after the user cleared the range.
    setLoading(true);
    try {
      const result = await post('/api/artifacts/search', {
        keyword: keyword ?? searchKeyword,
        artifact_type: type ?? artifactType,
        start_date: startOverride !== undefined ? startOverride : startDate,
        end_date: endOverride !== undefined ? endOverride : endDate,
        offset: newOffset,
        limit: PAGE_SIZE,
        all_cases: allCases,
      });
      setRows(result.hits || result.rows || result.rowData || []);
      setTotalRows(result.total_estimated ?? result.total ?? result.rowCount ?? 0);
      setOffset(newOffset);
    } catch {
      setRows([]);
      setTotalRows(0);
    } finally {
      setLoading(false);
    }
  }, [searchKeyword, artifactType, startDate, endDate, allCases]);

  // Load artifact types and initial rows on mount
  useEffect(() => {
    (async () => {
      try {
        const data = await get<any>('/api/cases/types');
        setTypes((data.artifact_types || []).map((t: any) => t.artifact_type));
      } catch {}
    })();
    fetchRows(0);
  }, []);

  const search = useCallback(() => {
    fetchRows(0, searchKeyword, artifactType);
  }, [searchKeyword, artifactType, fetchRows]);

  const columnDefs: ColDef[] = [
    { field: 'hit_id', headerName: t('common.id'), width: 90, sortable: true },
    ...(allCases ? [{
      field: 'case_id',
      headerName: t('common.case'),
      width: 140,
      sortable: true,
      cellStyle: { fontWeight: 600, color: '#60a5fa' },
    } as ColDef] : []),
    { field: 'artifact_type', headerName: t('common.type'), width: 200, sortable: true },
    {
      field: 'fields',
      headerName: t('common.summary'),
      flex: 1,
      valueFormatter: (p) => {
        if (!p.value) return '';
        const fields = p.value as Record<string, any>;
        return Object.entries(fields).slice(0, 3).map(([k, v]) => `${k}: ${String(v).slice(0, 60)}`).join(' | ');
      },
    },
    {
      field: 'timestamps',
      headerName: t('common.timestamp'),
      width: 180,
      valueFormatter: (p) => {
        if (!p.value) return '';
        const ts = p.value as Record<string, string>;
        const first = Object.values(ts)[0];
        return first || '';
      },
    },
  ];

  const onRowClicked = async (event: any) => {
    const hitId = event.data?.hit_id;
    if (!hitId) return;
    try {
      const data = await get(`/api/artifacts/detail/${hitId}`);
      setDetail(data);
    } catch {}
  };

  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;
  const totalPages = Math.max(1, Math.ceil(totalRows / PAGE_SIZE));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Filter bar */}
      <div style={{
        padding: '10px 16px', display: 'flex', gap: 8, borderBottom: '1px solid var(--border)',
        background: 'var(--surface)',
      }}>
        <input
          type="text"
          placeholder={t('artifacts.searchPlaceholder')}
          value={searchKeyword}
          onChange={(e) => setSearchKeyword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && search()}
          style={{
            flex: 1, padding: '6px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text)', fontSize: 12,
          }}
        />
        <select
          value={artifactType}
          onChange={(e) => { setArtifactType(e.target.value); setTimeout(() => fetchRows(0, searchKeyword, e.target.value), 0); }}
          style={{
            padding: '6px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text)', fontSize: 12, maxWidth: 250,
          }}
        >
          <option value="">{t('common.allTypes')}</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          type="date"
          value={startDate}
          onChange={(e) => setStartDate(e.target.value)}
          placeholder={t('artifacts.startDate')}
          title={t('artifacts.startDate')}
          style={{
            padding: '6px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text)', fontSize: 12,
          }}
        />
        <input
          type="date"
          value={endDate}
          onChange={(e) => setEndDate(e.target.value)}
          placeholder={t('artifacts.endDate')}
          title={t('artifacts.endDate')}
          style={{
            padding: '6px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text)', fontSize: 12,
          }}
        />
        <button className="btn btn-sm" onClick={search}>{t('common.search')}</button>

        {/* Date range presets — smart defaults so analysts don't guess
            numbers. Case-window button only renders when caseInfo exposes
            both bounds (Codex Round-12 guard). */}
        {(() => {
          const applyRange = (s: string, e: string) => {
            setStartDate(s);
            setEndDate(e);
            // Pass explicit overrides so the in-flight fetch uses the new
            // values directly rather than the stale closure captured when
            // this callback was created.
            fetchRows(0, undefined, undefined, s, e);
          };
          const today = new Date().toISOString().slice(0, 10);
          const weekAgo = new Date(Date.now() - 7 * 86400 * 1000).toISOString().slice(0, 10);
          const caseStart = (caseInfo?.date_range_start || "").slice(0, 10);
          const caseEnd = (caseInfo?.date_range_end || "").slice(0, 10);
          return (
            <span style={{ display: 'flex', gap: 4, alignItems: 'center', marginLeft: 6 }}>
              <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>{t('artifacts.preset')}</span>
              <button className="btn btn-sm" onClick={() => applyRange(weekAgo, today)}
                style={{ fontSize: 10, padding: '3px 8px' }}>{t('artifacts.lastSevenDays')}</button>
              {caseStart && caseEnd && (
                <button className="btn btn-sm" onClick={() => applyRange(caseStart, caseEnd)}
                  style={{ fontSize: 10, padding: '3px 8px' }} title={`${caseStart} ~ ${caseEnd}`}>
                  {t('artifacts.caseRange')}
                </button>
              )}
              <button className="btn btn-sm" onClick={() => applyRange("", "")}
                style={{ fontSize: 10, padding: '3px 8px' }}>{t('artifacts.allRange')}</button>
            </span>
          );
        })()}
        {caseCount >= 2 && (
          <label
            style={{
              display: 'flex', alignItems: 'center', gap: 6, fontSize: 11,
              color: allCases ? 'var(--accent)' : 'var(--text-dim)', cursor: 'pointer',
              padding: '6px 10px', borderRadius: 6,
              border: '1px solid var(--border)',
              background: allCases ? 'var(--accent-light)' : 'transparent',
            }}
            title={t('artifacts.allCasesTitle')}
          >
            <input
              type="checkbox"
              checked={allCases}
              onChange={(e) => setAllCases(e.target.checked)}
              style={{ margin: 0 }}
            />
            {t('common.allCases')}
          </label>
        )}
      </div>

      {/* Grid + Detail split */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* AG Grid */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {loading && (
            <div style={{
              padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 8,
              background: 'var(--surface)', borderBottom: '1px solid var(--border-light)',
              fontSize: 12, color: 'var(--accent)',
            }}>
              <div style={{
                width: 14, height: 14, border: '2px solid var(--border)',
                borderTopColor: 'var(--accent)', borderRadius: '50%',
                animation: 'spin 0.8s linear infinite',
              }} />
              {t('artifacts.loading')}
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
          )}
          {rows.length === 0 && !loading && (
            <>
              <div
                style={{
                  padding: '14px 16px', background: 'var(--surface)',
                  borderBottom: '1px solid var(--border-light)',
                  fontSize: 12, color: 'var(--text-dim)',
                }}
              >
                {t('artifacts.noMatches')}
              </div>
              <ZeroResultsHint
                toolName="search_artifacts"
                params={{
                  keyword: searchKeyword, artifact_type: artifactType,
                  start_date: startDate, end_date: endDate,
                  all_cases: allCases,
                }}
                message={t('artifacts.zeroDiagnostic')}
                onRetryFullRange={() => {
                  setStartDate("");
                  setEndDate("");
                  fetchRows(0, undefined, undefined, "", "");
                }}
              />
            </>
          )}
          <div style={{ flex: 1 }}>
            <AgGridReact
              ref={gridRef}
              columnDefs={columnDefs}
              rowData={rows}
              onRowClicked={onRowClicked}
              rowSelection="single"
            />
          </div>

          {/* Pagination controls */}
          <div style={{
            padding: '8px 16px', display: 'flex', alignItems: 'center', gap: 12,
            borderTop: '1px solid var(--border)', background: 'var(--surface)',
            fontSize: 12, color: 'var(--text-dim)',
          }}>
            <button
              className="btn btn-sm"
              disabled={offset === 0 || loading}
              onClick={() => fetchRows(Math.max(0, offset - PAGE_SIZE))}
            >
              {t('common.previous')}
            </button>
            <span>{t('common.pageOf', { page: currentPage, total: totalPages })}</span>
            <button
              className="btn btn-sm"
              disabled={offset + PAGE_SIZE >= totalRows || loading}
              onClick={() => fetchRows(offset + PAGE_SIZE)}
            >
              {t('common.next')}
            </button>
            <div style={{ flex: 1 }} />
            <span>{totalRows.toLocaleString()} {t('common.totalArtifacts')}</span>
          </div>
        </div>

        {/* Detail Panel */}
        {detail && (
          <div style={{
            width: 380, borderLeft: '1px solid var(--border)', overflowY: 'auto',
            padding: 16, background: 'var(--surface)', fontSize: 12,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
              <strong>{t('artifacts.hit', { id: detail.hit_id })}</strong>
              <button className="btn btn-sm" onClick={() => setDetail(null)}>{t('common.close')}</button>
            </div>
            <div style={{ marginBottom: 8 }}>
              <span className="badge badge-info">{detail.artifact_type}</span>
            </div>

            {/* Fields */}
            <h4 style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 12, marginBottom: 6, textTransform: 'uppercase' }}>{t('common.fields')}</h4>
            {Object.entries(detail.fields || {}).map(([k, v]) => (
              <div key={k} style={{ padding: '3px 0', borderBottom: '1px solid var(--border-light)' }}>
                <span style={{ color: 'var(--text-dim)' }}>{k}:</span>{' '}
                <span style={{ wordBreak: 'break-all' }}>{String(v).slice(0, 300)}</span>
              </div>
            ))}

            {/* Timestamps */}
            <h4 style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 12, marginBottom: 6, textTransform: 'uppercase' }}>{t('common.timestamps')}</h4>
            {Object.entries(detail.timestamps || {}).map(([k, v]) => (
              <div key={k} style={{ padding: '3px 0', fontFamily: 'var(--mono)', fontSize: 11 }}>
                <span style={{ color: 'var(--text-dim)' }}>{k}:</span> {String(v)}
              </div>
            ))}

            {detail.hash && (
              <>
                <h4 style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 12, marginBottom: 6, textTransform: 'uppercase' }}>{t('common.hash')}</h4>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, wordBreak: 'break-all' }}>{detail.hash}</div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
