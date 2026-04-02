import { useCallback, useEffect, useRef, useState } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { AllCommunityModule, ModuleRegistry, type ColDef } from 'ag-grid-community';
import { post, get } from '../hooks/useApi';

ModuleRegistry.registerModules([AllCommunityModule]);

const PAGE_SIZE = 100;

export default function ArtifactBrowser() {
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

  const fetchRows = useCallback(async (newOffset: number, keyword?: string, type?: string) => {
    setLoading(true);
    try {
      const result = await post('/api/artifacts/search', {
        keyword: keyword ?? searchKeyword,
        artifact_type: type ?? artifactType,
        start_date: startDate,
        end_date: endDate,
        offset: newOffset,
        limit: PAGE_SIZE,
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
  }, [searchKeyword, artifactType, startDate, endDate]);

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
    { field: 'hit_id', headerName: 'ID', width: 90, sortable: true },
    { field: 'artifact_type', headerName: 'Type', width: 200, sortable: true },
    {
      field: 'fields',
      headerName: 'Summary',
      flex: 1,
      valueFormatter: (p) => {
        if (!p.value) return '';
        const fields = p.value as Record<string, any>;
        return Object.entries(fields).slice(0, 3).map(([k, v]) => `${k}: ${String(v).slice(0, 60)}`).join(' | ');
      },
    },
    {
      field: 'timestamps',
      headerName: 'Timestamp',
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
          placeholder="Search artifacts..."
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
          <option value="">All Types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          type="date"
          value={startDate}
          onChange={(e) => setStartDate(e.target.value)}
          placeholder="Start date"
          title="Start date"
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
          placeholder="End date"
          title="End date"
          style={{
            padding: '6px 12px', borderRadius: 6,
            border: '1px solid var(--border)', background: 'var(--bg)',
            color: 'var(--text)', fontSize: 12,
          }}
        />
        <button className="btn btn-sm" onClick={search}>Search</button>
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
              Loading artifacts...
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
          )}
          <div style={{ flex: 1 }}>
            <AgGridReact
              ref={gridRef}
              columnDefs={columnDefs}
              rowData={rows}
              onRowClicked={onRowClicked}
              rowSelection="single"
              theme="legacy"
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
              Previous
            </button>
            <span>Page {currentPage} of {totalPages}</span>
            <button
              className="btn btn-sm"
              disabled={offset + PAGE_SIZE >= totalRows || loading}
              onClick={() => fetchRows(offset + PAGE_SIZE)}
            >
              Next
            </button>
            <div style={{ flex: 1 }} />
            <span>{totalRows.toLocaleString()} total artifacts</span>
          </div>
        </div>

        {/* Detail Panel */}
        {detail && (
          <div style={{
            width: 380, borderLeft: '1px solid var(--border)', overflowY: 'auto',
            padding: 16, background: 'var(--surface)', fontSize: 12,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
              <strong>Hit #{detail.hit_id}</strong>
              <button className="btn btn-sm" onClick={() => setDetail(null)}>Close</button>
            </div>
            <div style={{ marginBottom: 8 }}>
              <span className="badge badge-info">{detail.artifact_type}</span>
            </div>

            {/* Fields */}
            <h4 style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 12, marginBottom: 6, textTransform: 'uppercase' }}>Fields</h4>
            {Object.entries(detail.fields || {}).map(([k, v]) => (
              <div key={k} style={{ padding: '3px 0', borderBottom: '1px solid var(--border-light)' }}>
                <span style={{ color: 'var(--text-dim)' }}>{k}:</span>{' '}
                <span style={{ wordBreak: 'break-all' }}>{String(v).slice(0, 300)}</span>
              </div>
            ))}

            {/* Timestamps */}
            <h4 style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 12, marginBottom: 6, textTransform: 'uppercase' }}>Timestamps</h4>
            {Object.entries(detail.timestamps || {}).map(([k, v]) => (
              <div key={k} style={{ padding: '3px 0', fontFamily: 'var(--mono)', fontSize: 11 }}>
                <span style={{ color: 'var(--text-dim)' }}>{k}:</span> {String(v)}
              </div>
            ))}

            {detail.hash && (
              <>
                <h4 style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 12, marginBottom: 6, textTransform: 'uppercase' }}>Hash</h4>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, wordBreak: 'break-all' }}>{detail.hash}</div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
