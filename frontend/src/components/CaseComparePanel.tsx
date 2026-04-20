import { useEffect, useState } from 'react';
import { get } from '../hooks/useApi';
import { useStore } from '../hooks/useStore';

interface CaseMetaEnvelope {
  case_id: string;
  source_type: string;
  source_path: string;
  ok: boolean;
  error?: string;
  data?: {
    case_name?: string;
    total_hits?: number;
    date_range_start?: string;
    date_range_end?: string;
    source_type?: string;
  };
}

interface CompareResponse {
  ok: boolean;
  case_count: number;
  metadata: CaseMetaEnvelope[];
  artifact_counts: {
    matrix: Record<string, Record<string, number>>;
    families: string[];
    totals: Record<string, number>;
  };
  warnings: string[];
}

const sourceBadge = (t: string) => {
  if (t === 'kape') return { label: 'KAPE', color: '#60a5fa', bg: 'rgba(96,165,250,0.15)' };
  if (t === 'mfdb' || t === 'axiom') return { label: 'MFDB', color: '#4ade80', bg: 'rgba(74,222,128,0.15)' };
  return { label: (t || '?').toUpperCase(), color: '#9ca3af', bg: 'rgba(156,163,175,0.15)' };
};

export default function CaseComparePanel() {
  const { caseInfo } = useStore();
  const [data, setData] = useState<CompareResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [topN, setTopN] = useState(30);

  useEffect(() => {
    if (!caseInfo) return;
    setLoading(true);
    setError('');
    get('/api/cases/compare')
      .then((d) => setData(d))
      .catch((e) => setError(e.message || 'Failed to load comparison'))
      .finally(() => setLoading(false));
  }, [caseInfo]);

  if (!caseInfo) return null;

  const caseIds = (data?.metadata || []).map((m) => m.case_id);
  const families = data ? data.artifact_counts.families.slice(0, topN) : [];
  const hasOnlyOneCase = data && data.case_count <= 1;

  const switchTo = async (caseId: string) => {
    try {
      await fetch(`/api/cases/switch?case_id=${encodeURIComponent(caseId)}`, { method: 'POST' });
      location.reload();
    } catch {}
  };

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      <div style={{ marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, margin: '0 0 4px' }}>Compare Cases</h2>
        <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          Per-case artifact-count matrix and metadata for every loaded case. Click a cell to
          switch the active case; disconnected cases remain in the table with an explicit error.
        </div>
      </div>

      {loading && <div style={{ padding: 16, fontSize: 12, color: 'var(--text-dim)' }}>Loading comparison…</div>}

      {error && (
        <div style={{
          padding: '12px 16px', borderRadius: 8, marginBottom: 12,
          background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
          color: '#ef4444', fontSize: 12,
        }}>{error}</div>
      )}

      {hasOnlyOneCase && (
        <div style={{
          padding: '12px 16px', borderRadius: 8, marginBottom: 12,
          background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.2)',
          color: 'var(--text-dim)', fontSize: 12,
        }}>
          Only one case is loaded. Open another case from the header to compare them side by side.
        </div>
      )}

      {data && (
        <>
          {data.warnings.length > 0 && (
            <div style={{
              padding: '10px 14px', borderRadius: 8, marginBottom: 12,
              background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
              color: '#f59e0b', fontSize: 12,
            }}>
              <div style={{ fontWeight: 700, marginBottom: 4 }}>Partial results</div>
              {data.warnings.map((w, i) => <div key={i}>• {w}</div>)}
            </div>
          )}

          {/* Metadata row */}
          <div style={{ overflowX: 'auto', marginBottom: 16 }}>
            <table style={{ borderCollapse: 'collapse', fontSize: 12, minWidth: '100%' }}>
              <thead>
                <tr style={{ background: 'var(--surface)' }}>
                  <th style={{ padding: '8px 10px', textAlign: 'left', borderBottom: '1px solid var(--border)', fontWeight: 700 }}>Case</th>
                  <th style={{ padding: '8px 10px', textAlign: 'left', borderBottom: '1px solid var(--border)' }}>Source</th>
                  <th style={{ padding: '8px 10px', textAlign: 'right', borderBottom: '1px solid var(--border)' }}>Total hits</th>
                  <th style={{ padding: '8px 10px', textAlign: 'left', borderBottom: '1px solid var(--border)' }}>Date range</th>
                  <th style={{ padding: '8px 10px', textAlign: 'left', borderBottom: '1px solid var(--border)' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {data.metadata.map((m) => {
                  const b = sourceBadge(m.source_type);
                  return (
                    <tr key={m.case_id} style={{ borderBottom: '1px solid var(--border-light)' }}>
                      <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                        <span style={{
                          fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                          marginRight: 6, background: b.bg, color: b.color,
                        }}>{b.label}</span>
                        {m.data?.case_name || m.case_id}
                      </td>
                      <td style={{ padding: '8px 10px', color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={m.source_path}>
                        {m.source_path}
                      </td>
                      <td style={{ padding: '8px 10px', textAlign: 'right', fontFamily: 'var(--mono)' }}>
                        {m.data?.total_hits?.toLocaleString() ?? '—'}
                      </td>
                      <td style={{ padding: '8px 10px', color: 'var(--text-dim)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                        {(m.data?.date_range_start || '').slice(0, 10)} → {(m.data?.date_range_end || '').slice(0, 10)}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        {m.ok ? (
                          <span style={{ color: '#4ade80' }}>OK</span>
                        ) : (
                          <span style={{ color: '#ef4444' }} title={m.error}>ERR: {(m.error || '').slice(0, 40)}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Artifact matrix */}
          {families.length > 0 && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Artifact counts by family</h3>
                <div style={{ flex: 1 }} />
                <label style={{ fontSize: 11, color: 'var(--text-dim)' }}>Top</label>
                <select value={topN} onChange={(e) => setTopN(Number(e.target.value))}
                  style={{ padding: '3px 8px', fontSize: 11, borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)' }}>
                  <option value={15}>15</option>
                  <option value={30}>30</option>
                  <option value={60}>60</option>
                  <option value={9999}>All</option>
                </select>
              </div>
              <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 8 }}>
                <table style={{ borderCollapse: 'collapse', fontSize: 12, minWidth: '100%' }}>
                  <thead>
                    <tr style={{ background: 'var(--surface)' }}>
                      <th style={{ padding: '8px 10px', textAlign: 'left', borderBottom: '1px solid var(--border)', position: 'sticky', left: 0, background: 'var(--surface)' }}>Family</th>
                      {caseIds.map((cid) => (
                        <th key={cid} style={{ padding: '8px 10px', textAlign: 'right', borderBottom: '1px solid var(--border)' }}>{cid}</th>
                      ))}
                      <th style={{ padding: '8px 10px', textAlign: 'right', borderBottom: '1px solid var(--border)', color: 'var(--text-dim)' }}>Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {families.map((fam) => {
                      const row = data.artifact_counts.matrix[fam] || {};
                      const total = data.artifact_counts.totals[fam] || 0;
                      return (
                        <tr key={fam} style={{ borderBottom: '1px solid var(--border-light)' }}>
                          <td style={{ padding: '6px 10px', fontWeight: 500, position: 'sticky', left: 0, background: 'var(--bg)' }}>{fam}</td>
                          {caseIds.map((cid) => {
                            const n = row[cid] || 0;
                            return (
                              <td key={cid}
                                  onClick={() => n > 0 && switchTo(cid)}
                                  style={{
                                    padding: '6px 10px', textAlign: 'right', fontFamily: 'var(--mono)',
                                    color: n === 0 ? 'var(--text-dim)' : 'var(--text)',
                                    background: n === 0 ? 'transparent' : 'rgba(74,222,128,0.04)',
                                    cursor: n > 0 ? 'pointer' : 'default',
                                  }}
                                  title={n > 0 ? `Switch active case to ${cid}` : ''}>
                                {n > 0 ? n.toLocaleString() : '—'}
                              </td>
                            );
                          })}
                          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: 'var(--mono)', color: 'var(--text-dim)' }}>
                            {total.toLocaleString()}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
